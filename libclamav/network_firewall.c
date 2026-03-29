/*
 *  ClamAV Advanced Network Firewall & Threat Protection Module
 *
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "network_firewall.h"
#include "json_report.h"
#include "others.h"

/* -------------------------------------------------------------------------
 * Internal constants
 * ------------------------------------------------------------------------- */

/* SYN flood: alert if > this many SYNs per second */
#define NFW_SYN_FLOOD_THRESHOLD   1000
/* UDP flood: alert if > this many UDP packets per second */
#define NFW_UDP_FLOOD_THRESHOLD   5000
/* HTTP flood: alert if > this many requests per second */
#define NFW_HTTP_FLOOD_THRESHOLD  100

/* DNS tunneling: alert if query name exceeds this length */
#define NFW_DNS_QUERY_MAX_SAFE    64
/* DNS tunneling: alert if payload exceeds 512 bytes */
#define NFW_DNS_PAYLOAD_MAX_SAFE  512

/* Minimum label entropy (bits) to flag as likely base64/hex encoded tunnel */
#define NFW_DNS_ENTROPY_THRESHOLD 3.8

/* C2 beaconing: maximum jitter ratio still considered "regular" */
#define NFW_C2_JITTER_MAX         0.10

/* Number of connections to sample before deciding on beaconing */
#define NFW_C2_MIN_SAMPLES        5

/* Maximum C2 destination entries tracked per state */
#define NFW_MAX_C2_ENTRIES        1024

/* -------------------------------------------------------------------------
 * Internal types
 * ------------------------------------------------------------------------- */

/* Per-destination C2 beaconing tracker */
typedef struct {
    char     src_ip[NFW_MAX_IP_LEN];
    char     dst_ip[NFW_MAX_IP_LEN];
    uint16_t dst_port;
    time_t   last_seen[NFW_C2_MIN_SAMPLES + 2];
    size_t   payload_lens[NFW_C2_MIN_SAMPLES + 2];
    int      sample_count;
} nfw_c2_entry_t;

/* Known weak / deprecated TLS cipher suite prefixes */
static const char *nfw_weak_ciphers[] = {
    "RC4",
    "NULL",
    "EXPORT",
    "DES-",
    "3DES",
    "ADH-",
    "AECDH-",
    "MD5",
    NULL
};

/* Known bad TLS protocol versions */
static const char *nfw_bad_tls_versions[] = {
    "SSLv2",
    "SSLv3",
    "TLSv1.0",
    "TLSv1.1",
    NULL
};

/* -------------------------------------------------------------------------
 * Module state
 * ------------------------------------------------------------------------- */
struct nfw_state {
    nfw_config_t     cfg;
    nfw_ip_record_t  ip_table[NFW_MAX_TRACKED_IPS];
    uint32_t         ip_table_count;
    nfw_c2_entry_t   c2_table[NFW_MAX_C2_ENTRIES];
    uint32_t         c2_table_count;
};

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static nfw_ip_record_t *nfw_find_or_create_ip(nfw_state_t *state,
                                               const char *ip)
{
    uint32_t i;
    time_t now = time(NULL);

    /* Search for existing entry */
    for (i = 0; i < state->ip_table_count; i++) {
        if (strcmp(state->ip_table[i].ip, ip) == 0) {
            state->ip_table[i].last_seen = now;
            return &state->ip_table[i];
        }
    }

    /* Create new entry (evict oldest if full) */
    if (state->ip_table_count >= NFW_MAX_TRACKED_IPS) {
        /* Find oldest entry */
        uint32_t oldest_idx   = 0;
        time_t   oldest_time  = state->ip_table[0].last_seen;
        for (i = 1; i < NFW_MAX_TRACKED_IPS; i++) {
            if (state->ip_table[i].last_seen < oldest_time) {
                oldest_time = state->ip_table[i].last_seen;
                oldest_idx  = i;
            }
        }
        memset(&state->ip_table[oldest_idx], 0,
               sizeof(nfw_ip_record_t));
        strncpy(state->ip_table[oldest_idx].ip, ip,
                NFW_MAX_IP_LEN - 1);
        state->ip_table[oldest_idx].ip[NFW_MAX_IP_LEN - 1] = '\0';
        state->ip_table[oldest_idx].first_seen = now;
        state->ip_table[oldest_idx].last_seen  = now;
        return &state->ip_table[oldest_idx];
    }

    nfw_ip_record_t *rec = &state->ip_table[state->ip_table_count++];
    memset(rec, 0, sizeof(*rec));
    strncpy(rec->ip, ip, NFW_MAX_IP_LEN - 1);
    rec->ip[NFW_MAX_IP_LEN - 1] = '\0';
    rec->first_seen = now;
    rec->last_seen  = now;
    return rec;
}

/* Reset per-IP counters if the observation window has expired */
static void nfw_maybe_reset_counters(nfw_ip_record_t *rec,
                                     const nfw_config_t *cfg)
{
    time_t now = time(NULL);
    if ((now - rec->first_seen) >= (time_t)cfg->port_scan_timeout) {
        uint32_t prev_failed = rec->failed_login_count;
        char     ip_copy[NFW_MAX_IP_LEN];
        strncpy(ip_copy, rec->ip, NFW_MAX_IP_LEN - 1);
        ip_copy[NFW_MAX_IP_LEN - 1] = '\0';
        memset(rec, 0, sizeof(*rec));
        strncpy(rec->ip, ip_copy, NFW_MAX_IP_LEN - 1);
        rec->ip[NFW_MAX_IP_LEN - 1] = '\0';
        rec->first_seen         = now;
        rec->last_seen          = now;
        rec->failed_login_count = prev_failed; /* carry across windows */
    }
}

static void nfw_fill_log_defaults(nfw_threat_log_t *log,
                                   const char *src_ip)
{
    if (!log) return;
    memset(log, 0, sizeof(*log));
    /* ISO 8601 timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    if (tm_info) {
        strftime(log->timestamp, sizeof(log->timestamp),
                 "%Y-%m-%dT%H:%M:%SZ", tm_info);
    }
    if (src_ip)
        strncpy(log->source_ip, src_ip, NFW_MAX_IP_LEN - 1);
}

/* Shannon entropy of a string (used for DNS tunneling detection) */
static double nfw_string_entropy(const char *s, size_t len)
{
    if (!s || len == 0) return 0.0;
    int freq[256] = {0};
    size_t i;
    for (i = 0; i < len; i++) {
        freq[(unsigned char)s[i]]++;
    }
    double entropy = 0.0;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* -------------------------------------------------------------------------
 * Public API – lifecycle
 * ------------------------------------------------------------------------- */

void nfw_config_init_defaults(nfw_config_t *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));

    cfg->enabled                  = false;
    cfg->allow_port_scanning      = true;
    cfg->port_scan_threshold      = 10;
    cfg->port_scan_timeout        = 300;
    cfg->block_scanned_ports      = false;
    cfg->max_connections_per_ip   = 50;
    cfg->max_requests_per_second  = 100;
    cfg->max_failed_logins        = 5;
    cfg->lockout_duration         = 300;
    cfg->grace_period             = 10;
    cfg->enable_ip_reputation     = false;
    cfg->geo_blocking_enabled     = false;
    cfg->detect_impossible_travel = false;
    cfg->detect_unusual_location  = false;
    cfg->homograph_detection      = false;
    cfg->homograph_strict         = false;
    cfg->dnssec_enabled           = false;
    cfg->detect_dns_rebinding     = false;
    cfg->detect_dns_tunneling     = false;
    cfg->http_inspection          = false;
    cfg->validate_ssl_certificate = false;
    cfg->detect_tls_downgrade     = false;
    cfg->detect_c2_communication  = false;
    cfg->enable_ml_models         = false;
    cfg->ml_confidence_threshold  = 0.85;
}

nfw_state_t *nfw_init(const nfw_config_t *cfg)
{
    nfw_state_t *state = (nfw_state_t *)calloc(1, sizeof(nfw_state_t));
    if (!state) {
        cli_errmsg("nfw_init: failed to allocate firewall state structure\n");
        return NULL;
    }
    if (cfg)
        memcpy(&state->cfg, cfg, sizeof(nfw_config_t));
    else
        nfw_config_init_defaults(&state->cfg);

    return state;
}

void nfw_free(nfw_state_t *state)
{
    if (state)
        free(state);
}

/* -------------------------------------------------------------------------
 * Detection – port scanning
 * ------------------------------------------------------------------------- */

bool nfw_check_port_scan(nfw_state_t *state,
                          const char *src_ip,
                          uint16_t dst_port,
                          nfw_threat_log_t *log)
{
    if (!state || !state->cfg.enabled || !src_ip)
        return false;

    nfw_ip_record_t *rec = nfw_find_or_create_ip(state, src_ip);
    nfw_maybe_reset_counters(rec, &state->cfg);

    rec->connection_count++;

    /* Track distinct ports */
    bool port_known = false;
    uint32_t i;
    for (i = 0; i < rec->ports_seen_count; i++) {
        if (rec->ports_seen[i] == dst_port) {
            port_known = true;
            break;
        }
    }
    if (!port_known &&
        rec->ports_seen_count < NFW_MAX_PORTS_TRACKED) {
        rec->ports_seen[rec->ports_seen_count++] = dst_port;
        rec->port_count++;
    }

    /* Check if port-scan threshold is exceeded */
    if (!state->cfg.allow_port_scanning &&
        rec->port_count >= state->cfg.port_scan_threshold) {

        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_HIGH;
            log->threat_type = "Port Scanning";
            log->threat_name = NFW_ALERT_PORT_SCAN_DETECTED;
            log->port        = dst_port;
            log->protocol    = "TCP";
            log->action      = state->cfg.block_scanned_ports
                                   ? NFW_ACTION_BLOCK
                                   : NFW_ACTION_WARN;
            log->confidence  = 0.95;
        }

        if (state->cfg.block_scanned_ports)
            rec->blocked = true;

        return true;
    }

    /* Fast port sequence: many connections in a very short time */
    time_t now = time(NULL);
    double elapsed = difftime(now, rec->first_seen);
    if (elapsed > 0 &&
        ((double)rec->port_count / elapsed) > (double)state->cfg.port_scan_threshold) {

        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_MEDIUM;
            log->threat_type = "Port Scanning";
            log->threat_name = NFW_ALERT_FAST_PORT_SEQUENCE;
            log->port        = dst_port;
            log->protocol    = "TCP";
            log->action      = NFW_ACTION_WARN;
            log->confidence  = 0.80;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – DDoS / brute force
 * ------------------------------------------------------------------------- */

bool nfw_check_ddos(nfw_state_t *state,
                    const char *src_ip,
                    bool failed_login,
                    bool is_syn,
                    bool is_udp,
                    bool is_http,
                    nfw_threat_log_t *log)
{
    if (!state || !state->cfg.enabled || !src_ip)
        return false;

    nfw_ip_record_t *rec = nfw_find_or_create_ip(state, src_ip);
    nfw_maybe_reset_counters(rec, &state->cfg);

    if (is_syn)  rec->syn_count++;
    if (is_udp)  rec->udp_count++;
    if (is_http) rec->http_request_count++;
    if (failed_login) rec->failed_login_count++;
    rec->connection_count++;

    time_t now     = time(NULL);
    double elapsed = difftime(now, rec->first_seen);
    if (elapsed < 1.0) elapsed = 1.0;

    /* Check if IP is locked out */
    if (rec->blocked && now < rec->blocked_until)
        return false; /* already blocked, caller handles */

    /* SYN flood detection */
    if (is_syn &&
        ((double)rec->syn_count / elapsed) > NFW_SYN_FLOOD_THRESHOLD) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_CRITICAL;
            log->threat_type = "DDoS";
            log->threat_name = NFW_ALERT_SYN_FLOOD;
            log->protocol    = "TCP";
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = 0.92;
        }
        rec->blocked       = true;
        rec->blocked_until = now + (time_t)state->cfg.lockout_duration;
        return true;
    }

    /* UDP flood detection */
    if (is_udp &&
        ((double)rec->udp_count / elapsed) > NFW_UDP_FLOOD_THRESHOLD) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_CRITICAL;
            log->threat_type = "DDoS";
            log->threat_name = NFW_ALERT_UDP_FLOOD;
            log->protocol    = "UDP";
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = 0.90;
        }
        rec->blocked       = true;
        rec->blocked_until = now + (time_t)state->cfg.lockout_duration;
        return true;
    }

    /* HTTP flood detection */
    if (is_http &&
        ((double)rec->http_request_count / elapsed) >
            (double)state->cfg.max_requests_per_second) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_HIGH;
            log->threat_type = "DDoS";
            log->threat_name = NFW_ALERT_HTTP_FLOOD;
            log->protocol    = "HTTP";
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = 0.88;
        }
        rec->blocked       = true;
        rec->blocked_until = now + (time_t)state->cfg.lockout_duration;
        return true;
    }

    /* Brute force / credential stuffing */
    if (failed_login &&
        rec->failed_login_count >= state->cfg.max_failed_logins) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_HIGH;
            log->threat_type = "Brute Force";
            log->threat_name = NFW_ALERT_BRUTE_FORCE;
            log->protocol    = "TCP";
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = 0.85;
        }
        rec->blocked       = true;
        rec->blocked_until = now + (time_t)state->cfg.lockout_duration;
        return true;
    }

    /* Concurrent connection limit */
    if (rec->connection_count > state->cfg.max_connections_per_ip) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_MEDIUM;
            log->threat_type = "DDoS";
            log->threat_name = NFW_ALERT_POSSIBLE_DDOS;
            log->protocol    = "TCP";
            log->action      = NFW_ACTION_WARN;
            log->confidence  = 0.70;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – IP reputation
 *
 * This implementation provides the scoring framework.  In a production
 * deployment the score would be loaded from the ip_reputation_db file
 * or queried from threat-intelligence feeds (Spamhaus ZEN, AbuseIPDB,
 * etc.).  Here a simple internal lookup table of well-known malicious
 * ranges (RFC 5737 documentation ranges used as examples) is provided
 * for illustration.
 * ------------------------------------------------------------------------- */

/* Example: reserved / documentation prefixes that should never appear as
 * real source traffic.  Real deployments would have a much richer list. */
static const struct {
    const char *prefix;
    int         score;
    const char *label;
} nfw_known_bad_prefixes[] = {
    { "192.0.2.",   95, NFW_ALERT_BLACKLISTED_IP   }, /* TEST-NET-1 */
    { "198.51.100.", 95, NFW_ALERT_BLACKLISTED_IP   }, /* TEST-NET-2 */
    { "203.0.113.",  95, NFW_ALERT_BLACKLISTED_IP   }, /* TEST-NET-3 */
    { "0.0.0.0",     90, NFW_ALERT_BLACKLISTED_IP   }, /* Unspecified */
    { NULL, 0, NULL }
};

bool nfw_check_ip_reputation(nfw_state_t *state,
                              const char *src_ip,
                              int *score_out,
                              nfw_threat_log_t *log)
{
    if (!state || !state->cfg.enable_ip_reputation || !src_ip)
        return false;

    int score           = 0;
    const char *label   = NULL;
    int i;

    /* Check known-bad prefix table */
    for (i = 0; nfw_known_bad_prefixes[i].prefix; i++) {
        if (strncmp(src_ip, nfw_known_bad_prefixes[i].prefix,
                    strlen(nfw_known_bad_prefixes[i].prefix)) == 0) {
            score = nfw_known_bad_prefixes[i].score;
            label = nfw_known_bad_prefixes[i].label;
            break;
        }
    }

    if (score_out) *score_out = score;

    if (score >= NFW_REPUTATION_WARN) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->ip_reputation = score;
            log->threat_name   = label ? label : NFW_ALERT_BLACKLISTED_IP;
            log->threat_type   = "IP Reputation";
            log->action        = (score >= NFW_REPUTATION_BLOCK)
                                     ? NFW_ACTION_BLOCK
                                     : NFW_ACTION_WARN;
            log->severity      = (score >= NFW_REPUTATION_BLOCK)
                                     ? NFW_SEV_CRITICAL
                                     : NFW_SEV_HIGH;
            log->confidence    = score / 100.0;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – geolocation
 * ------------------------------------------------------------------------- */

/* Check if a 2-letter country code appears in a comma-separated list */
static bool nfw_country_in_list(const char *country_code,
                                 const char *list)
{
    if (!country_code || !list || !*list) return false;

    const char *p = list;
    while (*p) {
        /* skip spaces */
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        if (strncasecmp(p, country_code, 2) == 0) {
            char next = *(p + 2);
            if (next == '\0' || next == ',' || next == ' ')
                return true;
        }
        /* advance to next token */
        while (*p && *p != ',') p++;
    }
    return false;
}

bool nfw_check_geolocation(nfw_state_t *state,
                            const char *country_code,
                            nfw_threat_log_t *log)
{
    if (!state || !state->cfg.geo_blocking_enabled || !country_code)
        return false;

    bool denied = nfw_country_in_list(country_code,
                                       state->cfg.deny_countries);

    /* If allowed_countries is set, only those are permitted */
    if (!denied && state->cfg.allowed_countries[0] != '\0') {
        denied = !nfw_country_in_list(country_code,
                                       state->cfg.allowed_countries);
    }

    if (denied) {
        nfw_fill_log_defaults(log, NULL);
        if (log) {
            log->severity    = NFW_SEV_HIGH;
            log->threat_type = "Geolocation";
            log->threat_name = NFW_ALERT_RESTRICTED_GEO;
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = 1.0;
            log->geo_source  = country_code;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – URL homograph / Unicode spoofing
 * ------------------------------------------------------------------------- */

/* Unicode script block ranges (simplified – covers the most-abused blocks) */
typedef struct {
    unsigned int start;
    unsigned int end;
    const char  *name;
} nfw_unicode_block_t;

static const nfw_unicode_block_t nfw_unicode_blocks[] = {
    { 0x0000, 0x007F, "Basic Latin"          },
    { 0x0080, 0x00FF, "Latin-1 Supplement"   },
    { 0x0400, 0x04FF, "Cyrillic"             },
    { 0x0370, 0x03FF, "Greek"                },
    { 0x0600, 0x06FF, "Arabic"               },
    { 0x0900, 0x097F, "Devanagari"           },
    { 0x4E00, 0x9FFF, "CJK Unified"          },
    { 0,      0,      NULL                   }
};

/* Decode a single UTF-8 codepoint from *s, advance *s */
static unsigned int nfw_utf8_next(const unsigned char **s)
{
    unsigned int cp = 0;
    unsigned char c = **s;
    if (!c) return 0;

    if ((c & 0x80) == 0) {
        cp = c;
        (*s)++;
    } else if ((c & 0xE0) == 0xC0) {
        /* 2-byte sequence: need 1 continuation byte */
        cp = (c & 0x1F) << 6;
        (*s)++;
        if (**s == '\0') return 0;
        cp |= (**s & 0x3F); (*s)++;
    } else if ((c & 0xF0) == 0xE0) {
        /* 3-byte sequence: need 2 continuation bytes */
        cp = (c & 0x0F) << 12;
        (*s)++;
        if (**s == '\0') return 0;
        cp |= ((**s) & 0x3F) << 6; (*s)++;
        if (**s == '\0') return 0;
        cp |= ((**s) & 0x3F);      (*s)++;
    } else if ((c & 0xF8) == 0xF0) {
        /* 4-byte sequence: need 3 continuation bytes */
        cp = (c & 0x07) << 18;
        (*s)++;
        if (**s == '\0') return 0;
        cp |= ((**s) & 0x3F) << 12; (*s)++;
        if (**s == '\0') return 0;
        cp |= ((**s) & 0x3F) << 6;  (*s)++;
        if (**s == '\0') return 0;
        cp |= ((**s) & 0x3F);       (*s)++;
    } else {
        (*s)++; /* invalid byte – skip */
    }
    return cp;
}

static const char *nfw_unicode_block_name(unsigned int cp)
{
    int i;
    for (i = 0; nfw_unicode_blocks[i].name; i++) {
        if (cp >= nfw_unicode_blocks[i].start &&
            cp <= nfw_unicode_blocks[i].end)
            return nfw_unicode_blocks[i].name;
    }
    return "Other";
}

bool nfw_check_homograph(nfw_state_t *state,
                          const char *domain,
                          nfw_threat_log_t *log)
{
    if (!state || !state->cfg.homograph_detection || !domain)
        return false;

    /* Check for Punycode labels (xn--) */
    if (strncasecmp(domain, "xn--", 4) == 0 ||
        strstr(domain, ".xn--") != NULL) {

        nfw_fill_log_defaults(log, NULL);
        if (log) {
            log->severity    = NFW_SEV_MEDIUM;
            log->threat_type = "Homograph Attack";
            log->threat_name = NFW_ALERT_PUNYCODE_ABUSE;
            log->action      = state->cfg.homograph_strict
                                   ? NFW_ACTION_BLOCK
                                   : NFW_ACTION_WARN;
            log->confidence  = 0.70;
        }
        return true;
    }

    /* Scan for non-ASCII / mixed-script characters */
    const unsigned char *p         = (const unsigned char *)domain;
    const char          *first_block = NULL;
    bool                 mixed        = false;
    bool                 has_emoji    = false;
    bool                 has_rtl      = false;

    while (*p) {
        unsigned int cp = nfw_utf8_next(&p);
        if (cp == 0) break;

        /* Emoji range (simplified) */
        if (cp >= 0x1F300 && cp <= 0x1FAFF) {
            has_emoji = true;
            break;
        }

        /* RTL override (U+202E) */
        if (cp == 0x202E) {
            has_rtl = true;
            break;
        }

        if (cp <= 0x007F) continue; /* pure ASCII is fine */

        const char *block = nfw_unicode_block_name(cp);
        if (!first_block) {
            first_block = block;
        } else if (strcmp(block, first_block) != 0 &&
                   strcmp(block, "Basic Latin") != 0 &&
                   strcmp(first_block, "Basic Latin") != 0) {
            mixed = true;
            break;
        }
    }

    if (has_emoji || has_rtl || mixed) {
        nfw_fill_log_defaults(log, NULL);
        if (log) {
            log->severity    = NFW_SEV_HIGH;
            log->threat_type = "Homograph Attack";
            log->threat_name = has_emoji || has_rtl
                                   ? NFW_ALERT_HOMOGRAPH_DOMAIN
                                   : NFW_ALERT_MIXED_SCRIPT_DOMAIN;
            log->action      = state->cfg.homograph_strict
                                   ? NFW_ACTION_BLOCK
                                   : NFW_ACTION_WARN;
            log->confidence  = 0.85;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – DNS tunneling
 * ------------------------------------------------------------------------- */

bool nfw_check_dns_tunneling(nfw_state_t *state,
                              const char *query_name,
                              const char *query_type,
                              size_t payload_len,
                              nfw_threat_log_t *log)
{
    if (!state || !state->cfg.detect_dns_tunneling || !query_name)
        return false;

    bool suspicious = false;
    double confidence = 0.0;

    /* Oversized payload */
    if (payload_len > NFW_DNS_PAYLOAD_MAX_SAFE) {
        suspicious = true;
        confidence = 0.75;
    }

    /* Very long query name */
    size_t qlen = strlen(query_name);
    if (qlen > NFW_DNS_QUERY_MAX_SAFE) {
        suspicious = true;
        confidence = (confidence > 0.80) ? confidence : 0.80;
    }

    /* High entropy in the leftmost label (base64/hex-encoded data) */
    if (qlen > 0) {
        /* Isolate the first label */
        const char *dot = strchr(query_name, '.');
        size_t label_len = dot ? (size_t)(dot - query_name) : qlen;
        if (label_len >= 8) {
            double entropy = nfw_string_entropy(query_name, label_len);
            if (entropy >= NFW_DNS_ENTROPY_THRESHOLD) {
                suspicious = true;
                confidence = (confidence > 0.85) ? confidence : 0.85;
            }
        }
    }

    /* TXT records used to carry arbitrary data */
    if (query_type && strcasecmp(query_type, "TXT") == 0) {
        confidence += 0.05;
        if (confidence > 1.0) confidence = 1.0;
    }

    if (suspicious) {
        nfw_fill_log_defaults(log, NULL);
        if (log) {
            log->severity    = NFW_SEV_HIGH;
            log->threat_type = "DNS Tunneling";
            log->threat_name = NFW_ALERT_DNS_TUNNELING;
            log->protocol    = "DNS";
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = confidence;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – C2 beaconing
 * ------------------------------------------------------------------------- */

static nfw_c2_entry_t *nfw_find_or_create_c2(nfw_state_t *state,
                                               const char *src_ip,
                                               const char *dst_ip,
                                               uint16_t dst_port)
{
    uint32_t i;
    for (i = 0; i < state->c2_table_count; i++) {
        nfw_c2_entry_t *e = &state->c2_table[i];
        if (strcmp(e->src_ip, src_ip) == 0 &&
            strcmp(e->dst_ip, dst_ip) == 0 &&
            e->dst_port == dst_port)
            return e;
    }

    if (state->c2_table_count >= NFW_MAX_C2_ENTRIES) {
        /* Evict entry 0 (FIFO) */
        memmove(&state->c2_table[0], &state->c2_table[1],
                sizeof(nfw_c2_entry_t) * (NFW_MAX_C2_ENTRIES - 1));
        state->c2_table_count = NFW_MAX_C2_ENTRIES - 1;
    }

    nfw_c2_entry_t *e = &state->c2_table[state->c2_table_count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->src_ip,  src_ip,  NFW_MAX_IP_LEN - 1);
    strncpy(e->dst_ip,  dst_ip,  NFW_MAX_IP_LEN - 1);
    e->dst_port = dst_port;
    return e;
}

bool nfw_check_c2_beaconing(nfw_state_t *state,
                             const char *src_ip,
                             const char *dst_ip,
                             uint16_t dst_port,
                             size_t payload_len,
                             nfw_threat_log_t *log)
{
    if (!state || !state->cfg.detect_c2_communication || !src_ip || !dst_ip)
        return false;

    nfw_c2_entry_t *e = nfw_find_or_create_c2(state, src_ip,
                                                dst_ip, dst_port);

    time_t now = time(NULL);
    int sc = e->sample_count;
    int n;
    int i;
    double intervals[NFW_C2_MIN_SAMPLES];
    double sum;
    double mean;
    double sq_sum;
    double stddev;
    double jitter;
    double d;
    bool payload_consistent;
    bool beaconing;

    if (sc < NFW_C2_MIN_SAMPLES) {
        e->last_seen[sc]    = now;
        e->payload_lens[sc] = payload_len;
        e->sample_count++;
        return false; /* not enough data yet */
    }

    /* Compute inter-arrival intervals */
    n = NFW_C2_MIN_SAMPLES;
    for (i = 0; i < n - 1; i++) {
        intervals[i] = difftime(e->last_seen[i + 1], e->last_seen[i]);
    }
    intervals[n - 1] = difftime(now, e->last_seen[n - 1]);

    /* Mean interval */
    sum = 0;
    for (i = 0; i < n; i++) sum += intervals[i];
    mean = sum / n;

    if (mean <= 0) return false;

    /* Standard deviation */
    sq_sum = 0;
    for (i = 0; i < n; i++) {
        d = intervals[i] - mean;
        sq_sum += d * d;
    }
    stddev = sqrt(sq_sum / n);
    jitter = stddev / mean;

    /* Consistent payload sizes are another indicator */
    payload_consistent = true;
    for (i = 1; i < n; i++) {
        size_t a = e->payload_lens[i];
        size_t b = e->payload_lens[0];
        size_t diff = (a > b) ? (a - b) : (b - a);
        if (diff > 64) {
            payload_consistent = false;
            break;
        }
    }

    beaconing = (jitter <= NFW_C2_JITTER_MAX) && payload_consistent;

    /* Slide the window */
    memmove(e->last_seen, e->last_seen + 1,
            sizeof(time_t) * (NFW_C2_MIN_SAMPLES - 1));
    e->last_seen[NFW_C2_MIN_SAMPLES - 1] = now;
    memmove(e->payload_lens, e->payload_lens + 1,
            sizeof(size_t) * (NFW_C2_MIN_SAMPLES - 1));
    e->payload_lens[NFW_C2_MIN_SAMPLES - 1] = payload_len;

    if (beaconing) {
        nfw_fill_log_defaults(log, src_ip);
        if (log) {
            log->severity    = NFW_SEV_CRITICAL;
            log->threat_type = "C2 Communication";
            log->threat_name = NFW_ALERT_C2_BEACONING;
            strncpy(log->dest_ip, dst_ip, NFW_MAX_IP_LEN - 1);
            log->port        = dst_port;
            log->protocol    = "TCP";
            log->action      = NFW_ACTION_BLOCK;
            log->confidence  = 1.0 - jitter;
            if (log->confidence < 0.0) log->confidence = 0.0;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – HTTP header anomalies
 * ------------------------------------------------------------------------- */

bool nfw_check_http_headers(nfw_state_t *state,
                             const char *headers,
                             size_t headers_len,
                             nfw_threat_log_t *log)
{
    bool suspicious = false;
    const char *xff;
    const char *p;
    int commas;

    if (!state || !state->cfg.http_inspection || !headers || !headers_len)
        return false;

    /* Missing User-Agent */
    if (strstr(headers, "User-Agent:") == NULL &&
        strstr(headers, "user-agent:") == NULL) {
        suspicious = true;
    }

    /* Path traversal in request line – check the most common patterns */
    if (strstr(headers, "../") != NULL ||
        strstr(headers, "%2e%2e/") != NULL ||
        strstr(headers, "%2E%2E/") != NULL) {
        suspicious = true;
    }

    /* X-Forwarded-For loop detection */
    xff = strstr(headers, "X-Forwarded-For:");
    if (xff) {
        /* Count commas – many hops suggest loop or spoofing */
        commas = 0;
        p = xff;
        while (*p && *p != '\r' && *p != '\n') {
            if (*p == ',') commas++;
            p++;
        }
        if (commas > 8) suspicious = true;
    }

    if (suspicious) {
        nfw_fill_log_defaults(log, NULL);
        if (log) {
            log->severity    = NFW_SEV_MEDIUM;
            log->threat_type = "Protocol Anomaly";
            log->threat_name = NFW_ALERT_HTTP_HEADER_ANOMALY;
            log->protocol    = "HTTP";
            log->action      = NFW_ACTION_WARN;
            log->confidence  = 0.70;
        }
        return true;
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Detection – TLS cipher suite
 * ------------------------------------------------------------------------- */

bool nfw_check_tls_cipher(nfw_state_t *state,
                           const char *cipher_suite,
                           const char *tls_version,
                           nfw_threat_log_t *log)
{
    if (!state || !state->cfg.validate_ssl_certificate || !cipher_suite)
        return false;

    int i;

    /* Check for known-weak cipher prefixes */
    for (i = 0; nfw_weak_ciphers[i]; i++) {
        if (strncasecmp(cipher_suite, nfw_weak_ciphers[i],
                        strlen(nfw_weak_ciphers[i])) == 0) {
            nfw_fill_log_defaults(log, NULL);
            if (log) {
                log->severity    = NFW_SEV_HIGH;
                log->threat_type = "TLS Security";
                log->threat_name = NFW_ALERT_WEAK_CIPHER;
                log->protocol    = "TLS";
                log->action      = NFW_ACTION_BLOCK;
                log->confidence  = 0.95;
            }
            return true;
        }
    }

    /* Check for deprecated TLS versions */
    if (tls_version && state->cfg.detect_tls_downgrade) {
        for (i = 0; nfw_bad_tls_versions[i]; i++) {
            if (strcasecmp(tls_version, nfw_bad_tls_versions[i]) == 0) {
                nfw_fill_log_defaults(log, NULL);
                if (log) {
                    log->severity    = NFW_SEV_HIGH;
                    log->threat_type = "TLS Downgrade";
                    log->threat_name = NFW_ALERT_TLS_DOWNGRADE;
                    log->protocol    = "TLS";
                    log->action      = NFW_ACTION_WARN;
                    log->confidence  = 0.90;
                }
                return true;
            }
        }
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Logging
 * ------------------------------------------------------------------------- */

const char *nfw_severity_str(nfw_severity_t severity)
{
    switch (severity) {
        case NFW_SEV_LOW:      return "LOW";
        case NFW_SEV_MEDIUM:   return "MEDIUM";
        case NFW_SEV_HIGH:     return "HIGH";
        case NFW_SEV_CRITICAL: return "CRITICAL";
        default:               return "UNKNOWN";
    }
}

const char *nfw_action_str(nfw_action_t action)
{
    switch (action) {
        case NFW_ACTION_ALLOW:   return "ALLOW";
        case NFW_ACTION_MONITOR: return "MONITOR";
        case NFW_ACTION_WARN:    return "WARN";
        case NFW_ACTION_BLOCK:   return "BLOCK";
        default:                 return "UNKNOWN";
    }
}

char *nfw_log_to_json(const nfw_threat_log_t *log)
{
    if (!log) return NULL;

    /* Estimate a generous buffer size */
    size_t buf_size = 1024;
    char *buf = (char *)malloc(buf_size);
    if (!buf) return NULL;

    int n = snprintf(buf, buf_size,
        "{"
        "\"timestamp\":\"%s\","
        "\"severity\":\"%s\","
        "\"threat_type\":\"%s\","
        "\"threat_name\":\"%s\","
        "\"source_ip\":\"%s\","
        "\"dest_ip\":\"%s\","
        "\"port\":%u,"
        "\"protocol\":\"%s\","
        "\"action\":\"%s\","
        "\"confidence\":%.2f,"
        "\"geo_source\":\"%s\","
        "\"ip_reputation\":%d"
        "}",
        log->timestamp,
        nfw_severity_str(log->severity),
        log->threat_type  ? log->threat_type  : "",
        log->threat_name  ? log->threat_name  : "",
        log->source_ip,
        log->dest_ip,
        (unsigned)log->port,
        log->protocol     ? log->protocol     : "",
        nfw_action_str(log->action),
        log->confidence,
        log->geo_source   ? log->geo_source   : "",
        log->ip_reputation);

    if (n < 0 || (size_t)n >= buf_size) {
        /* Truncated or encoding error – try a larger buffer */
        free(buf);
        if (n < 0) {
            /* snprintf encoding error: fall back to a fixed large size */
            buf_size = 2048;
        } else {
            buf_size = (size_t)n + 2;
        }
        buf = (char *)malloc(buf_size);
        if (!buf) return NULL;
        snprintf(buf, buf_size,
            "{"
            "\"timestamp\":\"%s\","
            "\"severity\":\"%s\","
            "\"threat_type\":\"%s\","
            "\"threat_name\":\"%s\","
            "\"source_ip\":\"%s\","
            "\"dest_ip\":\"%s\","
            "\"port\":%u,"
            "\"protocol\":\"%s\","
            "\"action\":\"%s\","
            "\"confidence\":%.2f,"
            "\"geo_source\":\"%s\","
            "\"ip_reputation\":%d"
            "}",
            log->timestamp,
            nfw_severity_str(log->severity),
            log->threat_type  ? log->threat_type  : "",
            log->threat_name  ? log->threat_name  : "",
            log->source_ip,
            log->dest_ip,
            (unsigned)log->port,
            log->protocol     ? log->protocol     : "",
            nfw_action_str(log->action),
            log->confidence,
            log->geo_source   ? log->geo_source   : "",
            log->ip_reputation);
    }

    return buf;
}

void nfw_log_write(const nfw_threat_log_t *log, FILE *out)
{
    if (!log || !out) return;
    char *json = nfw_log_to_json(log);
    if (json) {
        fprintf(out, "%s\n", json);
        free(json);
    }
}

bool nfw_log_write_history(const nfw_threat_log_t *log)
{
    char report_file[1105];
    time_t now;
    char *json;

    if (!log) {
        return false;
    }

    json = nfw_log_to_json(log);
    if (!json) {
        return false;
    }

    now = time(NULL);
    if (0 != cl_json_history_append_daily_json(now,
                                               "network-reports",
                                               json,
                                               report_file,
                                               sizeof(report_file))) {
        free(json);
        return false;
    }
    free(json);

    cli_dbgmsg("nfw_log_write_history: JSON history report saved: %s\n", report_file);

    return true;
}
