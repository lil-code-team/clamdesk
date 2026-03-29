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

#ifndef __NETWORK_FIREWALL_H
#define __NETWORK_FIREWALL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "clamav.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Threat alert names emitted by the network firewall module
 * ------------------------------------------------------------------------- */

/* Port scanning */
#define NFW_ALERT_PORT_SCAN_DETECTED    "Heuristics.Network.PortScanDetected"
#define NFW_ALERT_FAST_PORT_SEQUENCE    "Heuristics.Network.FastPortSequence"
#define NFW_ALERT_SUSPICIOUS_FINGERPRINT "Heuristics.Network.SuspiciousFingerprint"
#define NFW_ALERT_NMAP_SCAN             "Heuristics.Network.NmapScan"
#define NFW_ALERT_MASSCAN_ACTIVITY      "Heuristics.Network.MasscanActivity"

/* DDoS / brute force */
#define NFW_ALERT_POSSIBLE_DDOS         "Heuristics.Network.PossibleDDoS"
#define NFW_ALERT_SYN_FLOOD             "Heuristics.Network.SYNFlood"
#define NFW_ALERT_UDP_FLOOD             "Heuristics.Network.UDPFlood"
#define NFW_ALERT_HTTP_FLOOD            "Heuristics.Network.HTTPFlood"
#define NFW_ALERT_BRUTE_FORCE           "Heuristics.Network.BruteForceAttempt"
#define NFW_ALERT_CREDENTIAL_STUFFING   "Heuristics.Network.CredentialStuffing"

/* IP reputation */
#define NFW_ALERT_BLACKLISTED_IP        "Heuristics.Network.BlacklistedIP"
#define NFW_ALERT_HIGH_RISK_ISP         "Heuristics.Network.HighRiskISP"
#define NFW_ALERT_KNOWN_BOTNET_C2       "Heuristics.Network.KnownBotnetC2"
#define NFW_ALERT_SPAM_NETWORK          "Heuristics.Network.SpamNetwork"
#define NFW_ALERT_MALWARE_DISTRIBUTION  "Heuristics.Network.MalwareDistribution"

/* Geolocation */
#define NFW_ALERT_IMPOSSIBLE_TRAVEL     "Heuristics.Network.ImpossibleTravel"
#define NFW_ALERT_UNUSUAL_COUNTRY       "Heuristics.Network.UnusualCountry"
#define NFW_ALERT_RESTRICTED_GEO        "Heuristics.Network.RestrictedGeolocation"
#define NFW_ALERT_TOR_EXIT_NODE         "Heuristics.Network.TorExitNode"
#define NFW_ALERT_VPN_DETECTED          "Heuristics.Network.VPNDetected"
#define NFW_ALERT_PROXY_DETECTED        "Heuristics.Network.ProxyDetected"

/* URL / domain */
#define NFW_ALERT_HOMOGRAPH_DOMAIN      "Heuristics.Network.HomographDomain"
#define NFW_ALERT_PUNYCODE_ABUSE        "Heuristics.Network.PunycodeAbuse"
#define NFW_ALERT_MIXED_SCRIPT_DOMAIN   "Heuristics.Network.MixedScriptDomain"
#define NFW_ALERT_NEW_DOMAIN            "Heuristics.Network.NewDomain"
#define NFW_ALERT_DNS_REBINDING         "Heuristics.Network.DNSRebinding"
#define NFW_ALERT_DNS_TUNNELING         "Heuristics.Network.DNSTunneling"
#define NFW_ALERT_DNSSEC_FAILURE        "Heuristics.Network.DNSSECFailure"

/* Protocol anomalies */
#define NFW_ALERT_HTTP_HEADER_ANOMALY   "Heuristics.Network.HTTPHeaderAnomaly"
#define NFW_ALERT_TLS_DOWNGRADE         "Heuristics.Network.TLSDowngrade"
#define NFW_ALERT_WEAK_CIPHER           "Heuristics.Network.WeakCipherSuite"
#define NFW_ALERT_PATH_TRAVERSAL        "Heuristics.Network.PathTraversal"

/* Behavioral / threat-specific */
#define NFW_ALERT_C2_BEACONING          "Heuristics.Network.C2Beaconing"
#define NFW_ALERT_C2_COMMUNICATION      "Heuristics.Network.C2Communication"
#define NFW_ALERT_RANSOMWARE_C2         "Heuristics.Network.RansomwareC2"
#define NFW_ALERT_CRYPTOMINER           "Heuristics.Network.CryptominerPool"
#define NFW_ALERT_COVERT_CHANNEL        "Heuristics.Network.CovertChannel"

/* -------------------------------------------------------------------------
 * Severity levels for threat logging
 * ------------------------------------------------------------------------- */
typedef enum nfw_severity {
    NFW_SEV_LOW      = 0,
    NFW_SEV_MEDIUM   = 1,
    NFW_SEV_HIGH     = 2,
    NFW_SEV_CRITICAL = 3
} nfw_severity_t;

/* -------------------------------------------------------------------------
 * Action taken when a threat is detected
 * ------------------------------------------------------------------------- */
typedef enum nfw_action {
    NFW_ACTION_ALLOW   = 0,
    NFW_ACTION_MONITOR = 1,
    NFW_ACTION_WARN    = 2,
    NFW_ACTION_BLOCK   = 3
} nfw_action_t;

/* -------------------------------------------------------------------------
 * IP reputation score thresholds
 * ------------------------------------------------------------------------- */
#define NFW_REPUTATION_BLOCK   85   /* Score >= 85: BLOCK */
#define NFW_REPUTATION_WARN    50   /* Score 50-84: WARN  */
#define NFW_REPUTATION_MONITOR 20   /* Score 20-49: MONITOR */
                                    /* Score < 20: ALLOW  */

/* -------------------------------------------------------------------------
 * Per-IP connection tracking entry (for port scan / DDoS detection)
 * ------------------------------------------------------------------------- */
#define NFW_MAX_TRACKED_IPS  4096
#define NFW_MAX_IP_LEN         46  /* IPv6 string max length */
#define NFW_MAX_PORTS_TRACKED 256

typedef struct nfw_ip_record {
    char     ip[NFW_MAX_IP_LEN];
    time_t   first_seen;
    time_t   last_seen;
    uint32_t port_count;               /* distinct ports contacted */
    uint32_t connection_count;         /* total connections in window */
    uint32_t failed_login_count;       /* failed authentication attempts */
    uint16_t ports_seen[NFW_MAX_PORTS_TRACKED];
    uint32_t ports_seen_count;
    uint32_t syn_count;                /* SYN packets in window */
    uint32_t udp_count;                /* UDP packets in window */
    uint32_t http_request_count;       /* HTTP requests in window */
    bool     blocked;                  /* currently blocked */
    time_t   blocked_until;
} nfw_ip_record_t;

/* -------------------------------------------------------------------------
 * Threat log entry (JSON-serialisable)
 * ------------------------------------------------------------------------- */
typedef struct nfw_threat_log {
    char        timestamp[32];        /* ISO 8601 */
    nfw_severity_t severity;
    const char *threat_type;
    const char *threat_name;
    char        source_ip[NFW_MAX_IP_LEN];
    char        dest_ip[NFW_MAX_IP_LEN];
    uint16_t    port;
    const char *protocol;
    nfw_action_t action;
    double      confidence;           /* 0.0 – 1.0 */
    const char *geo_source;           /* country name / code */
    int         ip_reputation;        /* 0–100 */
} nfw_threat_log_t;

/* -------------------------------------------------------------------------
 * Firewall configuration (mirrors clamd.conf options)
 * ------------------------------------------------------------------------- */
typedef struct nfw_config {
    /* General */
    bool     enabled;

    /* Port scan */
    bool     allow_port_scanning;
    uint32_t port_scan_threshold;     /* connections in observation window */
    uint32_t port_scan_timeout;       /* observation window seconds */
    bool     block_scanned_ports;

    /* DDoS / rate limiting */
    uint32_t max_connections_per_ip;
    uint32_t max_requests_per_second;
    uint32_t max_failed_logins;
    uint32_t lockout_duration;        /* seconds */
    uint32_t grace_period;            /* seconds */

    /* IP reputation */
    bool     enable_ip_reputation;
    char     ip_reputation_db[256];

    /* Geolocation */
    bool     geo_blocking_enabled;
    char     allowed_countries[512];  /* comma-separated ISO codes */
    char     deny_countries[512];
    bool     detect_impossible_travel;
    bool     detect_unusual_location;

    /* URL / domain */
    bool     homograph_detection;
    bool     homograph_strict;        /* strict = block mixed-script */
    bool     dnssec_enabled;
    bool     detect_dns_rebinding;
    bool     detect_dns_tunneling;

    /* Protocol */
    bool     http_inspection;
    bool     validate_ssl_certificate;
    bool     detect_tls_downgrade;

    /* Behavioral */
    bool     detect_c2_communication;
    bool     enable_ml_models;
    double   ml_confidence_threshold; /* 0.0 – 1.0 */
} nfw_config_t;

/* -------------------------------------------------------------------------
 * Module state (opaque from outside)
 * ------------------------------------------------------------------------- */
typedef struct nfw_state nfw_state_t;

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/**
 * @brief Allocate and initialise the network firewall state.
 *
 * @param cfg   Populated configuration structure.
 * @return      Pointer to the new state on success, NULL on failure.
 */
nfw_state_t *nfw_init(const nfw_config_t *cfg);

/**
 * @brief Release all resources held by the firewall state.
 *
 * @param state State returned by nfw_init().
 */
void nfw_free(nfw_state_t *state);

/**
 * @brief Initialise a firewall config with safe defaults.
 *
 * @param cfg   Output config structure.
 */
void nfw_config_init_defaults(nfw_config_t *cfg);

/* ---- Detection functions ------------------------------------------------ */

/**
 * @brief Check whether the given source IP is performing a port scan.
 *
 * @param state     Firewall state.
 * @param src_ip    Source IP address string.
 * @param dst_port  Destination port being contacted.
 * @param log       Output: populated if a threat is detected (may be NULL).
 * @return          True if a port-scan pattern was detected.
 */
bool nfw_check_port_scan(nfw_state_t *state,
                         const char *src_ip,
                         uint16_t dst_port,
                         nfw_threat_log_t *log);

/**
 * @brief Check connection rates for DDoS / brute-force patterns.
 *
 * @param state           Firewall state.
 * @param src_ip          Source IP address string.
 * @param failed_login    True if this event is a failed authentication attempt.
 * @param is_syn          True if this is a SYN packet.
 * @param is_udp          True if this is a UDP packet.
 * @param is_http         True if this is an HTTP request.
 * @param log             Output: populated if a threat is detected (may be NULL).
 * @return                True if a DDoS / brute-force pattern was detected.
 */
bool nfw_check_ddos(nfw_state_t *state,
                    const char *src_ip,
                    bool failed_login,
                    bool is_syn,
                    bool is_udp,
                    bool is_http,
                    nfw_threat_log_t *log);

/**
 * @brief Evaluate IP reputation score.
 *
 * @param state       Firewall state.
 * @param src_ip      Source IP address string.
 * @param score_out   Output: reputation score 0–100 (higher = more malicious).
 * @param log         Output: populated if a threat is detected (may be NULL).
 * @return            True if the IP should be blocked or warned about.
 */
bool nfw_check_ip_reputation(nfw_state_t *state,
                              const char *src_ip,
                              int *score_out,
                              nfw_threat_log_t *log);

/**
 * @brief Check whether the source country is blocked by geolocation policy.
 *
 * @param state       Firewall state.
 * @param country_code Two-letter ISO 3166-1 alpha-2 country code (e.g. "US").
 * @param log         Output: populated if blocked (may be NULL).
 * @return            True if the country is denied.
 */
bool nfw_check_geolocation(nfw_state_t *state,
                            const char *country_code,
                            nfw_threat_log_t *log);

/**
 * @brief Detect homograph / Unicode spoofing attacks in a domain name.
 *
 * Checks for:
 *  - Mixed Unicode scripts (e.g. Cyrillic + Latin)
 *  - Punycode abuse (xn-- labels that resemble ASCII domains)
 *  - Emoji domains
 *  - RTL override characters
 *
 * @param state   Firewall state.
 * @param domain  Domain name to inspect (UTF-8 or ACE form).
 * @param log     Output: populated if an attack is detected (may be NULL).
 * @return        True if a homograph attack pattern was detected.
 */
bool nfw_check_homograph(nfw_state_t *state,
                          const char *domain,
                          nfw_threat_log_t *log);

/**
 * @brief Check a DNS query for tunneling / covert-channel patterns.
 *
 * @param state         Firewall state.
 * @param query_name    Full DNS query name (FQDN).
 * @param query_type    DNS record type (e.g. "TXT", "A").
 * @param payload_len   Length of the DNS payload in bytes.
 * @param log           Output: populated if detected (may be NULL).
 * @return              True if DNS tunneling was detected.
 */
bool nfw_check_dns_tunneling(nfw_state_t *state,
                              const char *query_name,
                              const char *query_type,
                              size_t payload_len,
                              nfw_threat_log_t *log);

/**
 * @brief Detect C2 beaconing patterns in outbound connections.
 *
 * Analyses the timing and payload characteristics of a series of
 * connections from the same source to the same destination to
 * identify regular heartbeat (beaconing) behaviour.
 *
 * @param state         Firewall state.
 * @param src_ip        Source IP address.
 * @param dst_ip        Destination IP address.
 * @param dst_port      Destination port.
 * @param payload_len   Payload size of this connection.
 * @param log           Output: populated if C2 beaconing is detected.
 * @return              True if beaconing pattern detected.
 */
bool nfw_check_c2_beaconing(nfw_state_t *state,
                             const char *src_ip,
                             const char *dst_ip,
                             uint16_t dst_port,
                             size_t payload_len,
                             nfw_threat_log_t *log);

/**
 * @brief Detect HTTP header anomalies.
 *
 * @param state         Firewall state.
 * @param headers       Raw HTTP headers string.
 * @param headers_len   Length of headers string.
 * @param log           Output: populated if anomaly detected (may be NULL).
 * @return              True if an HTTP anomaly was detected.
 */
bool nfw_check_http_headers(nfw_state_t *state,
                             const char *headers,
                             size_t headers_len,
                             nfw_threat_log_t *log);

/**
 * @brief Check TLS cipher suite for weak or deprecated algorithms.
 *
 * @param state         Firewall state.
 * @param cipher_suite  TLS cipher suite name string.
 * @param tls_version   TLS protocol version string (e.g. "TLSv1.2").
 * @param log           Output: populated if a weak cipher is detected.
 * @return              True if a weak or deprecated cipher was found.
 */
bool nfw_check_tls_cipher(nfw_state_t *state,
                           const char *cipher_suite,
                           const char *tls_version,
                           nfw_threat_log_t *log);

/* ---- Logging ------------------------------------------------------------ */

/**
 * @brief Serialise a threat log entry to a JSON string.
 *
 * The returned buffer is allocated with malloc() and must be freed by
 * the caller.
 *
 * @param log   Threat log entry to serialise.
 * @return      Heap-allocated JSON string, or NULL on error.
 */
char *nfw_log_to_json(const nfw_threat_log_t *log);

/**
 * @brief Write a threat log entry to the given FILE stream as JSON.
 *
 * @param log   Threat log entry.
 * @param out   Output stream (e.g. a log file opened with fopen).
 */
void nfw_log_write(const nfw_threat_log_t *log, FILE *out);

/**
 * @brief Append a threat log entry to the JSON history report directory.
 *
 * Writes one JSON object line to:
 * history/reports/DD-MM-YYYY-network-reports.jsonl
 *
 * @param log   Threat log entry.
 * @return      True on success, false on failure.
 */
bool nfw_log_write_history(const nfw_threat_log_t *log);

/* ---- Utility ------------------------------------------------------------ */

/**
 * @brief Convert an nfw_severity_t value to a human-readable string.
 */
const char *nfw_severity_str(nfw_severity_t severity);

/**
 * @brief Convert an nfw_action_t value to a human-readable string.
 */
const char *nfw_action_str(nfw_action_t action);

#ifdef __cplusplus
}
#endif

#endif /* __NETWORK_FIREWALL_H */
