/*
 *  Shared JSON report helpers
 *
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <errno.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef _WIN32
#include <sys/stat.h>
#else
#include <direct.h>
#endif

#include "json_report.h"
#include "others.h"

void cl_json_fwrite_string(FILE *fp, const char *s)
{
    if (!s) {
        fputs("null", fp);
        return;
    }

    fputc('"', fp);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"') {
            fputs("\\\"", fp);
        } else if (c == '\\') {
            fputs("\\\\", fp);
        } else if (c == '\n') {
            fputs("\\n", fp);
        } else if (c == '\r') {
            fputs("\\r", fp);
        } else if (c == '\t') {
            fputs("\\t", fp);
        } else if (c < 0x20) {
            fprintf(fp, "\\u%04x", c);
        } else {
            fputc(c, fp);
        }
    }
    fputc('"', fp);
}

int cl_json_history_open_daily_file(time_t event_time,
                                    const char *suffix,
                                    char *report_file,
                                    size_t report_file_size,
                                    FILE **fp)
{
    char report_dir[1024];
    char date_str[16];
    struct tm tmp;

    if (!suffix || !report_file || !fp || report_file_size == 0) {
        return -1;
    }

#ifdef _WIN32
    if (0 != localtime_s(&tmp, &event_time)) {
#else
    if (!localtime_r(&event_time, &tmp)) {
#endif
        logg(LOGG_WARNING, "json-report-history: Failed to get local event time.\n");
        return -1;
    }

    strftime(date_str, sizeof(date_str), "%d-%m-%Y", &tmp);
    snprintf(report_dir, sizeof(report_dir), "history/reports");

#ifndef _WIN32
    if (mkdir("history", 0755) != 0 && errno != EEXIST) {
        logg(LOGG_WARNING, "json-report-history: Failed to create directory 'history': %s\n", strerror(errno));
        return -1;
    }
    if (mkdir(report_dir, 0755) != 0 && errno != EEXIST) {
        logg(LOGG_WARNING, "json-report-history: Failed to create directory '%s': %s\n", report_dir, strerror(errno));
        return -1;
    }
#else
    if (_mkdir("history") != 0 && errno != EEXIST) {
        logg(LOGG_WARNING, "json-report-history: Failed to create directory 'history': %s\n", strerror(errno));
        return -1;
    }
    if (_mkdir(report_dir) != 0 && errno != EEXIST) {
        logg(LOGG_WARNING, "json-report-history: Failed to create directory '%s': %s\n", report_dir, strerror(errno));
        return -1;
    }
#endif

    snprintf(report_file, report_file_size, "%s/%s-%s.jsonl", report_dir, date_str, suffix);

    *fp = fopen(report_file, "a");
    if (*fp == NULL) {
        logg(LOGG_WARNING, "json-report-history: Failed to open '%s' for appending: %s\n", report_file, strerror(errno));
        return -1;
    }

    return 0;
}

int cl_json_history_append_daily_json(time_t event_time,
                                      const char *suffix,
                                      const char *json,
                                      char *report_file,
                                      size_t report_file_size)
{
    FILE *fp;

    if (!json) {
        return -1;
    }

    if (0 != cl_json_history_open_daily_file(event_time,
                                             suffix,
                                             report_file,
                                             report_file_size,
                                             &fp)) {
        return -1;
    }

    fprintf(fp, "%s\n", json);
    fclose(fp);

    return 0;
}
