/*
 *  Shared JSON report helpers
 *
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef __JSON_REPORT_H
#define __JSON_REPORT_H

#include <stdio.h>
#include <time.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Write a JSON string value, escaping special characters. */
void cl_json_fwrite_string(FILE *fp, const char *s);

/*
 * Open history/reports/DD-MM-YYYY-<suffix>.jsonl in append mode.
 * Returns 0 on success, -1 on failure.
 */
int cl_json_history_open_daily_file(time_t event_time,
                                    const char *suffix,
                                    char *report_file,
                                    size_t report_file_size,
                                    FILE **fp);

/*
 * Append one JSON object line to history/reports/DD-MM-YYYY-<suffix>.jsonl.
 * Returns 0 on success, -1 on failure.
 */
int cl_json_history_append_daily_json(time_t event_time,
                                      const char *suffix,
                                      const char *json,
                                      char *report_file,
                                      size_t report_file_size);

#ifdef __cplusplus
}
#endif

#endif /* __JSON_REPORT_H */
