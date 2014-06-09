/*
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _UTIL_H__
#define _UTIL_H__

#define DBG(level, fmt, ...) do { \
	if (debug >= level) \
		fprintf(stderr, "mdnsd: %s (%d): " fmt, __func__, __LINE__, ## __VA_ARGS__); \
	} while (0)

extern int debug;

void *memdup(const void *d, int l);

extern void signal_setup(void);
extern char* get_hostname(void);
extern uint32_t rand_time_delta(uint32_t t);

#endif
