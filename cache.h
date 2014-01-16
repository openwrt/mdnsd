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

#ifndef _CACHE_H__
#define _CACHE_H__

#include <libubox/avl.h>
#include <libubox/list.h>

#include "dns.h"

struct cache_type {
        struct avl_node avl;

	char *key;
	char *val;
};

struct cache_entry {
        struct avl_node avl;

	char *entry;
	char *host;
	uint32_t ttl;
	time_t time;
};

struct cache_record {
        struct avl_node avl;

	char *record;
	uint16_t type;
	uint32_t ttl;
	int port;
	char *txt;
	uint8_t *rdata;
	uint16_t rdlength;
	time_t time;
};

extern struct avl_tree records, entries, types;

extern int cache_init(void);
extern void cache_scan(void);
extern void cache_cleanup(void);
extern void cache_answer(struct uloop_fd *u, uint8_t *base, int blen,
		char *name, struct dns_answer *a, uint8_t *rdata);
extern int cache_host_is_known(char *record);
extern char* cache_lookup_name(const char *key);

#endif
