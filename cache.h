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
#include <libubox/blob.h>

#include "dns.h"
#include "interface.h"

struct cache_service {
	struct avl_node avl;

	const char *entry;
	const char *host;
	uint32_t ttl;
	time_t time;
	struct interface *iface;
	int refresh;
};

struct cache_record {
	struct avl_node avl;

	const char *record;
	uint16_t type;
	uint32_t ttl;
	int port;
	const char *txt;
	const uint8_t *rdata;
	uint16_t rdlength;
	time_t time;
	struct interface *iface;
	struct sockaddr_storage from;
	int refresh;
};

extern struct avl_tree services;
extern struct avl_tree records;

int cache_init(void);
void cache_update(void);
void cache_cleanup(struct interface *iface);
void cache_answer(struct interface *iface, struct sockaddr *from, uint8_t *base,
		  int blen, char *name, struct dns_answer *a, uint8_t *rdata,
		  int flush);
int cache_host_is_known(char *record);
void cache_dump_records(struct blob_buf *buf, const char *name);
void cache_dump_recursive(struct blob_buf *b, const char *name, uint16_t type, struct interface *iface);

#endif
