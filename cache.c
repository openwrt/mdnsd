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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <time.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg_json.h>
#include <libubox/kvlist.h>
#include <libubus.h>

#include "cache.h"
#include "util.h"
#include "dns.h"

static struct uloop_timeout cache_gc;
struct avl_tree records, entries, hosts;
static struct blob_buf b;

static struct kvlist types;

static void
cache_record_free(struct cache_record *r, int rem)
{
	DBG(2, "%s %s\n", dns_type_string(r->type), r->record);
	if (rem)
		avl_delete(&records, &r->avl);
	free(r);
}

static void
cache_entry_free(struct cache_entry *s)
{
	DBG(2, "%s\n", s->entry);
	avl_delete(&entries, &s->avl);
	free(s);
}

static int
cache_is_expired(time_t t, uint32_t ttl)
{
	if (time(NULL) - t >= ttl)
		return 1;

	return 0;
}

static void
cache_gc_timer(struct uloop_timeout *timeout)
{
	struct cache_record *r, *p;
	struct cache_entry *s, *t;

	avl_for_each_element_safe(&records, r, avl, p)
		if (cache_is_expired(r->time, r->ttl))
			cache_record_free(r, 1);

	avl_for_each_element_safe(&entries, s, avl, t) {
		if (!s->host)
			continue;
		if (cache_is_expired(s->time, s->ttl))
			cache_entry_free(s);
	}

	uloop_timeout_set(timeout, 10000);
}

static void
cache_load_services(void)
{
	struct blob_attr *cur;
	int rem;

	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_file(&b, "/lib/mdns/service-types"))
		return;

	blob_for_each_attr(cur, b.head, rem)
		kvlist_set(&types, blobmsg_name(cur), blobmsg_get_string(cur));
}

char*
cache_lookup_name(const char *key)
{
	return kvlist_get(&types, key);
}

int
cache_init(void)
{
	kvlist_init(&types, kvlist_strlen);
	avl_init(&entries, avl_strcmp, true, NULL);
	avl_init(&records, avl_strcmp, true, NULL);

	cache_gc.cb = cache_gc_timer;
	uloop_timeout_set(&cache_gc, 10000);
	cache_load_services();

	return 0;
}

void cache_cleanup(void)
{
	struct cache_record *r, *p;
	struct cache_entry *s, *t;

	avl_for_each_element_safe(&records, r, avl, p)
		cache_record_free(r, 1);

	avl_for_each_element_safe(&entries, s, avl, t)
		cache_entry_free(s);
}

void
cache_scan(void)
{
	struct cache_entry *s;

	avl_for_each_element(&entries, s, avl)
		dns_send_question(&listener, s->entry, TYPE_PTR);
}

static struct cache_entry*
cache_entry(struct uloop_fd *u, char *entry, int hlen, int ttl)
{
	struct cache_entry *s;
	char *entry_buf;
	char *host_buf;
	char *type;

	s = avl_find_element(&entries, entry, s, avl);
	if (s)
		return s;

	s = calloc_a(sizeof(*s),
		&entry_buf, strlen(entry) + 1,
		&host_buf, hlen ? hlen + 1 : 0);

	s->avl.key = s->entry = strcpy(entry_buf, entry);
	s->time = time(NULL);
	s->ttl = ttl;

	if (hlen)
		s->host = strncpy(host_buf, s->entry, hlen);

	type = strstr(entry_buf, "._");
	if (type)
		type++;
	if (type)
		s->avl.key = type;
	avl_insert(&entries, &s->avl);

	if (!hlen)
		dns_send_question(u, entry, TYPE_PTR);

	return s;
}

static struct cache_record*
cache_record_find(char *record, int type, int port, int rdlength, uint8_t *rdata)
{
	struct cache_record *l = avl_find_element(&records, record, l, avl);

	if (!l)
		return NULL;

	while (l && !avl_is_last(&records, &l->avl) && !strcmp(l->record, record)) {
		struct cache_record *r = l;

		l = avl_next_element(l, avl);
		if (r->type != type)
			continue;

		if (r->type == TYPE_TXT || (r->type == TYPE_SRV))
			return r;

		if (r->port != port)
			continue;

		if (r->rdlength != rdlength)
			continue;

		if (!!r->rdata != !!rdata)
			continue;

		if (!r->rdata || !rdata || memcmp(r->rdata, rdata, rdlength))
			continue;

		return r;
	}

	return NULL;
}

int
cache_host_is_known(char *record)
{
	struct cache_record *l = avl_find_element(&records, record, l, avl);

	if (!l)
		return 0;

	while (l && !avl_is_last(&records, &l->avl) && !strcmp(l->record, record)) {
		struct cache_record *r = l;

		l = avl_next_element(l, avl);
		if ((r->type != TYPE_A) && (r->type != TYPE_AAAA))
			continue;
		return 1;
	}

	return 0;
}

void
cache_answer(struct uloop_fd *u, uint8_t *base, int blen, char *name, struct dns_answer *a, uint8_t *rdata)
{
	struct dns_srv_data *dsd = (struct dns_srv_data *) rdata;
	struct cache_record *r;
	int port = 0, dlen = 0, tlen = 0, nlen, rdlength;
	char *p = NULL;
	char *name_buf;
	void *rdata_ptr, *txt_ptr;

	if (!(a->class & CLASS_IN))
		return;

	nlen = strlen(name);

	switch (a->type) {
	case TYPE_PTR:
		if (a->rdlength < 2)
			return;

		if (dn_expand(base, base + blen, rdata, rdata_buffer, MAX_DATA_LEN) < 0) {
			perror("process_answer/dn_expand");
			return;
		}

		DBG(1, "A -> %s %s %s\n", dns_type_string(a->type), name, rdata_buffer);

		rdlength = strlen(rdata_buffer);

		if (!strcmp(C_DNS_SD, name)) {
			cache_entry(u, rdata_buffer, 0, a->ttl);
			return;
		}

		if ((rdlength < nlen) && (rdlength - nlen - 1 > 0))
			return;

		cache_entry(u, rdata_buffer, rdlength - nlen - 1, a->ttl);
		return;

	case TYPE_SRV:
		if (a->rdlength < 8)
			return;

		port = be16_to_cpu(dsd->port);
		break;

	case TYPE_TXT:
		rdlength = a->rdlength;
		if (rdlength <= 2)
			return;

		memcpy(rdata_buffer, &rdata[1], rdlength);
		rdata_buffer[rdlength] = rdata_buffer[rdlength + 1] = '\0';
		tlen = rdlength + 1;
		p = &rdata_buffer[*rdata];

		do {
			uint8_t v = *p;

			*p = '\0';
			if (v)
				p += v + 1;
		} while (*p);
		break;

	case TYPE_A:
		cache_entry(u, name, strlen(name), a->ttl);
		if (a->rdlength != 4)
			return;
		dlen = 4;
		break;

	case TYPE_AAAA:
		cache_entry(u, name, strlen(name), a->ttl);
		if (a->rdlength != 16)
			return;
		dlen = 16;
		break;

	default:
		return;
	}

	r = cache_record_find(name, a->type, port, dlen, rdata);
	if (r) {
		if (!a->ttl) {
			cache_record_free(r, 1);
			DBG(1, "D -> %s %s ttl:%d\n", dns_type_string(r->type), r->record, r->ttl);
		} else {
			r->ttl = a->ttl;
			DBG(1, "A -> %s %s ttl:%d\n", dns_type_string(r->type), r->record, r->ttl);
		}
		return;
	}

	if (!a->ttl)
		return;

	r = calloc_a(sizeof(*r),
		&name_buf, strlen(name) + 1,
		&txt_ptr, tlen,
		&rdata_ptr, dlen);

	r->avl.key = r->record = strcpy(name_buf, name);
	r->type = a->type;
	r->ttl = a->ttl;
	r->port = port;
	r->rdlength = dlen;
	r->time = time(NULL);

	if (tlen)
		r->txt = memcpy(txt_ptr, rdata_buffer, tlen);

	if (dlen)
		r->rdata = memcpy(rdata_ptr, rdata, dlen);

	if (avl_insert(&records, &r->avl))
		free(r);
	else
		DBG(1, "A -> %s %s ttl:%d\n", dns_type_string(r->type), r->record, r->ttl);
}
