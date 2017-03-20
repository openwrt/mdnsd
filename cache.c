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
#include "interface.h"

static struct uloop_timeout cache_gc;
struct avl_tree services;
AVL_TREE(records, avl_strcmp, true, NULL);

static void
cache_record_free(struct cache_record *r)
{
	DBG(2, "%s %s\n", dns_type_string(r->type), r->record);
	avl_delete(&records, &r->avl);
	free(r);
}

static void
cache_service_free(struct cache_service *s)
{
	DBG(2, "%s\n", s->entry);
	avl_delete(&services, &s->avl);
	free(s);
}

static int
cache_is_expired(time_t t, uint32_t ttl, int frac)
{
	if (monotonic_time() - t >= ttl * frac / 100)
		return 1;

	return 0;
}

static void
cache_gc_timer(struct uloop_timeout *timeout)
{
	struct cache_record *r, *p;
	struct cache_service *s, *t;

	avl_for_each_element_safe(&records, r, avl, p) {
		if (!cache_is_expired(r->time, r->ttl, r->refresh))
			continue;
		/* Records other than A(AAA) are handled as services */
		if (r->type != TYPE_A && r->type != TYPE_AAAA) {
			if (cache_is_expired(r->time, r->ttl, 100))
				cache_record_free(r);
			continue;
		}
		if (r->refresh >= 100) {
			cache_record_free(r);
			continue;
		}
		r->refresh += 50;
		dns_send_question(r->iface, (struct sockaddr *)&r->from, r->record, r->type, 0);
	}

	avl_for_each_element_safe(&services, s, avl, t) {
		if (!s->host)
			continue;
		if (!cache_is_expired(s->time, s->ttl, s->refresh))
			continue;
		if (s->refresh >= 100) {
			cache_service_free(s);
			continue;
		}
		s->refresh += 50;
		dns_send_question(s->iface, NULL, s->entry, TYPE_PTR, 0);
	}

	uloop_timeout_set(timeout, 10000);
}

int
cache_init(void)
{
	avl_init(&services, avl_strcmp, true, NULL);

	cache_gc.cb = cache_gc_timer;
	uloop_timeout_set(&cache_gc, 10000);

	return 0;
}

void cache_cleanup(struct interface *iface)
{
	struct cache_record *r, *p;
	struct cache_service *s, *t;

	avl_for_each_element_safe(&services, s, avl, t)
		if (!iface || iface == s->iface)
			cache_service_free(s);

	avl_for_each_element_safe(&records, r, avl, p)
		if (!iface || iface == r->iface)
			cache_record_free(r);
}

void
cache_update(void)
{
	struct interface *iface;
	struct cache_service *s;

	vlist_for_each_element(&interfaces, iface, node)
		avl_for_each_element(&services, s, avl)
			dns_send_question(iface, NULL, s->entry, TYPE_PTR, 0);
}

static struct cache_service*
cache_service(struct interface *iface, char *entry, int hlen, int ttl)
{
	struct cache_service *s, *t;
	char *entry_buf;
	char *host_buf;
	char *type;

	avl_for_each_element_safe(&services, s, avl, t)
		if (!strcmp(s->entry, entry)) {
			s->refresh = 50;
			s->time = monotonic_time();
			s->ttl = ttl;
			return s;
		}

	s = calloc_a(sizeof(*s),
		&entry_buf, strlen(entry) + 1,
		&host_buf, hlen ? hlen + 1 : 0);

	s->avl.key = s->entry = strcpy(entry_buf, entry);
	s->time = monotonic_time();
	s->ttl = ttl;
	s->iface = iface;
	s->refresh = 50;

	if (hlen)
		s->host = strncpy(host_buf, s->entry, hlen);

	type = strstr(entry_buf, "._");
	if (type)
		type++;
	if (type)
		s->avl.key = type;
	avl_insert(&services, &s->avl);

	if (!hlen)
		dns_send_question(iface, NULL, entry, TYPE_PTR, iface->multicast);

	return s;
}

static struct cache_record*
cache_record_find(char *record, int type, int port, int rdlength, uint8_t *rdata)
{
	struct cache_record *l = avl_find_element(&records, record, l, avl);

	if (!l)
		return NULL;

	while (l && l->record && !strcmp(l->record, record)) {
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

void cache_answer(struct interface *iface, struct sockaddr *from, uint8_t *base,
		  int blen, char *name, struct dns_answer *a, uint8_t *rdata,
		  int flush)
{
	struct dns_srv_data *dsd = (struct dns_srv_data *) rdata;
	struct cache_record *r;
	int port = 0, dlen = 0, tlen = 0, nlen, rdlength;
	char *p = NULL;
	char *name_buf;
	void *rdata_ptr, *txt_ptr;
	int host_len = 0;
	static char *rdata_buffer = (char *) mdns_buf;
	time_t now = monotonic_time();

	nlen = strlen(name);

	switch (a->type) {
	case TYPE_PTR:
		if (a->rdlength < 2)
			return;

		if (dn_expand(base, base + blen, rdata, rdata_buffer, MAX_DATA_LEN) < 0) {
			perror("process_answer/dn_expand");
			return;
		}

		DBG(1, "A -> %s %s %s ttl:%d\n", dns_type_string(a->type), name, rdata_buffer, a->ttl);

		rdlength = strlen(rdata_buffer);

		if (strcmp(C_DNS_SD, name) != 0 &&
		    nlen + 1 < rdlength && !strcmp(rdata_buffer + rdlength - nlen, name))
			host_len = rdlength - nlen - 1;

		if (name[0] == '_')
			cache_service(iface, rdata_buffer, host_len, a->ttl);

		dlen = strlen(rdata_buffer) + 1;
		rdata = (uint8_t*)rdata_buffer;
		break;

	case TYPE_SRV:
		if (a->rdlength < 8)
			return;

		port = be16_to_cpu(dsd->port);
		memcpy(rdata_buffer, dsd, sizeof(*dsd));
		if (dn_expand(base, base + blen, (const uint8_t*)&dsd[1],
				&rdata_buffer[sizeof(*dsd)], MAX_DATA_LEN - sizeof(*dsd)) < 0) {
			perror("process_answer/dn_expand");
			return;
		}
		dlen = sizeof(*dsd) + strlen(&rdata_buffer[sizeof(*dsd)]) + 1;
		rdata = (uint8_t*)rdata_buffer;
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
			if (v && p + v < &rdata_buffer[rdlength])
				p += v + 1;
		} while (*p);
		break;

	case TYPE_A:
		if (a->rdlength != 4)
			return;
		dlen = 4;
		break;

	case TYPE_AAAA:
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
			DBG(1, "D -> %s %s ttl:%d\n", dns_type_string(r->type), r->record, r->ttl);
			r->time = now + 1 - r->ttl;
			r->refresh = 100;
		} else {
			r->ttl = a->ttl;
			r->time = now;
			r->refresh = 50;
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
	r->time = now;
	r->iface = iface;
	if (iface->v6)
		memcpy(&r->from, from, sizeof(struct sockaddr_in6));
	else
		memcpy(&r->from, from, sizeof(struct sockaddr_in));
	r->refresh = 50;

	if (tlen)
		r->txt = memcpy(txt_ptr, rdata_buffer, tlen);

	if (dlen)
		r->rdata = memcpy(rdata_ptr, rdata, dlen);

	if (avl_insert(&records, &r->avl))
		free(r);
	else
		DBG(1, "A -> %s %s ttl:%d\n", dns_type_string(r->type), r->record, r->ttl);
}

void
cache_dump_records(struct blob_buf *buf, const char *name)
{
	struct cache_record *r, *last, *next;
	const char *txt;
	char buffer[INET6_ADDRSTRLEN];

	last = avl_last_element(&records, last, avl);
	for (r = avl_find_element(&records, name, r, avl); r; r = next) {
		switch (r->type) {
		case TYPE_TXT:
			if (r->txt && strlen(r->txt)) {
				txt = r->txt;
				do {
					blobmsg_add_string(buf, "txt", txt);
					txt = &txt[strlen(txt) + 1];
				} while (*txt);
			}
			break;

		case TYPE_SRV:
			if (r->port)
				blobmsg_add_u32(buf, "port", r->port);
			break;

		case TYPE_A:
			if ((r->rdlength == 4) && inet_ntop(AF_INET, r->rdata, buffer, INET6_ADDRSTRLEN))
				blobmsg_add_string(buf, "ipv4", buffer);
			break;

		case TYPE_AAAA:
			if ((r->rdlength == 16) && inet_ntop(AF_INET6, r->rdata, buffer, INET6_ADDRSTRLEN))
				blobmsg_add_string(buf, "ipv6", buffer);
			break;
		}

		if (r == last)
			break;

		next = avl_next_element(r, avl);
		if (strcmp(r->record, next->record) != 0)
			break;
	}
}

void
cache_dump_recursive(struct blob_buf *b, const char *name, uint16_t type, struct interface *iface)
{
	time_t now = monotonic_time();
	for (struct cache_record *r = avl_find_ge_element(&records, name, r, avl);
			r && !strcmp(r->record, name);
			r = !avl_is_last(&records, &r->avl) ? avl_next_element(r, avl) : NULL) {
		int32_t ttl = r->ttl - (now - r->time);
		if (ttl <= 0 || (iface && iface->ifindex != r->iface->ifindex) ||
				(type != TYPE_ANY && type != r->type))
			continue;

		const char *txt;
		char buf[INET6_ADDRSTRLEN];
		void *k = blobmsg_open_table(b, NULL), *l;
		const struct dns_srv_data *dsd = (const struct dns_srv_data*)r->rdata;

		blobmsg_add_string(b, "name", r->record);
		blobmsg_add_string(b, "type", dns_type_string(r->type));
		blobmsg_add_u32(b, "ttl", ttl);

		switch (r->type) {
		case TYPE_TXT:
			if ((txt = r->txt) && strlen(txt)) {
				l = blobmsg_open_array(b, "data");
				do {
					blobmsg_add_string(b, NULL, txt);
					txt = &txt[strlen(txt) + 1];
				} while (*txt);
				blobmsg_close_array(b, l);
			}
			break;

		case TYPE_SRV:
			if (r->rdlength > sizeof(*dsd)) {
				blobmsg_add_u32(b, "priority", be16_to_cpu(dsd->priority));
				blobmsg_add_u32(b, "weight", be16_to_cpu(dsd->weight));
				blobmsg_add_u32(b, "port", be16_to_cpu(dsd->port));
				blobmsg_add_string(b, "target", (const char*)&dsd[1]);
			}
			break;

		case TYPE_PTR:
			if (r->rdlength > 0)
				blobmsg_add_string(b, "target", (const char*)r->rdata);
			break;

		case TYPE_A:
			if ((r->rdlength == 4) && inet_ntop(AF_INET, r->rdata, buf, sizeof(buf)))
				blobmsg_add_string(b, "target", buf);
			break;

		case TYPE_AAAA:
			if ((r->rdlength == 16) && inet_ntop(AF_INET6, r->rdata, buf, sizeof(buf)))
				blobmsg_add_string(b, "target", buf);
			break;
		}

		blobmsg_close_table(b, k);


		if (r->type == TYPE_PTR) {
			cache_dump_recursive(b, (const char*)r->rdata, TYPE_SRV, iface);
			cache_dump_recursive(b, (const char*)r->rdata, TYPE_TXT, iface);
		}

		if (r->type == TYPE_SRV) {
			cache_dump_recursive(b, (const char*)&dsd[1], TYPE_A, iface);
			cache_dump_recursive(b, (const char*)&dsd[1], TYPE_AAAA, iface);
		}
	}
}
