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

#include <sys/types.h>
#include <arpa/inet.h>

#include <stdio.h>

#include <libubus.h>
#include <libubox/avl.h>
#include <libubox/uloop.h>

#include "ubus.h"
#include "cache.h"

static struct ubus_auto_conn conn;
static struct blob_buf b;

static int
mdns_reload(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	return 0;
}

static int
mdns_scan(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	cache_scan();
	return 0;
}

static void
mdns_add_records(const char *name)
{
	struct cache_record *r, *q = avl_find_element(&records, name, r, avl);
	const char *txt;
	char buffer[MAX_NAME_LEN];

	if (!q)
		return;

	do {
		r = q;
		switch (r->type) {
		case TYPE_TXT:
			if (r->txt && strlen(r->txt)) {
				txt = r->txt;
				do {
					blobmsg_add_string(&b, "txt", txt);
					txt = &txt[strlen(txt) + 1];
				} while (*txt);
			}
			break;

		case TYPE_SRV:
			if (r->port)
				blobmsg_add_u32(&b, "port", r->port);
			break;

		case TYPE_A:
			if ((r->rdlength == 4) && inet_ntop(AF_INET, r->rdata, buffer, INET6_ADDRSTRLEN))
				blobmsg_add_string(&b, "ipv4", buffer);
			break;

		case TYPE_AAAA:
			if ((r->rdlength == 16) && inet_ntop(AF_INET6, r->rdata, buffer, INET6_ADDRSTRLEN))
				blobmsg_add_string(&b, "ipv6", buffer);
			break;
		}
		q = avl_next_element(r, avl);
	} while (q && !strcmp(r->record, q->record));
}

static int
mdns_browse(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct cache_entry *s, *q;
	char buffer[MAX_NAME_LEN];
	void *c1 = NULL, *c2;

        blob_buf_init(&b, 0);
	avl_for_each_element(&entries, s, avl) {
		char *local;
		if (*((char *) s->avl.key) != '_')
			continue;
		snprintf(buffer, MAX_NAME_LEN, s->avl.key);
		local = strstr(buffer, ".local");
		if (local)
			*local = '\0';
		if (!strcmp(buffer, "_tcp") || !strcmp(buffer, "_udp"))
			continue;

		if (!c1) {
			c1 = blobmsg_open_table(&b, buffer);
		}
		snprintf(buffer, MAX_NAME_LEN, s->entry);
		local = strstr(buffer, "._");
		if (local)
			*local = '\0';
		c2 = blobmsg_open_table(&b, buffer);
		strncat(buffer, ".local", MAX_NAME_LEN);
		mdns_add_records(buffer);
		mdns_add_records(s->entry);
		blobmsg_close_table(&b, c2);
		q = avl_next_element(s, avl);
		if (!q || avl_is_last(&entries, &s->avl) || strcmp(s->avl.key, q->avl.key)) {
			blobmsg_close_table(&b, c1);
			c1 = NULL;
		}
	}
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static int
mdns_hosts(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct cache_entry *s;
	char buffer[MAX_NAME_LEN];
	void *c;

        blob_buf_init(&b, 0);
	avl_for_each_element(&entries, s, avl) {
		char *local;
		if (*((char *) s->avl.key) == '_')
			continue;
		snprintf(buffer, MAX_NAME_LEN, s->entry);
		local = strstr(buffer, "._");
		if (local)
			*local = '\0';
		c = blobmsg_open_table(&b, buffer);
		strncat(buffer, ".local", MAX_NAME_LEN);
		mdns_add_records(buffer);
		mdns_add_records(s->entry);
		blobmsg_close_table(&b, c);
	}
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static const struct ubus_method mdns_methods[] = {
	UBUS_METHOD_NOARG("scan", mdns_scan),
	UBUS_METHOD_NOARG("browse", mdns_browse),
	UBUS_METHOD_NOARG("hosts", mdns_hosts),
	UBUS_METHOD_NOARG("reload", mdns_reload),
};

static struct ubus_object_type mdns_object_type =
	UBUS_OBJECT_TYPE("mdns", mdns_methods);

static struct ubus_object mdns_object = {
	.name = "mdns",
	.type = &mdns_object_type,
	.methods = mdns_methods,
	.n_methods = ARRAY_SIZE(mdns_methods),
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	int ret;

	ret = ubus_add_object(ctx, &mdns_object);
	if (ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
}

void
ubus_startup(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}
