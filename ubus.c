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
#include <libubox/vlist.h>
#include <libubox/uloop.h>

#include "util.h"
#include "ubus.h"
#include "cache.h"
#include "service.h"
#include "interface.h"

static struct ubus_auto_conn conn;
static struct blob_buf b;

static int
mdns_reload(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	service_init();
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

static int
mdns_browse(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct cache_entry *s, *q;
	char *buffer = (char *) mdns_buf;
	void *c1 = NULL, *c2;

	blob_buf_init(&b, 0);
	avl_for_each_element(&entries, s, avl) {
		char *local;
		if (*((char *) s->avl.key) != '_')
			continue;
		snprintf(buffer, MAX_NAME_LEN, "%s", (const char *) s->avl.key);
		local = strstr(buffer, ".local");
		if (local)
			*local = '\0';
		if (!strcmp(buffer, "_tcp") || !strcmp(buffer, "_udp"))
			continue;

		if (!c1) {
			c1 = blobmsg_open_table(&b, buffer);
		}
		snprintf(buffer, MAX_NAME_LEN, "%s", (const char *) s->entry);
		local = strstr(buffer, "._");
		if (local)
			*local = '\0';
		c2 = blobmsg_open_table(&b, buffer);
		strncat(buffer, ".local", MAX_NAME_LEN);
		cache_dump_records(&b, buffer);
		cache_dump_records(&b, s->entry);
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
	char *buffer = (char *) mdns_buf;
	void *c;

	blob_buf_init(&b, 0);
	avl_for_each_element(&entries, s, avl) {
		char *local;
		if (*((char *) s->avl.key) == '_')
			continue;
		snprintf(buffer, MAX_NAME_LEN, "%s", (const char *) s->entry);
		local = strstr(buffer, "._");
		if (local)
			*local = '\0';
		c = blobmsg_open_table(&b, buffer);
		strncat(buffer, ".local", MAX_NAME_LEN);
		cache_dump_records(&b, buffer);
		cache_dump_records(&b, s->entry);
		blobmsg_close_table(&b, c);
	}
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static const struct blobmsg_policy config_policy[] = {
	{ "interfaces", BLOBMSG_TYPE_ARRAY },
};

static int
mdns_set_config(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *data, *cur;
	int rem;

	blobmsg_parse(config_policy, 1, &data, blob_data(msg), blob_len(msg));
	if (!data)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!blobmsg_check_attr_list(data, BLOBMSG_TYPE_STRING))
		return UBUS_STATUS_INVALID_ARGUMENT;

	vlist_update(&interfaces);
	blobmsg_for_each_attr(cur, data, rem)
		interface_add(blobmsg_data(cur));
	vlist_flush(&interfaces);

	return 0;
}


static const struct ubus_method mdns_methods[] = {
	UBUS_METHOD("set_config", mdns_set_config, config_policy),
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
