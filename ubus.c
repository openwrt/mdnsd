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
#include <ctype.h>

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
static struct ubus_subscriber udebug_sub;

static int
umdns_reload(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	service_init(1);
	return 0;
}

static int
umdns_update(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	cache_update();
	return 0;
}

static int
umdns_announcements(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct service *s;
	void *c1 = NULL, *c2 = NULL;

	blob_buf_init(&b, 0);
	vlist_for_each_element(&announced_services, s, node) {
		// is something there?
		if (!s->id || !strlen(s->id))
			continue;

		if (!s->service || !strlen(s->service))
			continue;

		if (!s->port)
			continue;

		if (!c1) {
			c1 = blobmsg_open_table(&b, (const char *) s->service);
		}

		c2 = blobmsg_open_table(&b, s->id);

		blobmsg_add_u32(&b, "port", s->port);

		// check if there are any text entries
		if (s->txt_len) {
			void *c_txt = NULL;
			int i;

			// this string will hold text records
			char *txt_str = (char *) calloc(s->txt_len, sizeof(char));

			// we get some weird characters like \u000b, so get don't copy them
			for (i=0; i<s->txt_len; i++) {
				if ((ispunct(s->txt[i])) || (isalnum(s->txt[i])))
					txt_str[i] = (char) s->txt[i];
				else
					txt_str[i] = ' ';
			}

			txt_str[s->txt_len] = '\0';

			// a table of txt json objects
			c_txt = blobmsg_open_array(&b, "txt");

			// split based on space and add each token to output
			char *pch = NULL, *pchr = NULL;

			for (pch = strtok_r(txt_str, " ", &pchr); pch != NULL; pch = strtok_r(NULL, " ", &pchr)) {
				// add it to array
				blobmsg_add_string(&b, "txt", pch);
			}

			// close the array
			blobmsg_close_array(&b, c_txt);

			// free the calloced memory
			free(txt_str);
		}

		blobmsg_close_table(&b, c2);
		blobmsg_close_table(&b, c1);
		c1 = NULL;
	}

	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

enum {
	BROWSE_SERVICE,
	BROWSE_ARRAY,
	BROWSE_ADDRESS,
	BROWSE_MAX
};

static const struct blobmsg_policy browse_policy[] = {
	[BROWSE_SERVICE]	= { "service", BLOBMSG_TYPE_STRING },
	[BROWSE_ARRAY]		= { "array", BLOBMSG_TYPE_BOOL },
	[BROWSE_ADDRESS]	= { "address", BLOBMSG_TYPE_BOOL },
};

static int
umdns_browse(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct cache_service *s, *q;
	char *buffer = (char *) mdns_buf;
	struct blob_attr *data[BROWSE_MAX];
	void *c1 = NULL, *c2;
	char *service = NULL;
	int array = 0;
	bool address = true;

	blobmsg_parse(browse_policy, BROWSE_MAX, data, blob_data(msg), blob_len(msg));
	if (data[BROWSE_SERVICE])
		service = blobmsg_get_string(data[BROWSE_SERVICE]);
	if (data[BROWSE_ARRAY])
		array = blobmsg_get_u8(data[BROWSE_ARRAY]);
	if (data[BROWSE_ADDRESS])
		address = blobmsg_get_bool(data[BROWSE_ADDRESS]);

	blob_buf_init(&b, 0);

	avl_for_each_element(&services, s, avl) {
		const char *hostname = buffer;
		char *local;

		snprintf(buffer, MAX_NAME_LEN, "%s", (const char *) s->avl.key);
		local = strstr(buffer, ".local");
		if (local)
			*local = '\0';
		if (!strcmp(buffer, "_tcp") || !strcmp(buffer, "_udp"))
			continue;
		if (service && strcmp(buffer, service))
			continue;
		if (!c1) {
			c1 = blobmsg_open_table(&b, buffer);
		}
		snprintf(buffer, MAX_NAME_LEN, "%s", s->entry);
		local = strstr(buffer, "._");
		if (local)
			*local = '\0';
		c2 = blobmsg_open_table(&b, buffer);
		strncat(buffer, ".local", MAX_NAME_LEN);
		if (s->iface)
			blobmsg_add_string(&b, "iface", s->iface->name);
		cache_dump_records(&b, s->entry, array, &hostname);
		if (address)
			cache_dump_records(&b, hostname, array, NULL);
		blobmsg_close_table(&b, c2);
		q = avl_next_element(s, avl);
		if (!q || avl_is_last(&services, &s->avl) || strcmp(s->avl.key, q->avl.key)) {
			blobmsg_close_table(&b, c1);
			c1 = NULL;
		}
	}

	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

enum {
	HOSTS_ARRAY,
	__HOSTS_MAX
};
static const struct blobmsg_policy hosts_policy[] = {
	[HOSTS_ARRAY] = { "array", BLOBMSG_TYPE_BOOL }
};

static int
umdns_hosts(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct cache_record *prev = NULL;
	struct blob_attr *tb[__HOSTS_MAX];
	struct cache_record *r;
	bool array = false;
	void *c;

	blobmsg_parse(hosts_policy, __HOSTS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
	if (tb[HOSTS_ARRAY])
		array = blobmsg_get_bool(tb[HOSTS_ARRAY]);

	blob_buf_init(&b, 0);
	avl_for_each_element(&records, r, avl) {
		if (r->type != TYPE_A && r->type != TYPE_AAAA)
			continue;
		/* Query each domain just once */
		if (!prev || strcmp(r->record, prev->record)) {
			c = blobmsg_open_table(&b, r->record);
			cache_dump_records(&b, r->record, array, NULL);
			blobmsg_close_table(&b, c);
		}
		prev = r;
	}
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

enum {
	CFG_INTERFACES,
	CFG_KEEP,
	CFG_MAX
};

static const struct blobmsg_policy config_policy[] = {
	[CFG_INTERFACES]	= { "interfaces", BLOBMSG_TYPE_ARRAY },
	[CFG_KEEP]		= { "keep", BLOBMSG_TYPE_BOOL },
};

static int
umdns_set_config(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *data[CFG_MAX], *cur;
	int rem, keep = false;

	blobmsg_parse(config_policy, CFG_MAX, data, blob_data(msg), blob_len(msg));
	if (!data[CFG_INTERFACES])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!blobmsg_check_attr_list(data[CFG_INTERFACES], BLOBMSG_TYPE_STRING))
		return UBUS_STATUS_INVALID_ARGUMENT;

	keep = data[CFG_KEEP] && blobmsg_get_bool(data[CFG_KEEP]);
	if (!keep) {
		vlist_update(&interfaces);
		ubus_notify(ctx, obj, "set_config", NULL, 1000);
	}

	blobmsg_for_each_attr(cur, data[CFG_INTERFACES], rem)
		interface_add(blobmsg_data(cur));

	if (!keep)
		vlist_flush(&interfaces);

	return 0;
}

enum query_attr {
	QUERY_QUESTION,
	QUERY_IFACE,
	QUERY_TYPE,
	QUERY_MAX
};

static const struct blobmsg_policy query_policy[QUERY_MAX] = {
	[QUERY_QUESTION]= { "question", BLOBMSG_TYPE_STRING },
	[QUERY_IFACE]	= { "interface", BLOBMSG_TYPE_STRING },
	[QUERY_TYPE]	= { "type", BLOBMSG_TYPE_INT32 },
};

static int
umdns_query(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[QUERY_MAX], *c;
	const char *question = C_DNS_SD;
	const char *ifname;
	int type = TYPE_ANY;

	blobmsg_parse(query_policy, QUERY_MAX, tb, blob_data(msg), blob_len(msg));

	if (!(c = tb[QUERY_IFACE]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	ifname = blobmsg_get_string(c);

	if ((c = tb[QUERY_QUESTION]))
		question = blobmsg_get_string(c);

	if ((c = tb[QUERY_TYPE]))
		type = blobmsg_get_u32(c);

	struct interface *iface_v4 = interface_get(ifname, SOCK_MC_IPV4);
	struct interface *iface_v6 = interface_get(ifname, SOCK_MC_IPV6);

	if (!iface_v4 && !iface_v6)
		return UBUS_STATUS_NOT_FOUND;

	if (!strcmp(method, "query")) {
		if (iface_v4)
			dns_send_question(iface_v4, NULL, question, type, 1);

		if (iface_v6)
			dns_send_question(iface_v6, NULL, question, type, 1);

		return UBUS_STATUS_OK;
	} else if (!strcmp(method, "fetch")) {
		blob_buf_init(&b, 0);
		void *k = blobmsg_open_array(&b, "records");
		cache_dump_recursive(&b, question, type, iface_v4 ? iface_v4 : iface_v6);
		blobmsg_close_array(&b, k);
		ubus_send_reply(ctx, req, b.head);
		return UBUS_STATUS_OK;
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
}


static const struct ubus_method umdns_methods[] = {
	UBUS_METHOD("set_config", umdns_set_config, config_policy),
	UBUS_METHOD("query", umdns_query, query_policy),
	UBUS_METHOD("fetch", umdns_query, query_policy),
	UBUS_METHOD("browse", umdns_browse, browse_policy),
	UBUS_METHOD_NOARG("announcements", umdns_announcements),
	UBUS_METHOD_NOARG("update", umdns_update),
	UBUS_METHOD("hosts", umdns_hosts, hosts_policy),
	UBUS_METHOD_NOARG("reload", umdns_reload),
};

static struct ubus_object_type umdns_object_type =
	UBUS_OBJECT_TYPE("umdns", umdns_methods);

static struct ubus_object umdns_object = {
	.name = "umdns",
	.type = &umdns_object_type,
	.methods = umdns_methods,
	.n_methods = ARRAY_SIZE(umdns_methods),
};

static struct blob_attr *
find_attr(struct blob_attr *attr, const char *name, enum blobmsg_type type)
{
	struct blobmsg_policy policy = { name, type };
	struct blob_attr *ret;

	if (!attr)
		return NULL;

	blobmsg_parse_attr(&policy, 1, &ret, attr);

	return ret;
}

static void
umdns_udebug_config_cb(struct blob_attr *data)
{
	enum {
		CFG_ATTR_ENABLED,
		__CFG_ATTR_MAX
	};
	static const struct blobmsg_policy policy[__CFG_ATTR_MAX] = {
		[CFG_ATTR_ENABLED] = { "enabled", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__CFG_ATTR_MAX];
	bool en;

	data = find_attr(data, "service", BLOBMSG_TYPE_TABLE);
	data = find_attr(data, "umdns", BLOBMSG_TYPE_TABLE);
	if (!data)
		return;

	blobmsg_parse_attr(policy, __CFG_ATTR_MAX, tb, data);
	if (!tb[CFG_ATTR_ENABLED])
		return;

	en = !!atoi(blobmsg_get_string(tb[CFG_ATTR_ENABLED]));
	umdns_udebug_set_enabled(en);
}

static int
umdns_udebug_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	umdns_udebug_config_cb(msg);

	return 0;
}

static void
umdns_udebug_req_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	umdns_udebug_config_cb(msg);
}

static bool
umdns_udebug_sub_cb(struct ubus_context *ctx, struct ubus_subscriber *sub,
		     const char *path)
{
	return !strcmp(path, "udebug");
}


static void
ubus_connect_handler(struct ubus_context *ctx)
{
	uint32_t id;
	int ret;

	ret = ubus_add_object(ctx, &umdns_object);
	if (ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));

	udebug_sub.cb = umdns_udebug_notify_cb;
	udebug_sub.new_obj_cb = umdns_udebug_sub_cb;
	ubus_register_subscriber(&conn.ctx, &udebug_sub);
	if (ubus_lookup_id(&conn.ctx, "udebug", &id) == 0) {
		ubus_subscribe(&conn.ctx, &udebug_sub, id);
		ubus_invoke(&conn.ctx, id, "get_config", NULL, umdns_udebug_req_cb, NULL, 1000);
	}
}

void
ubus_startup(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}

int ubus_service_list(ubus_data_handler_t cb)
{
	uint32_t id;
	int ret;

	blob_buf_init(&b, 0);
	ret = ubus_lookup_id(&conn.ctx, "service", &id);
	if (ret)
		return ret;

	return ubus_invoke(&conn.ctx, id, "list", b.head, cb, NULL, 5 * 1000);
}
