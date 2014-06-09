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
#include <arpa/nameser.h>
#include <sys/socket.h>

#include <resolv.h>
#include <glob.h>
#include <stdio.h>
#include <time.h>

#include <uci.h>
#include <uci_blob.h>

#include <libubox/vlist.h>
#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg_json.h>

#include "dns.h"
#include "service.h"
#include "util.h"
#include "interface.h"

enum {
	SERVICE_PORT,
	SERVICE_TXT,
	__SERVICE_MAX,
};

struct service {
	struct vlist_node node;

	time_t t;

	const char *service;
	const char *daemon;
	const uint8_t *txt;
	int txt_len;
	int port;
	int active;
};

static const struct blobmsg_policy service_policy[__SERVICE_MAX] = {
	[SERVICE_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
	[SERVICE_TXT] = { .name = "txt", .type = BLOBMSG_TYPE_ARRAY },
};

static const struct uci_blob_param_list service_attr_list = {
	.n_params = __SERVICE_MAX,
	.params = service_policy,
};

static void
service_update(struct vlist_tree *tree, struct vlist_node *node_new,
	       struct vlist_node *node_old);

static struct blob_buf b;
static VLIST_TREE(services, avl_strcmp, service_update, false, false);
static char *sdudp =  "_services._dns-sd._udp.local";
static char *sdtcp =  "_services._dns-sd._tcp.local";

static const char *
service_name(const char *domain)
{
	static char buffer[256];

	snprintf(buffer, sizeof(buffer), "%s.%s", mdns_hostname, domain);

	return buffer;
}

static void
service_add_ptr(const char *host)
{
	int len = dn_comp(host, mdns_buf, sizeof(mdns_buf), NULL, NULL);

	if (len < 1)
		return;

	dns_add_answer(TYPE_PTR, mdns_buf, len);
}

static void
service_add_srv(struct service *s)
{
	struct dns_srv_data *sd = (struct dns_srv_data *) mdns_buf;
	int len = sizeof(*sd);

	len += dn_comp(mdns_hostname_local, mdns_buf + len, sizeof(mdns_buf) - len, NULL, NULL);
	if (len <= sizeof(*sd))
		return;

	sd->port = cpu_to_be16(s->port);
	dns_add_answer(TYPE_SRV, mdns_buf, len);
}

#define TOUT_LOOKUP	60

static int
service_timeout(struct service *s)
{
	time_t t = time(NULL);

	if (t - s->t <= TOUT_LOOKUP)
		return 0;

	s->t = t;

	return 1;
}

void
service_reply_a(struct interface *iface, int type)
{
	if (type != TYPE_A)
		return;

	dns_init_answer();
	dns_add_answer(TYPE_A, (uint8_t *) &iface->v4_addr.s_addr, 4);
	dns_send_answer(iface, mdns_hostname_local);
}

void
service_reply(struct interface *iface, const char *match)
{
	struct service *s;

	vlist_for_each_element(&services, s, node) {
		const char *host = service_name(s->service);
		char *service = strstr(host, "._");

		if (!s->active || !service || !service_timeout(s))
			continue;

		service++;

		if (match && strcmp(match, s->service))
			continue;

		dns_init_answer();
		service_add_ptr(service_name(s->service));
		dns_send_answer(iface, service);

		dns_init_answer();
		service_add_srv(s);
		if (s->txt && s->txt_len)
			dns_add_answer(TYPE_TXT, (uint8_t *) s->txt, s->txt_len);
		dns_send_answer(iface, host);
	}

	if (match)
		return;

	service_reply_a(iface, TYPE_A);
}

void
service_announce_services(struct interface *iface, const char *service)
{
	struct service *s;
	int tcp = 1;

	if (!strcmp(service, sdudp))
		tcp = 0;
	else if (strcmp(service, sdtcp))
		return;

	vlist_for_each_element(&services, s, node) {
		if (!strstr(s->service, "._tcp") && tcp)
			continue;
		if (!strstr(s->service, "._udp") && !tcp)
			continue;
		s->t = 0;
		dns_init_answer();
		service_add_ptr(s->service);
		if (tcp)
			dns_send_answer(iface, sdtcp);
		else
			dns_send_answer(iface, sdudp);
		service_reply(iface, s->service);
	}
}

void
service_announce(struct interface *iface)
{
	service_announce_services(iface, sdudp);
	service_announce_services(iface, sdtcp);
}

static void
service_update(struct vlist_tree *tree, struct vlist_node *node_new,
	       struct vlist_node *node_old)
{
	struct service *s;

	if (!node_old)
		return;

	s = container_of(node_old, struct service, node);
	free(s);
}

static void
service_load(char *path)
{
	struct blob_attr *txt, *cur, *_tb[__SERVICE_MAX];
	int rem, i;
	glob_t gl;

	if (glob(path, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl))
		return;

	for (i = 0; i < gl.gl_pathc; i++) {
	        blob_buf_init(&b, 0);

		if (!blobmsg_add_json_from_file(&b, gl.gl_pathv[i]))
			continue;
		blob_for_each_attr(cur, b.head, rem) {
			struct service *s;
			char *d_service, *d_daemon;
			uint8_t *d_txt;
			int rem2;
			int txt_len = 0;

			blobmsg_parse(service_policy, ARRAY_SIZE(service_policy),
				_tb, blobmsg_data(cur), blobmsg_data_len(cur));
			if (!_tb[SERVICE_PORT] || !_tb[SERVICE_TXT])
				continue;

			blobmsg_for_each_attr(txt, _tb[SERVICE_TXT], rem2)
				txt_len += 1 + strlen(blobmsg_get_string(txt));

			s = calloc_a(sizeof(*s),
				&d_daemon, strlen(gl.gl_pathv[i]) + 1,
				&d_service, strlen(blobmsg_name(cur)) + 1,
				&d_txt, txt_len);
			if (!s)
				continue;

			s->port = blobmsg_get_u32(_tb[SERVICE_PORT]);
			s->service = strcpy(d_service, blobmsg_name(cur));
			s->daemon = strcpy(d_daemon, gl.gl_pathv[i]);
			s->active = 1;
			s->t = 0;
			s->txt_len = txt_len;
			s->txt = d_txt;

			blobmsg_for_each_attr(txt, _tb[SERVICE_TXT], rem2) {
				int len = strlen(blobmsg_get_string(txt));
				if (!len)
					continue;
				if (len > 0xff)
					len = 0xff;
				*d_txt = len;
				d_txt++;
				memcpy(d_txt, blobmsg_get_string(txt), len);
				d_txt += len;
			}

			vlist_add(&services, &s->node, s->service);
		}
	}
}

void
service_init(void)
{
	get_hostname();

	vlist_update(&services);
	service_load("/tmp/run/mdnsd/*");
	vlist_flush(&services);
}

void
service_cleanup(void)
{
	vlist_flush(&services);
	blob_buf_free(&b);
}
