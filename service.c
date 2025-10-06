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
#include <inttypes.h>
#include <stdio.h>
#include <time.h>

#include <libubus.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

#include "ubus.h"
#include "dns.h"
#include "service.h"
#include "util.h"
#include "interface.h"
#include "announce.h"

enum {
	SERVICE_INSTANCE,
	SERVICE_SERVICE,
	SERVICE_PORT,
	SERVICE_TXT,
	SERVICE_HOSTNAME,
	__SERVICE_MAX,
};

static const struct blobmsg_policy service_policy[__SERVICE_MAX] = {
	[SERVICE_INSTANCE] = { .name = "instance", .type = BLOBMSG_TYPE_STRING },
	[SERVICE_SERVICE] = { .name = "service", .type = BLOBMSG_TYPE_STRING },
	[SERVICE_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
	[SERVICE_TXT] = { .name = "txt", .type = BLOBMSG_TYPE_ARRAY },
	[SERVICE_HOSTNAME] = { .name = "hostname", .type = BLOBMSG_TYPE_STRING },
};

static void
hostname_update(struct vlist_tree *tree, struct vlist_node *node_new,
		struct vlist_node *node_old);

static struct blob_buf b;
VLIST_TREE(announced_services, avl_strcmp, service_update, false, false);
VLIST_TREE(hostnames, avl_strcmp, hostname_update, false, false);
static int service_init_announce;

/**
 * service_instance_name - construct Service Instance Name as in RFC 6763
 *
 * RFC 6763 specifies Service Instance Names in the following way:
 *
 * Service Instance Name = <Instance> . <Service> . <Domain>
 *
 * @s: service to generate service instance name for
 */
static const char *
service_instance_name(struct service *s)
{
	static char buffer[256];

	snprintf(buffer, sizeof(buffer), "%s.%s", s->instance, s->service);

	return buffer;
}

static void
service_add_ptr(const char *name, const char *host, int ttl)
{
	int len = dn_comp(host, mdns_buf, sizeof(mdns_buf), NULL, NULL);

	if (len < 1)
		return;

	dns_packet_answer(name, TYPE_PTR, mdns_buf, len, ttl);
}

static void
service_add_srv(const char *name, struct service *s, int ttl)
{
	struct dns_srv_data *sd = (struct dns_srv_data *) mdns_buf;
	int len = sizeof(*sd);

	len += dn_comp(s->hostname, mdns_buf + len, sizeof(mdns_buf) - len, NULL, NULL);
	if (len <= sizeof(*sd))
		return;

	sd->port = cpu_to_be16(s->port);
	dns_packet_answer(name, TYPE_SRV, mdns_buf, len, ttl);
}

#define TOUT_LOOKUP	60

static time_t
service_timeout(struct service *s)
{
	time_t t = monotonic_time();

	if (t - s->t <= TOUT_LOOKUP) {
		DBG(2, "t=%" PRId64 ", s->t=%" PRId64 ", t - s->t = %" PRId64 "\n", (int64_t)t, (int64_t)s->t, (int64_t)(t - s->t));
		return 0;
	}

	return t;
}

static void
service_reply_single(struct interface *iface, struct sockaddr *to, struct service *s, int ttl, int force,
			bool append)
{
	const char *host = service_instance_name(s);
	char *service = strstr(host, "._");
	time_t t = service_timeout(s);

	if (!force && (!s->active || !service || !t))
		return;

	service++;

	s->t = t;

	if (!append)
		dns_packet_init();

	service_add_ptr(service, service_instance_name(s), ttl);
	service_add_srv(host, s, ttl);
	if (s->txt && s->txt_len)
		dns_packet_answer(host, TYPE_TXT, (uint8_t *) s->txt, s->txt_len, ttl);

	if (!append)
		dns_packet_send(iface, to, 0, 0);
}

void
service_reply(struct interface *iface, struct sockaddr *to, const char *instance, const char *service_domain, int ttl, int force,
		bool append)
{
	struct service *s;

	vlist_for_each_element(&announced_services, s, node) {
		if (instance && strcmp(s->instance, instance))
			continue;
		if (service_domain && strcmp(s->service, service_domain))
			continue;
		service_reply_single(iface, to, s, ttl, force, append);
	}
}

void
service_announce_services(struct interface *iface, struct sockaddr *to, int ttl, bool append)
{
	struct service *s;
	int count = 0;

	if (!append)
		dns_packet_init();

	vlist_for_each_element(&announced_services, s, node) {
		s->t = 0;
		if (ttl) {
			service_add_ptr(C_DNS_SD, s->service, ttl);
			count++;
		}
	}
	if (count)
		if (!append)
			dns_packet_send(iface, to, 0, 0);
}

void
service_update(struct vlist_tree *tree, struct vlist_node *node_new,
	       struct vlist_node *node_old)
{
	struct interface *iface;
	struct service *s;

	if (!node_old) {
		s = container_of(node_new, struct service, node);
		if (service_init_announce)
			vlist_for_each_element(&interfaces, iface, node) {
				s->t = 0;
				service_reply_single(iface, NULL, s, announce_ttl, 1, false);
			}
		return;
	}

	s = container_of(node_old, struct service, node);
	if (!node_new && service_init_announce)
		vlist_for_each_element(&interfaces, iface, node)
			service_reply_single(iface, NULL, s, 0, 1, false);
	free(s);
}

static void
hostname_update(struct vlist_tree *tree, struct vlist_node *node_new,
		struct vlist_node *node_old)
{
	struct interface *iface;
	struct hostname *h;

	if (!node_old) {
		h = container_of(node_new, struct hostname, node);
		vlist_for_each_element(&interfaces, iface, node)
			dns_reply_a(iface, NULL, announce_ttl, h->hostname, false);
		return;
	}

	h = container_of(node_old, struct hostname, node);
	if (!node_new)
		vlist_for_each_element(&interfaces, iface, node)
			dns_reply_a(iface, NULL, 0, h->hostname, false);

	free(h);
}

static void
service_load_hostname(struct blob_attr *b)
{
	struct hostname *h;
	char *hostname, *d_hostname;

	hostname = blobmsg_get_string(b);
	h = calloc_a(sizeof(*h), &d_hostname, strlen(hostname) + 1);
	if (!h)
		return;

	h->hostname = strcpy(d_hostname, hostname);

	vlist_add(&hostnames, &h->node, h->hostname);
}

static void
service_load_blob(struct blob_attr *b)
{
	struct blob_attr *txt, *_tb[__SERVICE_MAX];
	struct service *s;
	char *d_instance, *d_hostname, *d_service, *d_id;
	uint8_t *d_txt;
	int rem2;
	int txt_len = 0;
	unsigned int n;

	blobmsg_parse(service_policy, ARRAY_SIZE(service_policy),
		_tb, blobmsg_data(b), blobmsg_data_len(b));

	if (_tb[SERVICE_HOSTNAME])
		service_load_hostname(_tb[SERVICE_HOSTNAME]);

	if (!_tb[SERVICE_PORT] || !_tb[SERVICE_SERVICE])
		return;

	if (_tb[SERVICE_TXT])
		blobmsg_for_each_attr(txt, _tb[SERVICE_TXT], rem2)
			txt_len += 1 + strlen(blobmsg_get_string(txt));

	n = strlen(blobmsg_name(b));
	s = calloc_a(sizeof(*s),
		&d_id, n + 1,
		&d_hostname, _tb[SERVICE_HOSTNAME] ? strlen(blobmsg_get_string(_tb[SERVICE_HOSTNAME])) + 1 : 0,
		&d_instance, _tb[SERVICE_INSTANCE] ? strlen(blobmsg_get_string(_tb[SERVICE_INSTANCE])) + 1 : 0,
		&d_service, strlen(blobmsg_get_string(_tb[SERVICE_SERVICE])) + 1,
		&d_txt, txt_len);
	if (!s)
		return;

	s->port = blobmsg_get_u32(_tb[SERVICE_PORT]);
	s->id = strncpy(d_id, blobmsg_name(b), n);
	if (_tb[SERVICE_HOSTNAME])
		s->hostname = strcpy(d_hostname, blobmsg_get_string(_tb[SERVICE_HOSTNAME]));
	else
		s->hostname = mdns_hostname_local;
	if (_tb[SERVICE_INSTANCE])
		s->instance = strcpy(d_instance, blobmsg_get_string(_tb[SERVICE_INSTANCE]));
	else
		s->instance = umdns_host_label;
	s->service = strcpy(d_service, blobmsg_get_string(_tb[SERVICE_SERVICE]));
	s->active = 1;
	s->t = 0;
	s->txt_len = txt_len;
	s->txt = d_txt;

	if (_tb[SERVICE_TXT])
		blobmsg_for_each_attr(txt, _tb[SERVICE_TXT], rem2) {
			int len = strlen(blobmsg_get_string(txt));
			if (!len)
				return;
			if (len > 0xff)
				len = 0xff;
			*d_txt = len;
			d_txt++;
			memcpy(d_txt, blobmsg_get_string(txt), len);
			d_txt += len;
		}

	vlist_add(&announced_services, &s->node, s->id);
}

static void
service_load(char *path)
{
	struct blob_attr *cur;
	glob_t gl;
	int i, rem;

	if (glob(path, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl))
		return;

	for (i = 0; i < gl.gl_pathc; i++) {
	        blob_buf_init(&b, 0);
		if (blobmsg_add_json_from_file(&b, gl.gl_pathv[i])) {
			blob_for_each_attr(cur, b.head, rem)
				service_load_blob(cur);
		} else {
			fprintf(stderr, "Error reading %s JSON\n", gl.gl_pathv[i]);
		}
	}
	globfree(&gl);
}

static void
service_init_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;

	get_hostname();

	vlist_update(&announced_services);
	vlist_update(&hostnames);
	service_load("/etc/umdns/*");

	blob_for_each_attr(cur, msg, rem) {
		struct blob_attr *cur2;
		int rem2;

		blobmsg_for_each_attr(cur2, cur, rem2) {
			struct blob_attr *cur3;
			int rem3;

			if (strcmp(blobmsg_name(cur2), "instances"))
				continue;

			blobmsg_for_each_attr(cur3, cur2, rem3) {
				struct blob_attr *cur4;
				int rem4;
				int running = 0;

				blobmsg_for_each_attr(cur4, cur3, rem4) {
					const char *name = blobmsg_name(cur4);

					if (!strcmp(name, "running")) {
						running = blobmsg_get_bool(cur4);
					} else if (running && !strcmp(name, "data")) {
						struct blob_attr *cur5;
						int rem5;

						blobmsg_for_each_attr(cur5, cur4, rem5) {
							struct blob_attr *cur6;
							int rem6;

							if (strcmp(blobmsg_name(cur5), "mdns"))
								continue;

							blobmsg_for_each_attr(cur6, cur5, rem6)
								service_load_blob(cur6);
						}
						break;
					}
				}
			}
		}
	}
	vlist_flush(&announced_services);
	vlist_flush(&hostnames);
}

void
service_init(int announce)
{
	get_hostname();

	service_init_announce = announce;
	ubus_service_list(service_init_cb);
}

void
service_cleanup(void)
{
	vlist_flush(&announced_services);
	blob_buf_free(&b);
}
