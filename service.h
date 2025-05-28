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

#ifndef _SERVICE_H__
#define _SERVICE_H__

#include <libubox/vlist.h>
#include <libubox/avl-cmp.h>

struct service {
	struct vlist_node node;

	time_t t;

	const char *id;
	const char *instance;
	const char *service;
	const char *hostname;
	const uint8_t *txt;
	int txt_len;
	int port;
	int active;
};

struct hostname {
	struct vlist_node node;

	const char *hostname;
};
extern struct vlist_tree hostnames;
extern struct vlist_tree announced_services;

extern void service_init(int announce);
extern void service_cleanup(void);
extern void service_reply(struct interface *iface, struct sockaddr *to, const char *instance, const char *service_domain, int ttl, int force);
extern void service_announce_services(struct interface *iface, struct sockaddr *to, int ttl);
extern void service_update(struct vlist_tree *tree, struct vlist_node *node_new, struct vlist_node *node_old);

#endif
