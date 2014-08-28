/*
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
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

#ifndef __MDNS_INTERFACE_H
#define __MDNS_INTERFACE_H

#include <sys/types.h>
#include <sys/uio.h>

#include <arpa/inet.h>

#include <libubox/uloop.h>
#include <libubox/vlist.h>

extern struct vlist_tree interfaces;

struct interface {
	struct vlist_node node;

	const char *name;
	char *id;
	struct uloop_fd fd;
	struct uloop_timeout reconnect;

	int v6;
	int ifindex;
	struct in_addr v4_addr;
	struct in6_addr v6_addr;

	struct uloop_timeout announce_timer;
	int announce_state;

	char *mcast_addr;
};

int interface_add(const char *name);
int interface_send_packet(struct interface *iface, struct iovec *iov, int iov_len);

#endif
