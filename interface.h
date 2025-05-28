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

#define SOCKTYPE_BIT_IPV6	(1 << 1)
#define SOCKTYPE_BIT_UNICAST (1 << 0)

enum umdns_socket_type {
	SOCK_MC_IPV4 = 0,
	SOCK_UC_IPV4 = SOCKTYPE_BIT_UNICAST,
	SOCK_MC_IPV6 = SOCKTYPE_BIT_IPV6,
	SOCK_UC_IPV6 = SOCKTYPE_BIT_IPV6 | SOCKTYPE_BIT_UNICAST,
};

struct interface_addr_list {
	union {
		struct {
			struct in_addr addr, mask;
		} *v4;
		struct {
			struct in6_addr addr, mask;
		} *v6;
	};
	int n_addr;
};

struct interface {
	struct vlist_node node;

	const char *name;
	enum umdns_socket_type type;
	bool need_multicast;
	int ifindex;

	struct interface_addr_list addrs;

	struct uloop_timeout announce_timer;
	int announce_state;
};

static inline bool interface_multicast(struct interface *iface)
{
	return !(iface->type & SOCKTYPE_BIT_UNICAST);
}

static inline bool interface_ipv6(struct interface *iface)
{
	return !!(iface->type & SOCKTYPE_BIT_IPV6);
}

int interface_add(const char *name);
int interface_init(void);
void interface_shutdown(void);
int interface_send_packet(struct interface *iface, struct sockaddr *to, struct iovec *iov, int iov_len);
struct interface* interface_get(const char *name, enum umdns_socket_type type);

#endif
