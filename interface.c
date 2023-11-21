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

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>
#include <libubox/utils.h>
#include "cache.h"
#include "interface.h"
#include "util.h"
#include "dns.h"
#include "announce.h"
#include "service.h"

static struct uloop_fd ufd[] = {
	[SOCK_UC_IPV4] = { .fd = -1 },
	[SOCK_UC_IPV6] = { .fd = -1 },
	[SOCK_MC_IPV4] = { .fd = -1 },
	[SOCK_MC_IPV6] = { .fd = -1 },
};

static int
interface_send_packet4(struct interface *iface, struct sockaddr_in *to, struct iovec *iov, int iov_len)
{
	static size_t cmsg_data[( CMSG_SPACE(sizeof(struct in_pktinfo)) / sizeof(size_t)) + 1];
	static struct sockaddr_in a = {};
	static struct msghdr m = {
		.msg_name = (struct sockaddr *) &a,
		.msg_namelen = sizeof(a),
		.msg_control = cmsg_data,
		.msg_controllen = CMSG_LEN(sizeof(struct in_pktinfo)),
	};
	struct in_pktinfo *pkti;
	struct cmsghdr *cmsg;
	int fd;

	a.sin_family = AF_INET;
	a.sin_port = htons(MCAST_PORT);
	m.msg_iov = iov;
	m.msg_iovlen = iov_len;

	memset(cmsg_data, 0, sizeof(cmsg_data));
	cmsg = CMSG_FIRSTHDR(&m);
	cmsg->cmsg_len = m.msg_controllen;
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;

	pkti = (struct in_pktinfo*) CMSG_DATA(cmsg);
	pkti->ipi_ifindex = iface->ifindex;

	fd = ufd[iface->type].fd;
	if (interface_multicast(iface)) {
		a.sin_addr.s_addr = inet_addr(MCAST_ADDR);
		if (to)
			fprintf(stderr, "Ignoring IPv4 address for multicast interface\n");
	} else {
		a.sin_addr.s_addr = to->sin_addr.s_addr;
	}

	return sendmsg(fd, &m, 0);
}

static int
interface_send_packet6(struct interface *iface, struct sockaddr_in6 *to, struct iovec *iov, int iov_len)
{
	static size_t cmsg_data[( CMSG_SPACE(sizeof(struct in6_pktinfo)) / sizeof(size_t)) + 1];
	static struct sockaddr_in6 a = {};
	static struct msghdr m = {
		.msg_name = (struct sockaddr *) &a,
		.msg_namelen = sizeof(a),
		.msg_control = cmsg_data,
		.msg_controllen = CMSG_LEN(sizeof(struct in6_pktinfo)),
	};
	struct in6_pktinfo *pkti;
	struct cmsghdr *cmsg;
	int fd;

	a.sin6_family = AF_INET6;
	a.sin6_port = htons(MCAST_PORT);
	a.sin6_scope_id = iface->ifindex;
	m.msg_iov = iov;
	m.msg_iovlen = iov_len;

	memset(cmsg_data, 0, sizeof(cmsg_data));
	cmsg = CMSG_FIRSTHDR(&m);
	cmsg->cmsg_len = m.msg_controllen;
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;

	pkti = (struct in6_pktinfo*) CMSG_DATA(cmsg);
	pkti->ipi6_ifindex = iface->ifindex;

	fd = ufd[iface->type].fd;
	if (interface_multicast(iface)) {
		inet_pton(AF_INET6, MCAST_ADDR6, &a.sin6_addr);
		if (to)
			fprintf(stderr, "Ignoring IPv6 address for multicast interface\n");
	} else {
		a.sin6_addr = to->sin6_addr;
	}

	return sendmsg(fd, &m, 0);
}

int
interface_send_packet(struct interface *iface, struct sockaddr *to, struct iovec *iov, int iov_len)
{
	if (!interface_multicast(iface) && !to) {
		fprintf(stderr, "No IP address specified for unicast interface\n");
		errno = EINVAL;
		return -1;
	}

	if (debug > 1) {
		fprintf(stderr, "TX ipv%d: %s\n", interface_ipv6(iface) ? 6 : 4, iface->name);
		fprintf(stderr, "  multicast: %d\n", interface_multicast(iface));
	}

	if (interface_ipv6(iface))
		return interface_send_packet6(iface, (struct sockaddr_in6 *)to, iov, iov_len);

	return interface_send_packet4(iface, (struct sockaddr_in *)to, iov, iov_len);
}

static struct interface *interface_lookup(unsigned int ifindex, enum umdns_socket_type type)
{
	struct interface *iface;

	vlist_for_each_element(&interfaces, iface, node)
		if (iface->ifindex == ifindex && iface->type == type)
			return iface;

	return NULL;
}

static void interface_free(struct interface *iface)
{
	announce_free(iface);
	free(iface->addrs.v4);
	free(iface);
}

static int
interface_valid_src(void *ip1, void *mask, void *ip2, int len)
{
	uint8_t *i1 = ip1;
	uint8_t *i2 = ip2;
	uint8_t *m = mask;
	int i;

	if (cfg_no_subnet)
		return 0;

	for (i = 0; i < len; i++, i1++, i2++, m++) {
		if ((*i1 & *m) != (*i2 & *m))
			return -1;
	}

	return 0;
}

static void
read_socket4(struct uloop_fd *u, unsigned int events)
{
	enum umdns_socket_type type = (enum umdns_socket_type)(u - ufd);
	struct interface *iface;
	static uint8_t buffer[8 * 1024];
	struct iovec iov[1];
	char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int)) + 1];
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	socklen_t len;
	struct sockaddr_in from;
	int flags = 0;
	uint8_t ttl = 0;
	struct in_pktinfo *inp = NULL;
	bool valid_src = false;

	if (u->eof) {
		uloop_end();
		return;
	}

	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr *) &from;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsg;
	msg.msg_controllen = sizeof(cmsg);

	len = recvmsg(u->fd, &msg, flags);
	if (len == -1) {
		perror("read failed");
		return;
	}
	for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
		void *c = CMSG_DATA(cmsgptr);

		switch (cmsgptr->cmsg_type) {
		case IP_PKTINFO:
			inp = ((struct in_pktinfo *) c);
			break;

		case IP_TTL:
			ttl = (uint8_t) *((int *) c);
			break;

		default:
			fprintf(stderr, "unknown cmsg %x\n", cmsgptr->cmsg_type);
			return;
		}
	}

	if (!inp)
		return;

	iface = interface_lookup(inp->ipi_ifindex, type);
	if (!iface)
		return;

	if (debug > 1) {
		char buf[256];

		fprintf(stderr, "RX ipv4: %s\n", iface->name);
		fprintf(stderr, "  multicast: %d\n", interface_multicast(iface));
		inet_ntop(AF_INET, &from.sin_addr, buf, 256);
		fprintf(stderr, "  src %s:%d\n", buf, ntohs(from.sin_port));
		inet_ntop(AF_INET, &inp->ipi_spec_dst, buf, 256);
		fprintf(stderr, "  dst %s\n", buf);
		inet_ntop(AF_INET, &inp->ipi_addr, buf, 256);
		fprintf(stderr, "  real %s\n", buf);
		fprintf(stderr, "  ttl %u\n", ttl);
	}

	for (size_t i = 0; i < iface->addrs.n_addr; i++) {
		if (!interface_valid_src((void *)&iface->addrs.v4[i].addr,
					 (void *)&iface->addrs.v4[i].mask,
					 (void *) &from.sin_addr, 4)) {
			valid_src = true;
			break;
		}
	}

	if (!valid_src)
		return;

	dns_handle_packet(iface, (struct sockaddr *) &from, ntohs(from.sin_port), buffer, len);
}

static void
read_socket6(struct uloop_fd *u, unsigned int events)
{
	enum umdns_socket_type type = (enum umdns_socket_type)(u - ufd);
	struct interface *iface;
	static uint8_t buffer[8 * 1024];
	struct iovec iov[1];
	char cmsg6[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int)) + 1];
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	socklen_t len;
	struct sockaddr_in6 from;
	int flags = 0;
	int ttl = 0;
	struct in6_pktinfo *inp = NULL;
	bool valid_src = false;

	if (u->eof) {
		uloop_end();
		return;
	}

	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr *) &from;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsg6;
	msg.msg_controllen = sizeof(cmsg6);

	len = recvmsg(u->fd, &msg, flags);
	if (len == -1) {
		perror("read failed");
		return;
	}
	for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
		void *c = CMSG_DATA(cmsgptr);

		switch (cmsgptr->cmsg_type) {
		case IPV6_PKTINFO:
			inp = ((struct in6_pktinfo *) c);
			break;

		case IPV6_HOPLIMIT:
			ttl = (uint8_t) *((int *) c);
			break;

		default:
			fprintf(stderr, "unknown cmsg %x\n", cmsgptr->cmsg_type);
			return;
		}
	}

	if (!inp)
		return;

	iface = interface_lookup(inp->ipi6_ifindex, type);
	if (!iface)
		return;

	if (debug > 1) {
		char buf[256];

		fprintf(stderr, "RX ipv6: %s\n", iface->name);
		fprintf(stderr, "  multicast: %d\n", interface_multicast(iface));
		inet_ntop(AF_INET6, &from.sin6_addr, buf, 256);
		fprintf(stderr, "  src %s:%d\n", buf, ntohs(from.sin6_port));
		inet_ntop(AF_INET6, &inp->ipi6_addr, buf, 256);
		fprintf(stderr, "  dst %s\n", buf);
		fprintf(stderr, "  ttl %u\n", ttl);
	}

	for (size_t i = 0; i < iface->addrs.n_addr; i++) {
		if (!interface_valid_src((void *)&iface->addrs.v6[i].addr,
					 (void *)&iface->addrs.v6[i].mask,
					 (void *)&from.sin6_addr, 6)) {
			valid_src = true;
			break;
		}
	}

	if (!valid_src)
		return;

	dns_handle_packet(iface, (struct sockaddr *) &from, ntohs(from.sin6_port), buffer, len);
}

static int
interface_mcast_setup4(struct interface *iface)
{
	struct ip_mreqn mreq;
	struct sockaddr_in sa = {};
	int fd = ufd[SOCK_MC_IPV4].fd;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(MCAST_PORT);
	inet_pton(AF_INET, MCAST_ADDR, &sa.sin_addr);

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr = sa.sin_addr;
	mreq.imr_ifindex = iface->ifindex;
	mreq.imr_address.s_addr = iface->addrs.v4[0].addr.s_addr;

	/* Some network drivers have issues with dropping membership of
	 * mcast groups when the iface is down, but don't allow rejoining
	 * when it comes back up. This is an ugly workaround
	 * -- this was copied from avahi --
	 */
	setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
	setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

	return 0;
}

static int
interface_mcast_setup6(struct interface *iface)
{
	struct ipv6_mreq mreq;
	struct sockaddr_in6 sa = {};
	int fd = ufd[SOCK_MC_IPV6].fd;

	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(MCAST_PORT);
	inet_pton(AF_INET6, MCAST_ADDR6, &sa.sin6_addr);

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_multiaddr = sa.sin6_addr;
	mreq.ipv6mr_interface = iface->ifindex;

	setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq));
	setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

	return 0;
}

static void interface_start(struct interface *iface)
{
	if (iface->type & SOCKTYPE_BIT_UNICAST)
		return;

	if (iface->type & SOCKTYPE_BIT_IPV6)
		interface_mcast_setup6(iface);
	else
		interface_mcast_setup4(iface);

	dns_send_question(iface, NULL, C_DNS_SD, TYPE_PTR, 0);
	announce_init(iface);
}

static bool
iface_equal(struct interface *if_old, struct interface *if_new)
{
	size_t addr_size;

	if (if_old->ifindex != if_new->ifindex ||
	    if_old->addrs.n_addr != if_new->addrs.n_addr)
		return false;

	if (if_old->type & SOCKTYPE_BIT_IPV6)
		addr_size = sizeof(*if_old->addrs.v6);
	else
		addr_size = sizeof(*if_old->addrs.v4);
	addr_size *= if_old->addrs.n_addr;
	if (memcmp(if_old->addrs.v4, if_new->addrs.v4, addr_size) != 0)
		return false;

	return true;
}

static void
iface_update_cb(struct vlist_tree *tree, struct vlist_node *node_new,
		struct vlist_node *node_old)
{
	struct interface *if_old = container_of_safe(node_old, struct interface, node);
	struct interface *if_new = container_of_safe(node_new, struct interface, node);

	if (if_old && if_new) {
		if (!iface_equal(if_old, if_new))
			cache_cleanup(if_old);
		free(if_old->addrs.v4);
		if_old->addrs = if_new->addrs;
		if_old->ifindex = if_new->ifindex;
		free(if_new);
		return;
	}

	if (if_old)
		interface_free(if_old);

	if (if_new)
		interface_start(if_new);
}

static int interface_init_socket(enum umdns_socket_type type)
{
	struct sockaddr_in6 local6 = {
		.sin6_family = AF_INET6
	};
	struct sockaddr_in local = {
		.sin_family = AF_INET
	};
	uint8_t ttl = 255;
	int ittl = 255;
	int yes = 1;
	int no = 0;
	int fd;
	int af = (type & SOCKTYPE_BIT_IPV6) ? AF_INET6 : AF_INET;

	if (ufd[type].fd >= 0)
		return 0;

	ufd[type].fd = fd = socket(af, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

	switch (type) {
	case SOCK_UC_IPV4:
	case SOCK_UC_IPV6:
		break;
	case SOCK_MC_IPV4:
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
		setsockopt(fd, IPPROTO_IP, IP_TTL, &ittl, sizeof(ittl));
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no));
		local.sin_port = htons(MCAST_PORT);
		break;
	case SOCK_MC_IPV6:
		setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
		setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &no, sizeof(no));
		local6.sin6_port = htons(MCAST_PORT);
		break;
	}

	if (type & SOCKTYPE_BIT_IPV6) {
		ufd[type].cb = read_socket6;
		if (bind(fd, (struct sockaddr *)&local6, sizeof(local6)) < 0)
			goto error;

		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes, sizeof(yes));
	} else {
		ufd[type].cb = read_socket4;
		if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
			goto error;

		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes));
	}

	uloop_fd_add(&ufd[type], ULOOP_READ);

	return 0;

error:
	close(ufd[type].fd);
	return -1;
}

static void
__interface_add(const char *name, enum umdns_socket_type type,
				struct interface_addr_list *list)
{
	struct interface *iface;
	unsigned int ifindex;
	char *id_buf;

	if (interface_init_socket(type))
		goto error;

	ifindex = if_nametoindex(name);
	if (!ifindex)
		goto error;

	iface = calloc_a(sizeof(*iface),
		&id_buf, strlen(name) + 3);

	sprintf(id_buf, "%d_%s", type, name);
	iface->name = id_buf + 2;
	iface->ifindex = ifindex;
	iface->type = type;
	iface->addrs = *list;

	vlist_add(&interfaces, &iface->node, id_buf);
	return;

error:
	free(list->v4);
}

int interface_add(const char *name)
{
	struct ifaddrs *ifap, *ifa;
	struct interface_addr_list addr4 = {}, addr6 = {};

	getifaddrs(&ifap);

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, name))
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sin;

			if (cfg_proto && (cfg_proto != 4))
				continue;

			addr4.v4 = realloc(addr4.v4, (addr4.n_addr + 1) * sizeof(*addr4.v4));
			sin = (struct sockaddr_in *) ifa->ifa_addr;
			addr4.v4[addr4.n_addr].addr = sin->sin_addr;
			sin = (struct sockaddr_in *) ifa->ifa_netmask;
			addr4.v4[addr4.n_addr++].mask = sin->sin_addr;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6) {
			uint8_t ll_prefix[] = {0xfe, 0x80 };
			struct sockaddr_in6 *sin6;

			if (cfg_proto && (cfg_proto != 6))
				continue;

			sin6 = (struct sockaddr_in6 *) ifa->ifa_addr;
			if (memcmp(&sin6->sin6_addr, &ll_prefix, 2))
				continue;

			addr6.v6 = realloc(addr6.v6, (addr6.n_addr + 1) * sizeof(*addr6.v6));
			sin6 = (struct sockaddr_in6 *) ifa->ifa_addr;
			addr6.v6[addr6.n_addr].addr = sin6->sin6_addr;
			sin6 = (struct sockaddr_in6 *) ifa->ifa_netmask;
			addr6.v6[addr6.n_addr++].mask = sin6->sin6_addr;
		}
	}

	freeifaddrs(ifap);

	if (addr4.n_addr) {
		size_t addr_size = addr4.n_addr * sizeof(*addr4.v4);
		void *addr_dup = malloc(addr_size);

		memcpy(addr_dup, addr4.v4, addr_size);
		__interface_add(name, SOCK_UC_IPV4, &addr4);
		addr4.v4 = addr_dup;
		__interface_add(name, SOCK_MC_IPV4, &addr4);
	}

	if (addr6.n_addr) {
		size_t addr_size = addr6.n_addr * sizeof(*addr6.v6);
		void *addr_dup = malloc(addr_size);

		memcpy(addr_dup, addr6.v6, addr_size);
		__interface_add(name, SOCK_UC_IPV6, &addr6);
		addr6.v6 = addr_dup;
		__interface_add(name, SOCK_MC_IPV6, &addr6);
	}

	return !addr4.n_addr && !addr6.n_addr;
}

void interface_shutdown(void)
{
	struct interface *iface;

	vlist_for_each_element(&interfaces, iface, node)
		if (interface_multicast(iface)) {
			dns_reply_a(iface, NULL, 0);
			service_announce_services(iface, NULL, 0);
		}

	for (size_t i = 0; i < ARRAY_SIZE(ufd); i++) {
		uloop_fd_delete(&ufd[i]);
		close(ufd[i].fd);
		ufd[i].fd = -1;
	}
}

struct interface *interface_get(const char *name, enum umdns_socket_type type)
{
	char id_buf[32];
	snprintf(id_buf, sizeof(id_buf), "%d_%s", type, name);
	struct interface *iface = vlist_find(&interfaces, id_buf, iface, node);
	return iface;
}

VLIST_TREE(interfaces, avl_strcmp, iface_update_cb, true, false);
