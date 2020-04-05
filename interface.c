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

static int
interface_send_packet4(struct interface *iface, struct sockaddr_in *to, struct iovec *iov, int iov_len)
{
	static size_t cmsg_data[( CMSG_SPACE(sizeof(struct in_pktinfo)) / sizeof(size_t)) + 1];
	static struct sockaddr_in a;
	static struct msghdr m = {
		.msg_name = (struct sockaddr *) &a,
		.msg_namelen = sizeof(a),
		.msg_control = cmsg_data,
		.msg_controllen = CMSG_LEN(sizeof(struct in_pktinfo)),
	};
	struct in_pktinfo *pkti;
	struct cmsghdr *cmsg;
	int fd = iface->fd.fd;

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

	if (iface->multicast) {
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
	static struct sockaddr_in6 a;
	static struct msghdr m = {
		.msg_name = (struct sockaddr *) &a,
		.msg_namelen = sizeof(a),
		.msg_control = cmsg_data,
		.msg_controllen = CMSG_LEN(sizeof(struct in6_pktinfo)),
	};
	struct in6_pktinfo *pkti;
	struct cmsghdr *cmsg;
	int fd = iface->fd.fd;

	a.sin6_family = AF_INET6;
	a.sin6_port = htons(MCAST_PORT);
	m.msg_iov = iov;
	m.msg_iovlen = iov_len;

	memset(cmsg_data, 0, sizeof(cmsg_data));
	cmsg = CMSG_FIRSTHDR(&m);
	cmsg->cmsg_len = m.msg_controllen;
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;

	pkti = (struct in6_pktinfo*) CMSG_DATA(cmsg);
	pkti->ipi6_ifindex = iface->ifindex;

	if (iface->multicast) {
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
	if (!iface->multicast && !to) {
		fprintf(stderr, "No IP address specified for unicast interface\n");
		errno = EINVAL;
		return -1;
	}

	if (debug > 1) {
		fprintf(stderr, "TX ipv%d: %s\n", iface->v6 * 2 + 4, iface->name);
		fprintf(stderr, "  multicast: %d\n", iface->multicast);
	}

	if (iface->v6)
		return interface_send_packet6(iface, (struct sockaddr_in6 *)to, iov, iov_len);

	return interface_send_packet4(iface, (struct sockaddr_in *)to, iov, iov_len);
}

static void interface_close(struct interface *iface)
{
	if (iface->fd.fd < 0)
		return;

	announce_free(iface);
	uloop_fd_delete(&iface->fd);
	close(iface->fd.fd);
	iface->fd.fd = -1;
}

static void interface_free(struct interface *iface)
{
	uloop_timeout_cancel(&iface->reconnect);
	interface_close(iface);
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
	struct interface *iface = container_of(u, struct interface, fd);
	static uint8_t buffer[8 * 1024];
	struct iovec iov[1];
	char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int)) + 1];
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	socklen_t len;
	struct sockaddr_in from;
	int flags = 0, ifindex = -1;
	uint8_t ttl = 0;
	struct in_pktinfo *inp = NULL;

	if (u->eof) {
		interface_close(iface);
		uloop_timeout_set(&iface->reconnect, 1000);
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

	if (debug > 1) {
		char buf[256];

		fprintf(stderr, "RX ipv4: %s\n", iface->name);
		fprintf(stderr, "  multicast: %d\n", iface->multicast);
		inet_ntop(AF_INET, &from.sin_addr, buf, 256);
		fprintf(stderr, "  src %s:%d\n", buf, ntohs(from.sin_port));
		inet_ntop(AF_INET, &inp->ipi_spec_dst, buf, 256);
		fprintf(stderr, "  dst %s\n", buf);
		inet_ntop(AF_INET, &inp->ipi_addr, buf, 256);
		fprintf(stderr, "  real %s\n", buf);
		fprintf(stderr, "  ttl %u\n", ttl);
	}

	if (inp->ipi_ifindex != iface->ifindex)
		fprintf(stderr, "invalid iface index %d != %d\n", ifindex, iface->ifindex);
	else if (!interface_valid_src((void *) &iface->v4_addr, (void *) &iface->v4_netmask, (void *) &from.sin_addr, 4))
		dns_handle_packet(iface, (struct sockaddr *) &from, ntohs(from.sin_port), buffer, len);
}

static void
read_socket6(struct uloop_fd *u, unsigned int events)
{
	struct interface *iface = container_of(u, struct interface, fd);
	static uint8_t buffer[8 * 1024];
	struct iovec iov[1];
	char cmsg6[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int)) + 1];
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	socklen_t len;
	struct sockaddr_in6 from;
	int flags = 0, ifindex = -1;
	int ttl = 0;
	struct in6_pktinfo *inp = NULL;

	if (u->eof) {
		interface_close(iface);
		uloop_timeout_set(&iface->reconnect, 1000);
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

	if (debug > 1) {
		char buf[256];

		fprintf(stderr, "RX ipv6: %s\n", iface->name);
		fprintf(stderr, "  multicast: %d\n", iface->multicast);
		inet_ntop(AF_INET6, &from.sin6_addr, buf, 256);
		fprintf(stderr, "  src %s:%d\n", buf, ntohs(from.sin6_port));
		inet_ntop(AF_INET6, &inp->ipi6_addr, buf, 256);
		fprintf(stderr, "  dst %s\n", buf);
		fprintf(stderr, "  ttl %u\n", ttl);
	}

	if (inp->ipi6_ifindex != iface->ifindex)
		fprintf(stderr, "invalid iface index %d != %d\n", ifindex, iface->ifindex);
	else if (!interface_valid_src((void *) &iface->v6_addr, (void *) &iface->v6_netmask, (void *) &from.sin6_addr, 16))
		dns_handle_packet(iface, (struct sockaddr *) &from, ntohs(from.sin6_port), buffer, len);
}

static int
interface_mcast_setup4(struct interface *iface)
{
	struct ip_mreqn mreq;
	uint8_t ttl = 255;
	int no = 0;
	struct sockaddr_in sa = { 0 };
	int fd = iface->fd.fd;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(MCAST_PORT);
	inet_pton(AF_INET, MCAST_ADDR, &sa.sin_addr);

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_address.s_addr = iface->v4_addr.s_addr;
	mreq.imr_multiaddr = sa.sin_addr;
	mreq.imr_ifindex = iface->ifindex;

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
		fprintf(stderr, "ioctl failed: IP_MULTICAST_TTL\n");

	/* Some network drivers have issues with dropping membership of
	 * mcast groups when the iface is down, but don't allow rejoining
	 * when it comes back up. This is an ugly workaround
	 * -- this was copied from avahi --
	 */
	setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		fprintf(stderr, "failed to join multicast group: %m\n");
		close(fd);
		fd = -1;
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no)) < 0)
		fprintf(stderr, "ioctl failed: IP_MULTICAST_LOOP\n");

	return 0;
}

static int
interface_socket_setup6(struct interface *iface)
{
	struct ipv6_mreq mreq;
	int ttl = 255;
	int no = 0;
	struct sockaddr_in6 sa = { 0 };
	int fd = iface->fd.fd;

	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(MCAST_PORT);
	inet_pton(AF_INET6, MCAST_ADDR6, &sa.sin6_addr);

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_multiaddr = sa.sin6_addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0)
		fprintf(stderr, "ioctl failed: IPV6_MULTICAST_HOPS\n");

	setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq));
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		fprintf(stderr, "failed to join multicast group: %m\n");
		close(fd);
		fd = -1;
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &no, sizeof(no)) < 0)
		fprintf(stderr, "ioctl failed: IPV6_MULTICAST_LOOP\n");

	return 0;
}

static void
reconnect_socket4(struct uloop_timeout *timeout)
{
	struct interface *iface = container_of(timeout, struct interface, reconnect);
	int ttl = 255;
	int yes = 1;

	iface->fd.fd = usock(USOCK_UDP | USOCK_SERVER | USOCK_NONBLOCK | USOCK_IPV4ONLY,
		(iface->multicast) ? (iface->mcast_addr) : (iface->v4_addrs), "5353");
	if (iface->fd.fd < 0) {
		fprintf(stderr, "failed to add listener %s: %m\n", iface->mcast_addr);
		goto retry;
	}

	if (setsockopt(iface->fd.fd, SOL_SOCKET, SO_BINDTODEVICE, iface->name, strlen(iface->name) < 0))
		fprintf(stderr, "ioctl failed: SO_BINDTODEVICE\n");

	if (setsockopt(iface->fd.fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: SO_REUSEADDR\n");

	if (setsockopt(iface->fd.fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
		fprintf(stderr, "ioctl failed: IP_TTL\n");

	if (setsockopt(iface->fd.fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: IP_RECVTTL\n");

	if (setsockopt(iface->fd.fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: IP_PKTINFO\n");

	if (iface->multicast && interface_mcast_setup4(iface)) {
		iface->fd.fd = -1;
		goto retry;
	}

	uloop_fd_add(&iface->fd, ULOOP_READ);
	if (iface->multicast) {
		dns_send_question(iface, NULL, C_DNS_SD, TYPE_PTR, 0);
		announce_init(iface);
	}

	return;

retry:
	uloop_timeout_set(timeout, 1000);
}

static void
reconnect_socket6(struct uloop_timeout *timeout)
{
	struct interface *iface = container_of(timeout, struct interface, reconnect);
	char mcast_addr[128];
	int ttl = 255;
	int yes = 1;

	snprintf(mcast_addr, sizeof(mcast_addr), "%s%%%s", (iface->multicast) ? (iface->mcast_addr) : (iface->v6_addrs), iface->name);
	iface->fd.fd = usock(USOCK_UDP | USOCK_SERVER | USOCK_NONBLOCK | USOCK_IPV6ONLY, mcast_addr, "5353");
	if (iface->fd.fd < 0) {
		fprintf(stderr, "failed to add listener %s: %m\n", mcast_addr);
		goto retry;
	}

	if (setsockopt(iface->fd.fd, SOL_SOCKET, SO_BINDTODEVICE, iface->name, strlen(iface->name) < 0))
		fprintf(stderr, "ioctl failed: SO_BINDTODEVICE\n");

	if (setsockopt(iface->fd.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
		fprintf(stderr, "ioctl failed: IPV6_UNICAST_HOPS\n");

	if (setsockopt(iface->fd.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: IPV6_RECVPKTINFO\n");

	if (setsockopt(iface->fd.fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: IPV6_RECVHOPLIMIT\n");

	if (setsockopt(iface->fd.fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: SO_REUSEADDR\n");

	if (iface->multicast && interface_socket_setup6(iface)) {
		iface->fd.fd = -1;
		goto retry;
	}

	uloop_fd_add(&iface->fd, ULOOP_READ);

	if (iface->multicast) {
		dns_send_question(iface, NULL, C_DNS_SD, TYPE_PTR, 0);
		announce_init(iface);
	}

	return;

retry:
	uloop_timeout_set(timeout, 1000);
}


static void interface_start(struct interface *iface)
{
	if (iface->v6) {
		iface->fd.cb = read_socket6;
		iface->reconnect.cb = reconnect_socket6;
	} else {
		iface->fd.cb = read_socket4;
		iface->reconnect.cb = reconnect_socket4;
	}
	uloop_timeout_set(&iface->reconnect, 100);
}

static void
iface_update_cb(struct vlist_tree *tree, struct vlist_node *node_new,
		struct vlist_node *node_old)
{
	struct interface *iface;

	if (node_old) {
		iface = container_of(node_old, struct interface, node);
		cache_cleanup(iface);
		interface_free(iface);
	}

	if (node_new) {
		iface = container_of(node_new, struct interface, node);
		interface_start(iface);
	}
}

static struct interface* _interface_add(const char *name, int multicast, int v6)
{
	struct interface *iface;
	char *name_buf;
	char *id_buf;

	iface = calloc_a(sizeof(*iface),
		&name_buf, strlen(name) + 1,
		&id_buf, strlen(name) + 5);

	sprintf(id_buf, "%d_%d_%s", multicast, v6, name);
	iface->name = strcpy(name_buf, name);
	iface->id = id_buf;
	iface->ifindex = if_nametoindex(name);
	iface->fd.fd = -1;
	iface->multicast = multicast;
	iface->v6 = v6;
	if (v6)
		iface->mcast_addr = MCAST_ADDR6;
	else
		iface->mcast_addr = MCAST_ADDR;

	if (iface->ifindex <= 0)
		goto error;

	vlist_add(&interfaces, &iface->node, iface->id);
	return iface;

error:
	free(iface);
	return NULL;
}

int interface_add(const char *name)
{
	struct interface *v4 = NULL, *v6 = NULL, *unicast;
	struct ifaddrs *ifap, *ifa;

	getifaddrs(&ifap);

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, name))
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET && !v4) {
			struct sockaddr_in *sa;

			if (cfg_proto && (cfg_proto != 4))
				continue;

			unicast = _interface_add(name, 0, 0);
			if (!unicast)
				continue;
			v4 = _interface_add(name, 1, 0);
			if (!v4)
				continue;

			sa = (struct sockaddr_in *) ifa->ifa_addr;
			memcpy(&v4->v4_addr, &sa->sin_addr, sizeof(v4->v4_addr));
			memcpy(&unicast->v4_addr, &sa->sin_addr, sizeof(unicast->v4_addr));

			inet_ntop(AF_INET, &sa->sin_addr, v4->v4_addrs, sizeof(v4->v4_addrs));
			inet_ntop(AF_INET, &sa->sin_addr, unicast->v4_addrs, sizeof(unicast->v4_addrs));

			sa = (struct sockaddr_in *) ifa->ifa_netmask;
			memcpy(&unicast->v4_netmask, &sa->sin_addr, sizeof(unicast->v4_netmask));
			memcpy(&v4->v4_netmask, &sa->sin_addr, sizeof(v4->v4_netmask));

			v4->peer = unicast;
			unicast->peer = v4;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6 && !v6) {
			uint8_t ll_prefix[] = {0xfe, 0x80 };
			struct sockaddr_in6 *sa6;

			if (cfg_proto && (cfg_proto != 6))
				continue;

			sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;
			if (memcmp(&sa6->sin6_addr, &ll_prefix, 2))
				continue;

			unicast = _interface_add(name, 0, 1);
			if (!unicast)
				continue;
			v6 = _interface_add(name, 1, 1);
			if (!v6)
				continue;

			memcpy(&v6->v6_addr, &sa6->sin6_addr, sizeof(v6->v6_addr));
			memcpy(&unicast->v6_addr, &sa6->sin6_addr, sizeof(unicast->v6_addr));

			inet_ntop(AF_INET6, &sa6->sin6_addr, v6->v6_addrs, sizeof(v6->v6_addrs));
			inet_ntop(AF_INET6, &sa6->sin6_addr, unicast->v6_addrs, sizeof(unicast->v6_addrs));

			sa6 = (struct sockaddr_in6 *) ifa->ifa_netmask;
			memcpy(&v6->v6_netmask, &sa6->sin6_addr, sizeof(v6->v6_netmask));
			memcpy(&unicast->v6_netmask, &sa6->sin6_addr, sizeof(unicast->v6_netmask));

			v6->peer = unicast;
			unicast->peer = v6;
		}
	}

	freeifaddrs(ifap);

	return !v4 && !v6;
}

void interface_shutdown(void)
{
	struct interface *iface;

	vlist_for_each_element(&interfaces, iface, node)
		if (iface->fd.fd > 0 && iface->multicast) {
			dns_reply_a(iface, NULL, 0);
			service_announce_services(iface, NULL, 0);
		}
	vlist_for_each_element(&interfaces, iface, node)
		interface_close(iface);
}

struct interface*
interface_get(const char *name, int v6, int multicast)
{
	char id_buf[32];
	snprintf(id_buf, sizeof(id_buf), "%d_%d_%s", multicast, v6, name);
	struct interface *iface = vlist_find(&interfaces, id_buf, iface, node);
	return iface;
}

VLIST_TREE(interfaces, avl_strcmp, iface_update_cb, false, false);
