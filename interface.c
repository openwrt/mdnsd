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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <libubox/avl-cmp.h>
#include <libubox/utils.h>
#include "interface.h"
#include "util.h"
#include "dns.h"
#include "announce.h"

struct interface *cur_iface = NULL;

int
interface_send_packet(struct interface *iface, struct iovec *iov, int iov_len)
{
	static size_t cmsg_data[( CMSG_SPACE(sizeof(struct in_pktinfo)) / sizeof(size_t)) + 1];
	static struct sockaddr_in a = {
		.sin_family = AF_INET,
		.sin_port = htons(MCAST_PORT),
	};
	static struct msghdr m = {
		.msg_name = (struct sockaddr *) &a,
		.msg_namelen = sizeof(a),
		.msg_control = cmsg_data,
		.msg_controllen = CMSG_LEN(sizeof(struct in_pktinfo)),
	};
	struct in_pktinfo *pkti;
	struct cmsghdr *cmsg;
	int fd = iface->fd.fd;

	m.msg_iov = iov;
	m.msg_iovlen = iov_len;

	memset(cmsg_data, 0, sizeof(cmsg_data));
	cmsg = CMSG_FIRSTHDR(&m);
	cmsg->cmsg_len = m.msg_controllen;
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;

	pkti = (struct in_pktinfo*) CMSG_DATA(cmsg);
	pkti->ipi_ifindex = iface->ifindex;

	a.sin_addr.s_addr = inet_addr(MCAST_ADDR);

	return sendmsg(fd, &m, 0);
}

static void interface_free(struct interface *iface)
{
	if (cur_iface == iface)
		cur_iface = NULL;

	announce_free(iface);
	if (iface->fd.fd >= 0) {
		uloop_fd_delete(&iface->fd);
		close(iface->fd.fd);
	}
	free(iface);
}

static void interface_start(struct interface *iface)
{
	cur_iface = iface;
}

static void
iface_update_cb(struct vlist_tree *tree, struct vlist_node *node_new,
		struct vlist_node *node_old)
{
	struct interface *iface;

	if (node_old) {
		iface = container_of(node_old, struct interface, node);
		interface_free(iface);
	}

	if (node_new) {
		iface = container_of(node_new, struct interface, node);
		interface_start(iface);
	}
}

int interface_socket_setup(struct interface *iface)
{
	struct ip_mreqn mreq;
	uint8_t ttl = 255;
	int yes = 1;
	int no = 0;
	struct sockaddr_in sa = { 0 };
	struct in_addr in;
	int fd = iface->fd.fd;

	inet_aton(iface->ip, &in);

	sa.sin_family = AF_INET;
	sa.sin_port = htons(MCAST_PORT);
	inet_pton(AF_INET, MCAST_ADDR, &sa.sin_addr);

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_address.s_addr = in.s_addr;
	mreq.imr_multiaddr = sa.sin_addr;
	mreq.imr_ifindex = iface->ifindex;

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
		fprintf(stderr, "ioctl failed: IP_MULTICAST_TTL\n");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: SO_REUSEADDR\n");

	/* Some network drivers have issues with dropping membership of
	 * mcast groups when the iface is down, but don't allow rejoining
	 * when it comes back up. This is an ugly workaround
	 * -- this was copied from avahi --
	 */
	setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		fprintf(stderr, "failed to join multicast group: %s\n", strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: IP_RECVTTL\n");

	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: IP_PKTINFO\n");

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof(no)) < 0)
		fprintf(stderr, "ioctl failed: IP_MULTICAST_LOOP\n");

	return 0;
}

static const char*
get_iface_ipv4(const char *ifname)
{
	static char buffer[INET_ADDRSTRLEN];
	struct ifreq ir;
	const char *ret;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return NULL;

	memset(&ir, 0, sizeof(struct ifreq));
	strncpy(ir.ifr_name, ifname, sizeof(ir.ifr_name));

	if (ioctl(sock, SIOCGIFADDR, &ir) < 0)
		return NULL;

	ret = inet_ntop(AF_INET, &((struct sockaddr_in *) &ir.ifr_addr)->sin_addr, buffer, sizeof(buffer));
	close(sock);

	return ret;
}

int interface_add(const char *name)
{
	struct interface *iface;
	const char *ip_str;
	char *name_buf, *ip_buf;

	ip_str = get_iface_ipv4(name);
	if (!ip_str)
		return -1;

	iface = calloc_a(sizeof(*iface),
		&name_buf, strlen(name) + 1,
		&ip_buf, strlen(ip_str) + 1);

	iface->name = strcpy(name_buf, name);
	iface->ip = strcpy(ip_buf, ip_str);
	iface->ifindex = if_nametoindex(name);
	iface->fd.fd = -1;

	if (iface->ifindex <= 0)
		goto error;

	vlist_add(&interfaces, &iface->node, name);
	return 0;

error:
	free(iface);
	return -1;
}

VLIST_TREE(interfaces, avl_strcmp, iface_update_cb, false, false);
