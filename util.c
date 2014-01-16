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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>

#include <libubox/uloop.h>

#include "dns.h"
#include "util.h"

int debug = 0;
struct uloop_fd listener;

static void
signal_shutdown(int signal)
{
	uloop_end();
}

void
signal_setup(void)
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, signal_shutdown);
	signal(SIGKILL, signal_shutdown);
}

uint32_t
rand_time_delta(uint32_t t)
{
	uint32_t val;
	int fd = open("/dev/urandom", O_RDONLY);

	if (!fd)
		return t;

	if (read(fd, &val, sizeof(val)) == sizeof(val)) {
		int range = t / 30;

		srand(val);
		val = t + (rand() % range) - (range / 2);
	} else {
		val = t;
	}

	close(fd);

	return val;
}

const char*
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

char*
get_hostname(void)
{
	static struct utsname utsname;

	if (uname(&utsname) < 0)
		return NULL;

	return utsname.nodename;
}

int
socket_setup(int fd, const char *ip)
{
	struct ip_mreqn mreq;
	uint8_t ttl = 255;
	int yes = 1;
	int no = 0;
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(MCAST_PORT);
	inet_pton(AF_INET, MCAST_ADDR, &sa.sin_addr);

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_address.s_addr = htonl(INADDR_ANY);
	mreq.imr_multiaddr = sa.sin_addr;

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
		fprintf(stderr, "ioctl failed: IP_MULTICAST_TTL\n");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
		fprintf(stderr, "ioctl failed: SO_REUSEADDR\n");

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

void*
memdup(void *d, int l)
{
	void *r = malloc(l);
	if (!r)
		return NULL;
	memcpy(r, d, l);
	return r;
}

