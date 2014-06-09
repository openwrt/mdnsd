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

#include <sys/stat.h>
#include <sys/types.h>

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <resolv.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <asm/byteorder.h>

#include <libubus.h>
#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/avl-cmp.h>

#include "dns.h"
#include "ubus.h"
#include "util.h"
#include "cache.h"
#include "service.h"
#include "announce.h"
#include "interface.h"

static struct uloop_timeout reconnect;
char *iface_name = "eth0";

static void
read_socket(struct uloop_fd *u, unsigned int events)
{
	struct interface *iface = container_of(u, struct interface, fd);
	static uint8_t buffer[8 * 1024];
	int len;

	if (u->eof) {
		uloop_fd_delete(u);
		close(u->fd);
		u->fd = -1;
		uloop_timeout_set(&reconnect, 1000);
		return;
	}

	len = read(u->fd, buffer, sizeof(buffer));
	if (len < 1) {
		fprintf(stderr, "read failed: %s\n", strerror(errno));
		return;
	}

	dns_handle_packet(iface, buffer, len);
}

static void
reconnect_socket(struct uloop_timeout *timeout)
{
	cur_iface->fd.fd = usock(USOCK_UDP | USOCK_SERVER | USOCK_NONBLOCK, MCAST_ADDR, "5353");
	if (cur_iface->fd.fd < 0) {
		fprintf(stderr, "failed to add listener: %s\n", strerror(errno));
		uloop_timeout_set(&reconnect, 1000);
	} else {
		if (interface_socket_setup(cur_iface)) {
			uloop_timeout_set(&reconnect, 1000);
			cur_iface->fd.fd = -1;
			return;
		}

		uloop_fd_add(&cur_iface->fd, ULOOP_READ);
		sleep(5);
		dns_send_question(cur_iface, "_services._dns-sd._udp.local", TYPE_PTR);
		announce_init(cur_iface);
	}
}

int
main(int argc, char **argv)
{
	int ch, ttl;

	while ((ch = getopt(argc, argv, "h:t:i:d")) != -1) {
		switch (ch) {
		case 'h':
			hostname = optarg;
			break;
		case 't':
			ttl = atoi(optarg);
			if (ttl > 0)
				announce_ttl = ttl;
			else
				fprintf(stderr, "invalid ttl\n");
			break;
		case 'd':
			debug++;
			break;
		case 'i':
			iface_name = optarg;
			break;
		}
	}

	if (!iface_name)
		return -1;

	uloop_init();

	if (interface_add(iface_name)) {
		fprintf(stderr, "Failed to add interface %s\n", iface_name);
		return -1;
	}

	if (!cur_iface)
		return -1;

	signal_setup();

	if (cache_init())
		return -1;

	service_init();

	cur_iface->fd.cb = read_socket;
	reconnect.cb = reconnect_socket;

	uloop_timeout_set(&reconnect, 100);
	ubus_startup();
	uloop_run();
	uloop_done();

	cache_cleanup();
	service_cleanup();

	return 0;
}
