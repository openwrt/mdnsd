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

static int
parse_answer(struct uloop_fd *u, uint8_t *buffer, int len, uint8_t **b, int *rlen, int cache)
{
	char *name = dns_consume_name(buffer, len, b, rlen);
	struct dns_answer *a;
	uint8_t *rdata;

	if (!name) {
		fprintf(stderr, "dropping: bad question\n");
		return -1;
	}

	a = dns_consume_answer(b, rlen);
	if (!a) {
		fprintf(stderr, "dropping: bad question\n");
		return -1;
	}

	rdata = *b;
	if (a->rdlength > *rlen) {
		fprintf(stderr, "dropping: bad question\n");
		return -1;
	}

	*rlen -= a->rdlength;
	*b += a->rdlength;

	if (cache)
		cache_answer(u, buffer, len, name, a, rdata);

	return 0;
}

static void
parse_question(struct uloop_fd *u, char *name, struct dns_question *q)
{
	char *host;

	DBG(1, "Q -> %s %s\n", dns_type_string(q->type), name);

	switch (q->type) {
	case TYPE_ANY:
		host = service_name("local");
		if (!strcmp(name, host))
			service_reply(u, NULL);
		break;

	case TYPE_PTR:
		service_announce_services(u, name);
		service_reply(u, name);
		break;

	case TYPE_AAAA:
	case TYPE_A:
		host = strstr(name, ".local");
		if (host)
			*host = '\0';
		if (!strcmp(hostname, name))
			service_reply_a(u, q->type);
		break;
	};
}

static void
read_socket(struct uloop_fd *u, unsigned int events)
{
	uint8_t buffer[8 * 1024];
	uint8_t *b = buffer;
	struct dns_header *h;
	int len, rlen;

	if (u->eof) {
		uloop_fd_delete(u);
		close(u->fd);
		u->fd = -1;
		uloop_timeout_set(&reconnect, 1000);
		return;
	}

	rlen = len = read(u->fd, buffer, sizeof(buffer));
	if (len < 1) {
		fprintf(stderr, "read failed: %s\n", strerror(errno));
		return;
	}

	h = dns_consume_header(&b, &rlen);
	if (!h) {
		fprintf(stderr, "dropping: bad header\n");
		return;
	}

	while (h->questions-- > 0) {
		char *name = dns_consume_name(buffer, len, &b, &rlen);
		struct dns_question *q;

		if (!name) {
			fprintf(stderr, "dropping: bad name\n");
			return;
		}

		q = dns_consume_question(&b, &rlen);
		if (!q) {
			fprintf(stderr, "dropping: bad question\n");
			return;
		}

		if (!(h->flags & FLAG_RESPONSE))
			parse_question(announce_fd, name, q);
	}

	if (!(h->flags & FLAG_RESPONSE))
		return;

	while (h->answers-- > 0)
		parse_answer(u, buffer, len, &b, &rlen, 1);

	while (h->authority-- > 0)
		parse_answer(u, buffer, len, &b, &rlen, 0);

	while (h->additional-- > 0)
		parse_answer(u, buffer, len, &b, &rlen, 1);
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
		announce_init(&cur_iface->fd);
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
