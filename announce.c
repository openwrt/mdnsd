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

#include <stdio.h>

#include <libubox/uloop.h>

#include "cache.h"
#include "dns.h"
#include "util.h"
#include "service.h"
#include "announce.h"
#include "interface.h"

#define TTL_TIMEOUT	75

enum {
	STATE_PROBE1 = 0,
	STATE_PROBE2,
	STATE_PROBE3,
	STATE_PROBE_WAIT,
	STATE_PROBE_END,
	STATE_ANNOUNCE,
};

static struct uloop_timeout announce;
struct uloop_fd *announce_fd;
static int announce_state;
int announce_ttl = 75 * 60;

static void
announce_timer(struct uloop_timeout *timeout)
{
	char host[256];

	snprintf(host, sizeof(host), "%s.local", hostname);

	switch (announce_state) {
		case STATE_PROBE1:
		case STATE_PROBE2:
		case STATE_PROBE3:
			dns_send_question(cur_iface, host, TYPE_ANY);
			uloop_timeout_set(timeout, 250);
			announce_state++;
			break;

		case STATE_PROBE_WAIT:
			uloop_timeout_set(timeout, 500);
			announce_state++;
			break;

		case STATE_PROBE_END:
			if (cache_host_is_known(host)) {
				fprintf(stderr, "the host %s already exists. stopping announce service\n", host);
				return;
			}
			announce_state++;

		case STATE_ANNOUNCE:
			service_announce(announce_fd);
			uloop_timeout_set(timeout, announce_ttl * 800);
			break;
	}
}

void
announce_init(struct uloop_fd *u)
{
	announce_state = STATE_PROBE1;
	announce.cb = announce_timer;
	announce_fd = u;
	uloop_timeout_set(&announce, 100);
}
