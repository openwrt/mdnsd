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

int announce_ttl = 75 * 60;

static void
announce_timer(struct uloop_timeout *timeout)
{
	struct interface *iface = container_of(timeout, struct interface, announce_timer);

	switch (iface->announce_state) {
		case STATE_PROBE1:
		case STATE_PROBE2:
		case STATE_PROBE3:
			dns_send_question(iface, NULL, mdns_hostname_local, TYPE_ANY, 1);
			uloop_timeout_set(timeout, 250);
			iface->announce_state++;
			break;

		case STATE_PROBE_WAIT:
			uloop_timeout_set(timeout, 500);
			iface->announce_state++;
			break;

		case STATE_PROBE_END:
			if (cache_host_is_known(mdns_hostname_local)) {
				fprintf(stderr, "the host %s already exists. stopping announce service\n", mdns_hostname_local);
				return;
			}
			iface->announce_state++;
			/* Fall through */

		case STATE_ANNOUNCE:
			dns_reply_a(iface, NULL, announce_ttl);
			service_announce_services(iface, NULL, announce_ttl);
			uloop_timeout_set(timeout, announce_ttl * 800);
			break;
	}
}

void
announce_init(struct interface *iface)
{
	iface->announce_state = STATE_PROBE1;
	iface->announce_timer.cb = announce_timer;
	uloop_timeout_set(&iface->announce_timer, 100);
}

void
announce_free(struct interface *iface)
{
	uloop_timeout_cancel(&iface->announce_timer);
}
