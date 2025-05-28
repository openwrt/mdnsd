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

#include <libubus.h>
#include <libubox/uloop.h>

#include "dns.h"
#include "ubus.h"
#include "util.h"
#include "cache.h"
#include "service.h"
#include "announce.h"
#include "interface.h"

int cfg_proto = 0;
int cfg_no_subnet = 0;

static struct udebug ud;
static struct udebug_buf udb_log;
static const struct udebug_buf_meta meta_log = {
	.name = "umdns_log",
	.format = UDEBUG_FORMAT_STRING,
};

static struct udebug_ubus_ring rings[] = {
	{
		.buf = &udb_log,
		.meta = &meta_log,
		.default_entries = 1024,
		.default_size = 64 * 1024,
	}
};

static void
umdns_udebug_vprintf(const char *format, va_list ap)
{
	if (!udebug_buf_valid(&udb_log))
		return;

	udebug_entry_init(&udb_log);
	udebug_entry_vprintf(&udb_log, format, ap);
	udebug_entry_add(&udb_log);
}

void umdns_udebug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	umdns_udebug_vprintf(format, ap);
	va_end(ap);
}


void umdns_udebug_config(struct udebug_ubus *ctx, struct blob_attr *data,
			 bool enabled)
{
	udebug_ubus_apply_config(&ud, rings, ARRAY_SIZE(rings), data, enabled);
}

static void
signal_shutdown(int signal)
{
	uloop_end();
}

int
main(int argc, char **argv)
{
	int ch, ttl;

	uloop_init();
	udebug_init(&ud);
	udebug_auto_connect(&ud, NULL);

	while ((ch = getopt(argc, argv, "t:i:d46n")) != -1) {
		switch (ch) {
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
			interface_add(optarg);
			break;
		case '4':
			cfg_proto = 4;
			break;
		case '6':
			cfg_proto = 6;
			break;
		case 'n':
			cfg_no_subnet = 1;
			break;

		default:
			return -1;
		}
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, signal_shutdown);
	signal(SIGKILL, signal_shutdown);

	if (cache_init())
		return -1;

	ubus_startup();

	service_init(0);

	uloop_run();
	uloop_done();

	interface_shutdown();
	cache_cleanup(NULL);
	service_cleanup();
	vlist_flush(&interfaces);

	return 0;
}
