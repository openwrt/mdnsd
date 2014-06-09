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

uint8_t mdns_buf[MDNS_BUF_LEN];
int debug = 0;

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

char*
get_hostname(void)
{
	static struct utsname utsname;

	if (uname(&utsname) < 0)
		return NULL;

	return utsname.nodename;
}

void*
memdup(const void *d, int l)
{
	void *r = malloc(l);
	if (!r)
		return NULL;
	memcpy(r, d, l);
	return r;
}

