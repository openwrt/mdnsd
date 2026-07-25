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
#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>

#include "dns.h"
#include "util.h"

uint8_t mdns_buf[MDNS_BUF_LEN];
int debug = 0;

char umdns_host_label[HOSTNAME_LEN];
char mdns_hostname_local[HOSTNAME_LEN + 6];

static char umdns_host_base[HOSTNAME_LEN];
static unsigned int umdns_host_suffix;

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

/* "-" plus the widest suffix an unsigned int can print, plus the terminator */
#define HOSTNAME_SUFFIX_LEN	12

static void apply_hostname(void)
{
	if (umdns_host_suffix)
		snprintf(umdns_host_label, sizeof(umdns_host_label), "%.*s-%u",
			 (int)sizeof(umdns_host_label) - HOSTNAME_SUFFIX_LEN,
			 umdns_host_base, umdns_host_suffix + 1);
	else
		snprintf(umdns_host_label, sizeof(umdns_host_label), "%s", umdns_host_base);

	snprintf(mdns_hostname_local, sizeof(mdns_hostname_local), "%s.local", umdns_host_label);
}

void get_hostname(void)
{
	struct utsname utsname;

	umdns_host_label[0] = 0;
	mdns_hostname_local[0] = 0;

	if (uname(&utsname) < 0)
		return;

	/*
	 * Only start over from the unsuffixed name when the system host name
	 * itself changed, so that a name picked to resolve a conflict survives
	 * an unrelated reload.
	 */
	if (strcmp(umdns_host_base, utsname.nodename)) {
		snprintf(umdns_host_base, sizeof(umdns_host_base), "%s", utsname.nodename);
		umdns_host_suffix = 0;
	}

	apply_hostname();
}

bool rename_hostname(void)
{
	if (umdns_host_suffix >= HOSTNAME_MAX_SUFFIX)
		return false;

	umdns_host_suffix++;
	apply_hostname();

	return true;
}

time_t monotonic_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}
