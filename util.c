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

void get_hostname(void)
{
	struct utsname utsname;

	umdns_host_label[0] = 0;
	mdns_hostname_local[0] = 0;

	if (uname(&utsname) < 0)
		return;

	snprintf(umdns_host_label, sizeof(umdns_host_label), "%s", utsname.nodename);
	snprintf(mdns_hostname_local, sizeof(mdns_hostname_local), "%s.local", utsname.nodename);
}

time_t monotonic_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}
