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

#ifndef _SERVICE_H__
#define _SERVICE_H__

extern char *hostname;
extern char* service_name(char *domain);
extern void service_init(void);
extern void service_cleanup(void);
extern void service_announce(struct uloop_fd *u);
extern void service_announce_services(struct uloop_fd *u, char *service);
extern void service_reply(struct uloop_fd *u, char *match);
extern void service_reply_a(struct uloop_fd *u, int type);

#endif
