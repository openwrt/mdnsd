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

#ifndef _DNS_H__
#define _DNS_H__

#define FLAG_RESPONSE		0x8000
#define FLAG_AUTHORATIVE	0x0400

#define TYPE_A			0x0001
#define TYPE_PTR		0x000C
#define TYPE_TXT		0x0010
#define TYPE_AAAA		0x001c
#define TYPE_SRV		0x0021
#define TYPE_ANY		0x00ff

#define IS_COMPRESSED(x)	((x & 0xc0) == 0xc0)

#define MCAST_ADDR		"224.0.0.251"
#define MCAST_PORT		5353

#define CLASS_FLUSH		0x8000
#define CLASS_IN		0x0001

#define MAX_NAME_LEN		8096
#define MAX_DATA_LEN		8096

#define C_DNS_SD                "_services._dns-sd._udp.local"

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
};

struct dns_srv_data {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
} __attribute__((packed, aligned(2)));

struct dns_answer {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
} __attribute__((packed, aligned(2)));

struct dns_question {
	uint16_t type;
	uint16_t class;
} __attribute__((packed, aligned(2)));

struct interface;

extern char rdata_buffer[MAX_DATA_LEN + 1];

extern void dns_send_question(struct interface *iface, const char *question, int type);
extern void dns_init_answer(void);
extern void dns_add_answer(int type, const uint8_t *rdata, uint16_t rdlength);
extern void dns_send_answer(struct interface *iface, const char *answer);
extern char* dns_consume_name(const uint8_t *base, int blen, uint8_t **data, int *len);
extern struct dns_answer* dns_consume_answer(uint8_t **data, int *len);
extern struct dns_question* dns_consume_question(uint8_t **data, int *len);
extern struct dns_header* dns_consume_header(uint8_t **data, int *len);
extern const char* dns_type_string(uint16_t type);

#endif
