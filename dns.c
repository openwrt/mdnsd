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
#include <sys/stat.h>

#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/utils.h>

#include "announce.h"
#include "util.h"
#include "dns.h"
#include "cache.h"
#include "service.h"
#include "interface.h"

char rdata_buffer[MAX_DATA_LEN + 1];
static char name_buffer[MAX_NAME_LEN + 1];

const char*
dns_type_string(uint16_t type)
{
	switch (type) {
	case TYPE_A:
		return "A";

	case TYPE_AAAA:
		return "AAAA";

	case TYPE_PTR:
		return "PTR";

	case TYPE_TXT:
		return "TXT";

	case TYPE_SRV:
		return "SRV";

	case TYPE_ANY:
		return "ANY";
	}

	return "N/A";
}

void
dns_send_question(struct interface *iface, const char *question, int type)
{
	static struct dns_header h = {
		.questions = cpu_to_be16(1),
	};
	static struct dns_question q = {
		.class = cpu_to_be16(1),
	};
	static struct iovec iov[] = {
		{
			.iov_base = &h,
			.iov_len = sizeof(h),
		},
		{
			.iov_base = name_buffer,
		},
		{
			.iov_base = &q,
			.iov_len = sizeof(q),
		}
	};
	int len;

	q.type = __cpu_to_be16(type);

	len = dn_comp(question, (void *) name_buffer, sizeof(name_buffer), NULL, NULL);
	if (len < 1)
		return;

	iov[1].iov_len = len;

	if (interface_send_packet(iface, iov, ARRAY_SIZE(iov)) < 0)
		fprintf(stderr, "failed to send question\n");
	else
		DBG(1, "Q <- %s %s\n", dns_type_string(type), question);
}


struct dns_reply {
	int type;
	struct dns_answer a;
	uint16_t rdlength;
	uint8_t *rdata;
	char *buffer;
};

#define MAX_ANSWER	8
static struct dns_reply dns_reply[1 + (MAX_ANSWER * 3)];
static int dns_answer_cnt;

void
dns_init_answer(void)
{
	dns_answer_cnt = 0;
}

void
dns_add_answer(int type, const uint8_t *rdata, uint16_t rdlength)
{
	struct dns_reply *a = &dns_reply[dns_answer_cnt];
	if (dns_answer_cnt == MAX_ANSWER)
		return;
	a->rdata = memdup(rdata, rdlength);
	a->type = type;
	a->rdlength = rdlength;
	dns_answer_cnt++;
}

void
dns_send_answer(struct interface *iface, const char *answer)
{
	uint8_t buffer[256];
	struct dns_header h = { 0 };
	struct iovec *iov;
	int len, i;

	if (!dns_answer_cnt)
		return;

	h.answers = __cpu_to_be16(dns_answer_cnt);
	h.flags = __cpu_to_be16(0x8400);

	iov = alloca(sizeof(struct iovec) * ((dns_answer_cnt * 3) + 1));
	iov[0].iov_base = &h;
	iov[0].iov_len = sizeof(struct dns_header);

	for (i = 0; i < dns_answer_cnt; i++) {
		struct dns_answer *a = &dns_reply[i].a;
		int id = (i * 3) + 1;

		memset(a, 0, sizeof(*a));
		a->type = __cpu_to_be16(dns_reply[i].type);
		a->class = __cpu_to_be16(1);
		a->ttl = __cpu_to_be32(announce_ttl);
		a->rdlength = __cpu_to_be16(dns_reply[i].rdlength);

		len = dn_comp(answer, buffer, sizeof(buffer), NULL, NULL);
		if (len < 1)
			return;

		dns_reply[i].buffer = iov[id].iov_base = memdup(buffer, len);
		iov[id].iov_len = len;

		iov[id + 1].iov_base = a;
		iov[id + 1].iov_len = sizeof(struct dns_answer);

		iov[id + 2].iov_base = dns_reply[i].rdata;
		iov[id + 2].iov_len = dns_reply[i].rdlength;

		DBG(1, "A <- %s %s\n", dns_type_string(dns_reply[i].type), answer);
	}

	if (interface_send_packet(iface, iov, (dns_answer_cnt * 3) + 1) < 0)
		fprintf(stderr, "failed to send question\n");

	for (i = 0; i < dns_answer_cnt; i++) {
		free(dns_reply[i].buffer);
		free(dns_reply[i].rdata);
	}
	dns_answer_cnt = 0;
}

static int
scan_name(const uint8_t *buffer, int len)
{
	int offset = 0;

	while (len && (*buffer != '\0')) {
		int l = *buffer;

		if (IS_COMPRESSED(l))
			return offset + 2;

		len -= l + 1;
		offset += l + 1;
		buffer += l + 1;
	}

	if (!len || !offset || (*buffer != '\0'))
		return -1;

	return offset + 1;
}

static struct dns_header*
dns_consume_header(uint8_t **data, int *len)
{
	struct dns_header *h = (struct dns_header *) *data;
	uint16_t *swap = (uint16_t *) h;
	int endianess = 6;

	if (*len < sizeof(struct dns_header))
		return NULL;

	while (endianess--) {
		*swap = __be16_to_cpu(*swap);
		swap++;
	}

	*len -= sizeof(struct dns_header);
	*data += sizeof(struct dns_header);

	return h;
}

static struct dns_question*
dns_consume_question(uint8_t **data, int *len)
{
	struct dns_question *q = (struct dns_question *) *data;
	uint16_t *swap = (uint16_t *) q;
	int endianess = 2;

	if (*len < sizeof(struct dns_question))
		return NULL;

	while (endianess--) {
		*swap = __be16_to_cpu(*swap);
		swap++;
	}

	*len -= sizeof(struct dns_question);
	*data += sizeof(struct dns_question);

	return q;
}

static struct dns_answer*
dns_consume_answer(uint8_t **data, int *len)
{
	struct dns_answer *a = (struct dns_answer *) *data;

	if (*len < sizeof(struct dns_answer))
		return NULL;

	a->type = __be16_to_cpu(a->type);
	a->class = __be16_to_cpu(a->class);
	a->ttl = __be32_to_cpu(a->ttl);
	a->rdlength = __be16_to_cpu(a->rdlength);

	*len -= sizeof(struct dns_answer);
	*data += sizeof(struct dns_answer);

	return a;
}

static char *
dns_consume_name(const uint8_t *base, int blen, uint8_t **data, int *len)
{
	int nlen = scan_name(*data, *len);

	if (nlen < 1)
		return NULL;

	if (dn_expand(base, base + blen, *data, name_buffer, MAX_NAME_LEN) < 0) {
		perror("dns_consume_name/dn_expand");
		return NULL;
	}

	*len -= nlen;
	*data += nlen;

	return name_buffer;
}

static int
parse_answer(struct interface *iface, uint8_t *buffer, int len, uint8_t **b, int *rlen, int cache)
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
		cache_answer(iface, buffer, len, name, a, rdata);

	return 0;
}

static void
parse_question(struct interface *iface, char *name, struct dns_question *q)
{
	char *host;

	DBG(1, "Q -> %s %s\n", dns_type_string(q->type), name);

	switch (q->type) {
	case TYPE_ANY:
		host = service_name("local");
		if (!strcmp(name, host))
			service_reply(iface, NULL);
		break;

	case TYPE_PTR:
		service_announce_services(iface, name);
		service_reply(iface, name);
		break;

	case TYPE_AAAA:
	case TYPE_A:
		host = strstr(name, ".local");
		if (host)
			*host = '\0';
		if (!strcmp(hostname, name))
			service_reply_a(iface, q->type);
		break;
	};
}

void
dns_handle_packet(struct interface *iface, uint8_t *buffer, int len)
{
	struct dns_header *h;
	uint8_t *b = buffer;
	int rlen = len;

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
			parse_question(iface, name, q);
	}

	if (!(h->flags & FLAG_RESPONSE))
		return;

	while (h->answers-- > 0)
		parse_answer(iface, buffer, len, &b, &rlen, 1);

	while (h->authority-- > 0)
		parse_answer(iface, buffer, len, &b, &rlen, 0);

	while (h->additional-- > 0)
		parse_answer(iface, buffer, len, &b, &rlen, 1);
}
