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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <ifaddrs.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/utils.h>
#include <libubox/avl-cmp.h>

#include "announce.h"
#include "util.h"
#include "dns.h"
#include "cache.h"
#include "service.h"
#include "interface.h"

#define QUERY_BATCH_SIZE	16

struct query_entry {
	struct avl_node node;
	uint16_t type;
	char name[];
};

static AVL_TREE(queries, avl_strcmp, true, NULL);
static char name_buffer[MAX_NAME_LEN + 1];

static struct {
	struct dns_header h;
	unsigned char data[9000 - sizeof(struct dns_header)];
} __attribute__((packed)) pkt;
static size_t pkt_len;
static struct dns_question *pkt_q[32];
static unsigned int pkt_n_q;
static unsigned char *dnptrs[255];

const char*
dns_type_string(uint16_t type)
{
	static const struct {
		uint16_t type;
		char str[5];
	} type_str[] = {
		{ TYPE_A, "A" },
		{ TYPE_AAAA, "AAAA" },
		{ TYPE_PTR, "PTR" },
		{ TYPE_TXT, "TXT" },
		{ TYPE_SRV, "SRV" },
		{ TYPE_ANY, "ANY" },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(type_str); i++) {
		if (type == type_str[i].type)
			return type_str[i].str;
	}

	return "N/A";
}

void dns_packet_init(void)
{
	dnptrs[0] = (unsigned char *)&pkt;
	dnptrs[1] = NULL;
	pkt_len = 0;
	pkt_n_q = 0;
	memset(&pkt.h, 0, sizeof(pkt.h));
}

static inline void *dns_packet_tail(size_t len)
{
	if (pkt_len + len > sizeof(pkt.data))
		return NULL;

	return &pkt.data[pkt_len];
}

static int
dns_packet_add_name(const char *name)
{
	void *data;

	data = dns_packet_tail(MAX_NAME_LEN);
	if (!data)
		return -1;

	return dn_comp(name, data, MAX_NAME_LEN, dnptrs, dnptrs + ARRAY_SIZE(dnptrs) - 1);
}

static void *dns_packet_record_add(size_t data_len, const char *name)
{
	void *data;
	int len;

	len = dns_packet_add_name(name);
	if (len < 1)
		return NULL;

	data = dns_packet_tail(len + data_len);
	if (!data)
		return NULL;

	pkt_len += len + data_len;

	return data + len;
}

bool dns_packet_question(const char *name, int type)
{
	struct dns_question *q;

	q = dns_packet_record_add(sizeof(*q), name);
	if (!q)
		return false;

	pkt.h.questions += cpu_to_be16(1);
	pkt_q[pkt_n_q++] = q;
	memset(q, 0, sizeof(*q));
	q->class = cpu_to_be16(1);
	q->type = cpu_to_be16(type);
	DBG(1, "Q <- %s %s\n", dns_type_string(type), name);

	return true;
}

void dns_packet_answer(const char *name, int type, const uint8_t *rdata, uint16_t rdlength, int ttl)
{
	struct dns_answer *a;

	pkt.h.flags |= cpu_to_be16(0x8400);

	a = dns_packet_record_add(sizeof(*a) + rdlength, name);
	if (!a)
		return;

	memset(a, 0, sizeof(*a));
	a->type = cpu_to_be16(type);
	a->class = cpu_to_be16(1);
	a->ttl = cpu_to_be32(ttl);
	a->rdlength = cpu_to_be16(rdlength);
	memcpy(a + 1, rdata, rdlength);
	DBG(1, "A <- %s %s\n", dns_type_string(be16_to_cpu(a->type)), name);

	pkt.h.answers += cpu_to_be16(1);
}

static void dns_question_set_multicast(struct dns_question *q, bool val)
{
	if (val)
		q->class &= ~cpu_to_be16(CLASS_UNICAST);
	else
		q->class |= cpu_to_be16(CLASS_UNICAST);
}

void dns_packet_send(struct interface *iface, struct sockaddr *to, bool query, int multicast)
{
	struct iovec iov = {
		.iov_base = &pkt,
		.iov_len = sizeof(pkt.h) + pkt_len,
	};
	size_t i;

	if (query) {
		if (multicast < 0)
			multicast = iface->need_multicast;

		for (i = 0; i < pkt_n_q; i++)
			dns_question_set_multicast(pkt_q[i], multicast);
	}

	if (interface_send_packet(iface, to, &iov, 1) < 0)
		perror("failed to send answer");
}

static void dns_packet_broadcast(void)
{
	struct interface *iface;

	vlist_for_each_element(&interfaces, iface, node)
		dns_packet_send(iface, NULL, 1, -1);
}

void
dns_send_question(struct interface *iface, struct sockaddr *to,
		  const char *question, int type, int multicast)
{
	dns_packet_init();
	dns_packet_question(question, type);
	dns_packet_send(iface, to, true, multicast);
}

static void
dns_query_pending(struct uloop_timeout *t)
{
	struct query_entry *e, *tmp;
	int count = 0;

	dns_packet_init();
	avl_remove_all_elements(&queries, e, node, tmp) {
		dns_packet_question(e->name, e->type);
		free(e);

		if (++count < QUERY_BATCH_SIZE)
			continue;

		count = 0;
		dns_packet_broadcast();
	}

	if (count)
		dns_packet_broadcast();
}

void dns_query(const char *name, uint16_t type)
{
	static struct uloop_timeout timer = {
		.cb = dns_query_pending
	};
	struct query_entry *e;

	e = avl_find_element(&queries, name, e, node);
	while (e) {
		if (e->type == type)
			return;

		e = avl_next_element(e, node);
		if (strcmp(e->name, name) != 0)
			break;
	}

	e = calloc(1, sizeof(*e) + strlen(name) + 1);
	e->type = type;
	e->node.key = e->name;
	strcpy(e->name, name);
	avl_insert(&queries, &e->node);

	if (queries.count > QUERY_BATCH_SIZE)
		timer.cb(&timer);

	if (!timer.pending)
		uloop_timeout_set(&timer, 100);
}

void
dns_reply_a(struct interface *iface, struct sockaddr *to, int ttl, const char *hostname, bool append)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	struct sockaddr_in6 *sa6;

	if (!hostname)
		hostname = mdns_hostname_local;

	getifaddrs(&ifap);

	if (!append)
		dns_packet_init();

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, iface->name))
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			dns_packet_answer(hostname, TYPE_A, (uint8_t *) &sa->sin_addr, 4, ttl);
		}
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;
			dns_packet_answer(hostname, TYPE_AAAA, (uint8_t *) &sa6->sin6_addr, 16, ttl);
		}
	}
	freeifaddrs(ifap);

	if(!append)
		dns_packet_send(iface, to, 0, 0);
}

void
dns_reply_a_additional(struct interface *iface, struct sockaddr *to, int ttl, bool append)
{
	struct hostname *h;

	vlist_for_each_element(&hostnames, h, node)
		dns_reply_a(iface, to, ttl, h->hostname, append);
}

static int
scan_name(const uint8_t *buffer, int len)
{
	int offset = 0;

	while (len && (*buffer != '\0')) {
		int l = *buffer;

		if (IS_COMPRESSED(l))
			return offset + 2;

		if (l + 1 > len) return -1;
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

	if (*len < sizeof(struct dns_header))
		return NULL;

	h->id = be16_to_cpu(h->id);
	h->flags = be16_to_cpu(h->flags);
	h->questions = be16_to_cpu(h->questions);
	h->answers = be16_to_cpu(h->answers);
	h->authority = be16_to_cpu(h->authority);
	h->additional = be16_to_cpu(h->additional);

	*len -= sizeof(struct dns_header);
	*data += sizeof(struct dns_header);

	return h;
}

static struct dns_question*
dns_consume_question(uint8_t **data, int *len)
{
	struct dns_question *q = (struct dns_question *) *data;

	if (*len < sizeof(struct dns_question))
		return NULL;

	q->type = be16_to_cpu(q->type);
	q->class = be16_to_cpu(q->class);

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

	a->type = be16_to_cpu(a->type);
	a->class = be16_to_cpu(a->class);
	a->ttl = be32_to_cpu(a->ttl);
	a->rdlength = be16_to_cpu(a->rdlength);

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

static int parse_answer(struct interface *iface, struct sockaddr *from,
			uint8_t *buffer, int len, uint8_t **b, int *rlen,
			int cache)
{
	char *name = dns_consume_name(buffer, len, b, rlen);
	struct dns_answer *a;
	uint8_t *rdata;

	if (!name || *rlen < 0) {
		fprintf(stderr, "dropping: bad question\n");
		return -1;
	}

	a = dns_consume_answer(b, rlen);
	if (!a) {
		fprintf(stderr, "dropping: bad question\n");
		return -1;
	}

	if ((a->class & ~CLASS_FLUSH) != CLASS_IN)
		return -1;

	rdata = *b;
	if (a->rdlength > *rlen) {
		fprintf(stderr, "dropping: bad question\n");
		return -1;
	}

	*rlen -= a->rdlength;
	*b += a->rdlength;

	if (cache)
		cache_answer(iface, from, buffer, len, name, a, rdata, a->class & CLASS_FLUSH);

	return 0;
}

static int
match_ipv6_addresses(char *reverse_ip, struct in6_addr *intf_ip)
{
	int i = 0, j = 0, idx = 0;
	char temp_ip[INET6_ADDRSTRLEN] = "";
	struct in6_addr buf;

	for (i = strlen(reverse_ip) - 1; i >= 0; i--) {
		if (reverse_ip[i] == '.')
			continue;

		if (j == 4) {
			temp_ip[idx] = ':';
			idx++;
			j = 0;
		}
		temp_ip[idx] = reverse_ip[i];
		idx++;
		j++;
	}

	if (inet_pton(AF_INET6, temp_ip, &buf) <= 0)
		return 0;

	return !memcmp(&buf, intf_ip, sizeof(buf));
}

static int
match_ip_addresses(char *reverse_ip, char *intf_ip)
{
	int ip1[4], ip2[4];

	sscanf(reverse_ip, "%d.%d.%d.%d", &ip1[3], &ip1[2], &ip1[1], &ip1[0]);
	sscanf(intf_ip, "%d.%d.%d.%d", &ip2[0], &ip2[1], &ip2[2], &ip2[3]);

	int i;
	for (i = 0; i < 4; i++) {
		if (ip1[i] != ip2[i])
			return 0;
	}
	return 1;
}

static void
dns_reply_reverse_ip6_mapping(struct interface *iface, struct sockaddr *to, int ttl, char *name, char *reverse_ip,
				bool append)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *sa6;

	char intf_ip[INET6_ADDRSTRLEN] = "";
	uint8_t buffer[256];
	int len;

	getifaddrs(&ifap);

	if (!append)
		dns_packet_init();

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, iface->name))
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;
			if (inet_ntop(AF_INET6, &sa6->sin6_addr, intf_ip, INET6_ADDRSTRLEN) == NULL)
				continue;

			if (match_ipv6_addresses(reverse_ip, &sa6->sin6_addr)) {
				len = dn_comp(mdns_hostname_local, buffer, sizeof(buffer), NULL, NULL);

				if (len < 1)
					continue;

				dns_packet_answer(name, TYPE_PTR, buffer, len, ttl);
			}
		}
	}

	if (!append)
		dns_packet_send(iface, to, 0, 0);

	freeifaddrs(ifap);
}

static void
dns_reply_reverse_ip4_mapping(struct interface *iface, struct sockaddr *to, int ttl, char *name, char *reverse_ip,
				bool append)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;

	char intf_ip[INET_ADDRSTRLEN] = "";
	uint8_t buffer[256];
	int len;

	getifaddrs(&ifap);

	if (!append)
		dns_packet_init();

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, iface->name))
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			if (inet_ntop(AF_INET, &sa->sin_addr, intf_ip, INET_ADDRSTRLEN) == NULL)
				continue;

			if (match_ip_addresses(reverse_ip, intf_ip)) {
				len = dn_comp(mdns_hostname_local, buffer, sizeof(buffer), NULL, NULL);

				if (len < 1)
					continue;

				dns_packet_answer(name, TYPE_PTR, buffer, len, ttl);
			}
		}
	}
	if (!append)
		dns_packet_send(iface, to, 0, 0);

	freeifaddrs(ifap);
}

static bool
is_reverse_dns_query(const char *name, const char *suffix)
{
	if (!name || !suffix)
		return false;

	size_t name_len = strlen(name);
	size_t suffix_len = strlen(suffix);

	if (suffix_len > name_len)
		return false;

	if (strncmp(name + (name_len - suffix_len), suffix, suffix_len) == 0)
		return true;

	return false;
}

static void
parse_question(struct interface *iface, struct sockaddr *from, char *name, struct dns_question *q, bool append)
{
	int is_unicast = (q->class & CLASS_UNICAST) != 0;
	struct sockaddr *to = NULL;
	struct hostname *h;
	char *host, *host6;

	/* TODO: Multicast if more than one quarter of TTL has passed */
	if (is_unicast) {
		/* if append is true we have already done this */
		if (!append) {
			to = from;
			if (interface_multicast(iface))
				iface = interface_get(iface->name, iface->type | SOCKTYPE_BIT_UNICAST);
		}
	}

	DBG(1, "Q -> %s %s\n", dns_type_string(q->type), name);

	switch (q->type) {
	case TYPE_ANY:
		if (!strcasecmp(name, mdns_hostname_local)) {
			dns_reply_a(iface, to, announce_ttl, NULL, append);
			dns_reply_a_additional(iface, to, announce_ttl, append);
			service_reply(iface, to, NULL, NULL, announce_ttl, is_unicast, append);
		}
		break;

	case TYPE_PTR:
		if (is_reverse_dns_query(name, ".in-addr.arpa")) {
			host = strstr(name, ".in-addr.arpa");
			char name_buf[256];
			strcpy(name_buf, name);
			*host = '\0';
			dns_reply_reverse_ip4_mapping(iface, to, announce_ttl, name_buf, name, append);
			break;
		}

		if (is_reverse_dns_query(name, ".ip6.arpa")) {
			host6 = strstr(name, ".ip6.arpa");
			char name_buf6[256];
			strcpy(name_buf6, name);
			*host6 = '\0';
			dns_reply_reverse_ip6_mapping(iface, to, announce_ttl, name_buf6, name, append);
			break;
		}

		if (!strcasecmp(name, C_DNS_SD)) {
			service_announce_services(iface, to, announce_ttl, append);
		} else {
			if (name[0] == '_') {
				service_reply(iface, to, NULL, name, announce_ttl, is_unicast, append);
			} else {
				/* First dot separates instance name from the rest */
				char *dot = strchr(name, '.');

				if (dot) {
					*dot = '\0';
					service_reply(iface, to, name, dot + 1, announce_ttl, is_unicast, append);
					*dot = '.';
				}
			}
		}
		break;

	case TYPE_AAAA:
	case TYPE_A:
		host = strcasestr(name, ".local");
		if (host)
			*host = '\0';
		if (!strcasecmp(umdns_host_label, name)) {
			dns_reply_a(iface, to, announce_ttl, NULL, append);
		} else {
			if (host)
				*host = '.';
			vlist_for_each_element(&hostnames, h, node)
				if (!strcasecmp(h->hostname, name))
					dns_reply_a(iface, to, announce_ttl, h->hostname, append);
		}
		break;
	};
}

static void
dns_append_questions(uint8_t *orig_buffer, int orig_len)
{
	/* Construct original question section */
	const struct dns_header *orig_h;
	uint8_t *ptr = orig_buffer;
	int len = orig_len;

	orig_h = dns_consume_header(&ptr, &len);
	if (orig_h) {
		pkt.h.id = cpu_to_be16(orig_h->id);

		uint16_t q_count = be16_to_cpu(orig_h->questions);
		while (q_count-- > 0 && len > 0) {
			char *qname = dns_consume_name(orig_buffer, orig_len, &ptr, &len);
			if (!qname || len < (int)sizeof(struct dns_question))
				break;

			struct dns_question *q = dns_consume_question(&ptr, &len);
			if (!q)
				break;

			dns_packet_question(qname, q->type);
		}
	}
}

void
dns_handle_packet(struct interface *iface, struct sockaddr *from, uint16_t port, uint8_t *buffer, int len)
{
	struct dns_header *h;
	uint8_t *b = buffer;
	int rlen = len;
	uint8_t orig_buffer[len];
	struct sockaddr *to = NULL;
	bool append = false;

	/* make a copy of the original buffer since it might be needed to construct the answer
	 * in case the query is received from a one-shot multicast dns querier */
	memcpy(orig_buffer, buffer, len);

	h = dns_consume_header(&b, &rlen);
	if (!h) {
		fprintf(stderr, "dropping: bad header\n");
		return;
	}

	/* legacy querier */
	if (port != MCAST_PORT) {
		/* aggregate answers and send, instead of sending separately */
		append = true;

		/* packet construction starts here */
		dns_packet_init();

		/* add original questions, as outlined by RFC 6762 Section 6.7 */
		dns_append_questions(orig_buffer, len);

		/* to return a unicast response */
		to = from;
		if (interface_multicast(iface))
			iface = interface_get(iface->name, iface->type | SOCKTYPE_BIT_UNICAST);
	}

	while (h->questions-- > 0) {
		char *name = dns_consume_name(buffer, len, &b, &rlen);
		struct dns_question *q;

		if (!name || rlen < 0) {
			fprintf(stderr, "dropping: bad name\n");
			return;
		}

		q = dns_consume_question(&b, &rlen);
		if (!q) {
			fprintf(stderr, "dropping: bad question\n");
			return;
		}

		if (!(h->flags & FLAG_RESPONSE))
			parse_question(iface, from, name, q, append);
	}

	/* if append is true, then answers have only been appended to the packet, not sent, so we do that here */
	if (append && pkt.h.answers > 0)
		dns_packet_send(iface, to, 0, 0);

	if (!(h->flags & FLAG_RESPONSE))
		return;

	while (h->answers-- > 0)
		if (parse_answer(iface, from, buffer, len, &b, &rlen, 1))
			return;

	while (h->authority-- > 0)
		if (parse_answer(iface, from, buffer, len, &b, &rlen, 1))
			return;

	while (h->additional-- > 0)
		if (parse_answer(iface, from, buffer, len, &b, &rlen, 1))
			return;

}
