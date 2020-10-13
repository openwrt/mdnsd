#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "dns.h"
#include "cache.c"
#include "interface.h"

int cfg_proto = 0;
int cfg_no_subnet = 0;

static void fuzz_dns_handle_packet(uint8_t *input, size_t size)
{
	struct sockaddr from;
	struct interface iface;
	struct cache_service *s, *t;

	memset(&from, 0, sizeof(from));
	memset(&iface, 0, sizeof(iface));

	cache_init();
	dns_handle_packet(&iface, &from, 1922, input, size);

	avl_for_each_element_safe(&services, s, avl, t)
		cache_service_free(s);
}

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t size)
{
	uint8_t *buf = calloc(1, size);
	if (!buf)
		return 0;

	memcpy(buf, input, size);
	fuzz_dns_handle_packet(buf, size);
	free(buf);

	return 0;
}
