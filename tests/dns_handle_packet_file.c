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

int main(int argc, char *argv[])
{
	size_t len = 0;
	FILE *fd = NULL;
	uint8_t *buf = NULL;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <packet.bin>\n", argv[0]);
		return -1;
	}

	fd = fopen(argv[1], "r");
	if (!fd) {
		perror("unable to open input file\n");
		return -1;
	}

	buf = calloc(1, MDNS_BUF_LEN+1);
	if (!buf)
		return -1;

	len = fread(buf, 1, MDNS_BUF_LEN, fd);

	fuzz_dns_handle_packet(buf, len);

	fclose(fd);
	free(buf);
}
