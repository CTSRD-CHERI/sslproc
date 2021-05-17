/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/param.h>
#include <stdio.h>

#include <openssl/ssl.h>

#ifdef USE_SSLPROC
#include <sslproc.h>
#include <sslproc_namespace.h>
#endif

#include "sslproc_test_cb.h"

static const char *version_strings[] = {
	[SSL3_VERSION] = "SSL3.0",
	[TLS1_VERSION] = "TLS1.0",
	[TLS1_1_VERSION] = "TLS1.1",
	[TLS1_2_VERSION] = "TLS1.2",
	[TLS1_3_VERSION] = "TLS1.3",
};

void
msg_cb(int write_p, int version, int content_type, const void *buf,
    size_t len, SSL *ssl, void *arg)
{
	const char *prefix = arg;
	const char *str_write_p = write_p ? ">>>" : "<<<";
	const char *str_version;
	const char *str_content_type = "";

	if (version > nitems(version_strings) ||
	    version_strings[version] == NULL)
		str_version = "???";
	else
		str_version = version_strings[version];

        switch (content_type) {
        case 20:
		str_content_type = ", ChangeCipherSpec";
		break;
        case 21:
		str_content_type = ", Alert";
		break;
        case 22:
		str_content_type = ", Handshake";
		break;
        case 23:
		str_content_type = ", ApplicationData";
		break;
        case 24:
		str_content_type = ", Heartbeat";
		break;
        }

	printf("%s%s %s%s [length %04lx]\n", prefix, str_write_p,
	    str_version, str_content_type, (unsigned long)len);

	if (len > 0) {
		size_t num, i;

		printf("   ");
		num = len;
		for (i = 0; i < num; i++) {
			if (i % 16 == 0 && i > 0)
				printf("\n   ");
			printf(" %02x", ((const unsigned char *)buf)[i]);
		}
		if (i < len)
			printf(" ...");
		printf("\n");
	}
}
