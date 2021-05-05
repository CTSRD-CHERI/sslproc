/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sslproc.h>
#include <sslproc_namespace.h>

#define	dprintf(...) do {			\
	if (verbose) {				\
		printf("%s: ", __func__);	\
		printf(__VA_ARGS__);		\
	}					\
} while (0)

#define FAIL(...) do {					\
	printf("%s: FAIL: ", __func__);			\
	printf(__VA_ARGS__);				\
	printf("\n");					\
	return;						\
} while (0)

#define PASS() do {					\
	printf("%s: PASS\n", __func__);			\
	return;						\
} while (0)

static int verbose;

static void
usage(void)
{
	fprintf(stderr, "Usage: sslproc_test [-v]\n");
	exit(1);
}

static void
test_ctx_create(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	SSL_CTX_free(ctx);

	PASS();
}

static void
test_ctx_refs(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	if (SSL_CTX_up_ref(ctx) != 1) {
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		FAIL("failed to increment ref count");
	}
	
	SSL_CTX_free(ctx);
	SSL_CTX_free(ctx);

	PASS();
}

static void
test_ctx_options(void)
{
	SSL_CTX *ctx;
	long options, new;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	options = SSL_CTX_get_options(ctx);
	dprintf("initial options: %#lx\n", options);

	new = SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
	dprintf("options after set: %#lx\n", new);

	if (SSL_CTX_get_options(ctx) != new) {
		SSL_CTX_free(ctx);
		FAIL("failed to get updated options after set");
	}

	new = SSL_CTX_clear_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
	dprintf("options after clear: %#lx\n", new);

	if (SSL_CTX_get_options(ctx) != new) {
		SSL_CTX_free(ctx);
		FAIL("failed to get updated options after clear");
	}

	if (new != options) {
		SSL_CTX_free(ctx);
		FAIL("final options don't match initial options\n");
	}

	SSL_CTX_free(ctx);

	PASS();
}

int
main(int ac, char **av)
{
	int ch;

	while ((ch = getopt(ac, av, "v")) != -1)
		switch (ch) {
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}

	test_ctx_create();
	test_ctx_refs();
	test_ctx_options();

	return (0);
}
