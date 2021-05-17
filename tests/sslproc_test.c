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

#include <sys/param.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef USE_SSLPROC
#include <sslproc.h>
#include <sslproc_namespace.h>
#endif

#include "sslproc_test_cb.h"

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

static int show_messages, verbose;
static const char *short_message = "this is a test message";
static const char *cert;
static const char *privkey;

static void
usage(void)
{
	fprintf(stderr,
	    "Usage: sslproc_test [-c certfile] [-k keyfile] [-mv]\n");
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

static void
test_ctx_proto_versions(void)
{
	SSL_CTX *ctx;
	int version;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	version = SSL_CTX_get_min_proto_version(ctx);
	dprintf("initial min version: %d\n", version);

	version = SSL_CTX_get_max_proto_version(ctx);
	dprintf("initial min version: %d\n", version);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to set min version");
	}

	if (SSL_CTX_get_min_proto_version(ctx) != TLS1_2_VERSION)
		FAIL("min version after set did not match");

	if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to set min version");
	}

	if (SSL_CTX_get_max_proto_version(ctx) != TLS1_3_VERSION)
		FAIL("min version after set did not match");

	SSL_CTX_free(ctx);

	PASS();
}

static void
test_ctx_app_data(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	if (SSL_CTX_set_app_data(ctx, (void *)(uintptr_t)0xdeadbeef) != 1) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to set app data");
	}

	if (SSL_CTX_get_app_data(ctx) != (void *)(uintptr_t)0xdeadbeef)
		FAIL("returned app data did not match");

	SSL_CTX_free(ctx);

	PASS();
}

static void
test_ctx_mode(void)
{
	SSL_CTX *ctx;
	long mode, new;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	mode = SSL_CTX_get_mode(ctx);
	dprintf("initial mode: %#lx\n", mode);

	new = SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	dprintf("mode after set: %#lx\n", new);

	if (SSL_CTX_get_mode(ctx) != new) {
		SSL_CTX_free(ctx);
		FAIL("failed to get updated mode after set");
	}

	new = SSL_CTX_clear_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	dprintf("mode after clear: %#lx\n", new);

	if (SSL_CTX_get_mode(ctx) != new) {
		SSL_CTX_free(ctx);
		FAIL("failed to get updated mode after clear");
	}

	if (new != mode) {
		SSL_CTX_free(ctx);
		FAIL("final mode doesn't match initial mode\n");
	}

	SSL_CTX_free(ctx);

	PASS();
}

static void
test_ssl_create(void)
{
	SSL_CTX *ctx;
	SSL *ssl;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		FAIL("failed to create session");
	}

	SSL_free(ssl);

	SSL_CTX_free(ctx);

	PASS();
}

static void
test_ssl_refs(void)
{
	SSL_CTX *ctx;
	SSL *ssl;

	ctx = SSL_CTX_new(TLS_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create context");
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		FAIL("failed to create session");
	}
	SSL_CTX_free(ctx);

	if (SSL_up_ref(ssl) != 1) {
		ERR_print_errors_fp(stdout);
		SSL_free(ssl);
		FAIL("failed to increment ref count");
	}

	SSL_free(ssl);
	SSL_free(ssl);

	PASS();
}

static bool
create_ssl_contexts(SSL_CTX **cctx, SSL_CTX **sctx)
{
	SSL_CTX *ctx1, *ctx2;

	ctx1 = NULL;
	ctx2 = NULL;

	ctx1 = SSL_CTX_new(TLS_client_method());
	if (ctx1 == NULL)
		goto error;
	ctx2 = SSL_CTX_new(TLS_server_method());
	if (ctx2 == NULL)
		goto error;

	if (cert != NULL && privkey != NULL) {
		if (SSL_CTX_use_certificate_file(ctx2, cert,
		    SSL_FILETYPE_PEM) != 1)
			goto error;
		if (SSL_CTX_use_PrivateKey_file(ctx2, privkey,
		    SSL_FILETYPE_PEM) != 1)
			goto error;
		if (SSL_CTX_check_private_key(ctx2) != 1)
			goto error;
	}

	*cctx = ctx1;
	*sctx = ctx2;
	return (true);

error:
	SSL_CTX_free(ctx1);
	SSL_CTX_free(ctx2);
	return (false);
}

static bool
create_ssl_memory_sessions(SSL_CTX *cctx, SSL_CTX *sctx, SSL **cssl, SSL **sssl)
{
	BIO *bio1, *bio2;
	SSL *ssl1, *ssl2;

	bio1 = NULL;
	bio2 = NULL;
	ssl1 = NULL;
	ssl2 = NULL;

	bio1 = BIO_new(BIO_s_mem());
	if (bio1 == NULL)
		goto error;
	BIO_set_mem_eof_return(bio1, -1);

	bio2 = BIO_new(BIO_s_mem());
	if (bio2 == NULL)
		goto error;
	BIO_set_mem_eof_return(bio2, -1);

	ssl1 = SSL_new(cctx);
	if (ssl1 == NULL)
		goto error;
	if (BIO_up_ref(bio1) != 1)
		goto error;
	SSL_set0_rbio(ssl1, bio1);
	if (BIO_up_ref(bio2) != 1)
		goto error;
	SSL_set0_wbio(ssl1, bio2);

	ssl2 = SSL_new(sctx);
	if (ssl2 == NULL)
		goto error;
	SSL_set0_rbio(ssl2, bio2);
	SSL_set0_wbio(ssl2, bio1);

	*cssl = ssl1;
	*sssl = ssl2;
	return (true);

error:
	SSL_free(ssl2);
	SSL_free(ssl1);
	BIO_free(bio2);
	BIO_free(bio1);
	return (false);
}

static bool
establish_sessions(SSL *cssl, SSL *sssl)
{
	bool connected, accepted;
	int error, ret;

	connected = false;
	accepted = false;
	while (!connected && !accepted) {
		while (!connected) {
			ret = SSL_connect(cssl);
			if (ret == 1) {
				connected = true;
				break;
			}
			error = SSL_get_error(cssl, ret);
			if (error == SSL_ERROR_WANT_WRITE)
				continue;
			if (error == SSL_ERROR_WANT_READ)
				break;
			dprintf("error from SSL_connect\n");
			return (false);
		}

		while (!accepted) {
			ret = SSL_accept(sssl);
			if (ret == 1) {
				accepted = true;
				break;
			}
			error = SSL_get_error(sssl, ret);
			if (error == SSL_ERROR_WANT_WRITE)
				continue;
			if (error == SSL_ERROR_WANT_READ)
				break;
			dprintf("error from SSL_accept\n");
			return (false);
		}
	}
	return (true);
}

static bool
send_message(SSL *source, SSL *dest, const char *source_name,
    const char *dest_name, const void *message, size_t len)
{
	char buf[len];
	int error, ret;

	ret = SSL_write(source, message, len);
	if (ret <= 0) {
		dprintf("unexpected error %d from %s write\n",
		    SSL_get_error(source, ret), source_name);
		return (false);
	}
	if (ret != len) {
		dprintf("short write to %s\n", dest_name);
		return (false);
	}

	memset(buf, 0xa5, len);
	for (;;) {
		ret = SSL_read(dest, buf, len);
		if (ret <= 0) {
			error = SSL_get_error(dest, ret);
			if (error == SSL_ERROR_WANT_READ)
				continue;
			dprintf("unexpected error %d from %s read\n", error,
			    dest_name);
			return (false);
		}
		if (ret != len) {
			dprintf("short read from %s\n", source_name);
			return (false);
		}
		break;
	}
	if (memcmp(buf, message, len) != 0) {
		dprintf("%s received incorrect data\n", dest_name);
		return (false);
	}
	return (true);
}

static bool
ping_pong_message(SSL *cssl, SSL *sssl, const void *message, size_t len)
{

	if (!send_message(cssl, sssl, "client", "server", message, len))
		return (false);
	return (send_message(sssl, cssl, "server", "client", message, len));
}

static void
test_ssl_memory_ping_pong(void)
{
	SSL_CTX *cctx, *sctx;
	SSL *cssl, *sssl;

	if (!create_ssl_contexts(&cctx, &sctx)) {
		ERR_print_errors_fp(stdout);
		FAIL("failed to create contexts");
	}

	if (!create_ssl_memory_sessions(cctx, sctx, &cssl, &sssl)) {
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(cctx);
		SSL_CTX_free(sctx);
		FAIL("failed to create sessions");
	}
	SSL_CTX_free(cctx);
	SSL_CTX_free(sctx);

	if (show_messages) {
		SSL_set_msg_callback(cssl, msg_cb);
		SSL_set_msg_callback_arg(cssl, "C");
		SSL_set_msg_callback(sssl, msg_cb);
		SSL_set_msg_callback_arg(sssl, "S");
	}

	if (!establish_sessions(cssl, sssl)) {
		ERR_print_errors_fp(stdout);
		SSL_free(cssl);
		SSL_free(sssl);
		FAIL("failed to establish sessions");
	}

	if (!ping_pong_message(cssl, sssl, short_message,
	    strlen(short_message))) {
		ERR_print_errors_fp(stdout);
		SSL_free(cssl);
		SSL_free(sssl);
		FAIL("failed to pass messages");
	}

	SSL_free(cssl);
	SSL_free(sssl);

	PASS();
}

int
main(int ac, char **av)
{
	int ch;

	while ((ch = getopt(ac, av, "c:k:mv")) != -1)
		switch (ch) {
		case 'c':
			cert = optarg;
			break;
		case 'k':
			privkey = optarg;
			break;
		case 'm':
			show_messages = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}

	test_ctx_create();
	test_ctx_refs();
	test_ctx_options();
	test_ctx_proto_versions();
	test_ctx_app_data();
	test_ctx_mode();
	test_ssl_create();
	test_ssl_refs();
	test_ssl_memory_ping_pong();

	return (0);
}
