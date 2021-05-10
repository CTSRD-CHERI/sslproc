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

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "sslproc.h"
#include "sslproc_internal.h"
#include "ControlSocket.h"

PSSL_CTX *
PSSL_CTX_new(const PSSL_METHOD *method)
{
	POPENSSL_init_ssl();

	PSSL_CTX *ctx = new PSSL_CTX();
	if (ctx == nullptr) {
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return (nullptr);
	}

	if (CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, &ctx->ex_data) !=
	    1) {
		free(ctx);
		return (nullptr);
	}

	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds) == -1) {
		int save_error = errno;

		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		free(ctx);
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "socketpair: ", strerror(save_error));
		return (nullptr);
	}

	/*
	 * This doesn't use posix_spawn due to a lack of
	 * posix_spawn_file_actions_addclosefrom().
	 */
	pid_t pid = vfork();
	if (pid == -1) {
		int save_error = errno;

		close(fds[0]);
		close(fds[1]);
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		free(ctx);
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "vfork: ", strerror(save_error));
		return (nullptr);
	}

	if (pid == 0) {
		/* child */
		if (dup2(fds[1], 3) == -1)
			exit(127);
		closefrom(4);
		execlp("sslproc", "sslproc", NULL);
		exit(127);
	}

	close(fds[1]);

	ctx->cs = new ControlSocket(fds[0]);
	if (!ctx->cs->init() || !ctx->cs->createContext(method)) {
		delete ctx->cs;
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		free(ctx);
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		return (nullptr);
	}

	ctx->refs = 1;
	return (ctx);
}

int
PSSL_CTX_up_ref(PSSL_CTX *ctx)
{
	int refs;

	refs = ctx->refs;
	for (;;) {
		if (refs == INT_MAX)
			return (0);
		if (ctx->refs.compare_exchange_weak(refs, refs + 1,
		    std::memory_order_relaxed))
			return (1);
	}
}

void
PSSL_CTX_free(PSSL_CTX *ctx)
{
	if (ctx->refs.fetch_sub(1, std::memory_order_relaxed) > 1)
		return;

	delete ctx->cs;
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, &ctx->ex_data);
	free(ctx);
}

long
PSSL_CTX_set_options(PSSL_CTX *ctx, long options)
{
	return (ctx->cs->setContextOptions(options));
}

long
PSSL_CTX_clear_options(PSSL_CTX *ctx, long options)
{
	return (ctx->cs->clearContextOptions(options));
}

long
PSSL_CTX_get_options(PSSL_CTX *ctx)
{
	return (ctx->cs->getContextOptions());
}

long
PSSL_CTX_ctrl(PSSL_CTX *ctx, int cmd, long larg, void *parg)
{
	switch (cmd) {
	case SSL_CTRL_SET_MIN_PROTO_VERSION:
	case SSL_CTRL_SET_MAX_PROTO_VERSION:
	case SSL_CTRL_GET_MIN_PROTO_VERSION:
	case SSL_CTRL_GET_MAX_PROTO_VERSION:
	case SSL_CTRL_MODE:
	case SSL_CTRL_CLEAR_MODE:
		return (ctx->cs->contextControl(cmd, larg));
	default:
		abort();
	}
}

int
PSSL_CTX_set_ex_data(PSSL_CTX *ctx, int idx, void *data)
{
	return (CRYPTO_set_ex_data(&ctx->ex_data, idx, data));
}

void *
PSSL_CTX_get_ex_data(const PSSL_CTX *ctx, int idx)
{
	return (CRYPTO_get_ex_data(&ctx->ex_data, idx));
}
