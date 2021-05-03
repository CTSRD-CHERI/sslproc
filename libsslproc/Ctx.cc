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

#include "sslproc.h"
#include "sslproc_internal.h"
#include "ControlSocket.h"

PSSL_CTX *
PSSL_CTX_new(const PSSL_METHOD *method)
{
	PSSL_CTX *ctx = new PSSL_CTX();
	if (ctx == nullptr)
		return (nullptr);

	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, fds) == -1) {
		free(ctx);
		return (nullptr);
	}

	/*
	 * This doesn't use posix_spawn due to a lack of
	 * posix_spawn_file_actions_addclosefrom().
	 */
	pid_t pid = vfork();
	if (pid == -1) {
		close(fds[0]);
		close(fds[1]);
		free(ctx);
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
	if (!ctx->cs->init()) {
		delete ctx->cs;
		free(ctx);
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
