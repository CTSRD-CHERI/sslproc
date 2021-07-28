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

#include "sslproc.h"
#include "sslproc_internal.h"
#include "CommandSocket.h"
#include "TargetStore.h"

PSSL_CONF_CTX *
PSSL_CONF_CTX_new(void)
{
	if (POPENSSL_init_ssl() != 0)
		return (nullptr);

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CONF_CTX_NEW, ERR_R_NO_COMMAND_SOCKET);
		return (nullptr);
	}

	PSSL_CONF_CTX *cctx = new PSSL_CONF_CTX();
	if (cctx == nullptr) {
		PROCerr(PROC_F_SSL_CONF_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(Message::CREATE_CONF_CONTEXT);
	if (!ref) {
		delete cctx;
		PROCerr(PROC_F_SSL_CONF_CTX_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to create remote context");
		return (nullptr);
	}

	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE || msg->bodyLength() != sizeof(int)) {
		delete cctx;
		PROCerr(PROC_F_SSL_CONF_CTX_NEW, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "failed to create remote context");
		return (nullptr);
	}

	cctx->target = *reinterpret_cast<const int *>(msg->body());
	if (!targets.insert(cctx->target, cctx)) {
		cs->waitForReply(Message::FREE_CONF_CONTEXT, cctx->target);
		delete cctx;
		PROCerr(PROC_F_SSL_CONF_CTX_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "duplicate target");
		return (nullptr);
	}

	return (cctx);
}

int
PSSL_CONF_CTX_finish(PSSL_CONF_CTX *cctx)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CONF_CTX_FINISH, ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CONF_CTX_FINISH,
	    cctx->target);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

void
PSSL_CONF_CTX_free(PSSL_CONF_CTX *cctx)
{
	if (cctx == nullptr)
		return;

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();
	MessageRef ref = cs->waitForReply(Message::FREE_CONF_CONTEXT,
	    cctx->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	targets.remove(cctx->target);

	delete cctx;
}

unsigned int
PSSL_CONF_CTX_set_flags(PSSL_CONF_CTX *cctx, unsigned int flags)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();
	MessageRef ref = cs->waitForReply(Message::CONF_CTX_SET_FLAGS,
	    cctx->target, &flags, sizeof(flags));
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	return (ref.result()->ret);
}

int
PSSL_CONF_cmd(PSSL_CONF_CTX *cctx, const char *cmd, const char *value)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CONF_CMD, ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	struct iovec iov[2];
	iov[0].iov_base = const_cast<char *>(cmd);
	iov[0].iov_len = strlen(cmd) + 1;
	iov[1].iov_base = const_cast<char *>(value);
	iov[1].iov_len = strlen(value) + 1;
	MessageRef ref = cs->waitForReply(Message::CONF_CMD, cctx->target,
	    iov, 2);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

int
PSSL_CONF_cmd_value_type(PSSL_CONF_CTX *cctx, const char *cmd)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();
	MessageRef ref = cs->waitForReply(Message::CONF_CMD_VALUE_TYPE,
	    cctx->target, cmd, strlen(cmd));
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	return (ref.result()->ret);
}

void
PSSL_CONF_CTX_set_ssl_ctx(PSSL_CONF_CTX *cctx, PSSL_CTX *ctx)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();
	MessageRef ref = cs->waitForReply(Message::CONF_CTX_SET_SSL_CTX,
	    cctx->target, &ctx->target, sizeof(ctx->target));
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
}
