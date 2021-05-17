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

#include <unistd.h>

#include <openssl/ssl.h>

#include "sslproc.h"
#include "sslproc_internal.h"
#include "ControlSocket.h"
#include "SSLSession.h"

PSSL *
PSSL_new(PSSL_CTX *ctx)
{
	POPENSSL_init_ssl();

	if (ctx == nullptr) {
		PROCerr(PROC_F_SSL_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return (nullptr);
	}

	if (PSSL_CTX_up_ref(ctx) != 1) {
		PROCerr(PROC_F_SSL_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to add context reference");
		return (nullptr);
	}

	PSSL *ssl = new PSSL();
	if (ssl == nullptr) {
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
		return (nullptr);
	}

	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds) == -1) {
		int save_error = errno;

		delete ssl;
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "socketpair: ", strerror(save_error));
		return (nullptr);
	}

	if (!ctx->cs->createSession(fds[1])) {
		close(fds[0]);
		close(fds[1]);
		delete ssl;
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to create remote session");
		return (nullptr);
	}
	close(fds[1]);

	ssl->ss = new SSLSession(ssl, fds[0]);
	if (!ssl->ss->init()) {
		delete ssl->ss;
		delete ssl;
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		return (nullptr);
	}

	ssl->ctx = ctx;
	ssl->rbio = nullptr;
	ssl->wbio = nullptr;
	ssl->refs = 1;
	return (ssl);
}

int
PSSL_up_ref(PSSL *ssl)
{
	int refs;

	refs = ssl->refs;
	for (;;) {
		if (refs == INT_MAX)
			return (0);
		if (ssl->refs.compare_exchange_weak(refs, refs + 1,
		    std::memory_order_relaxed))
			return (1);
	}
}

void
PSSL_free(PSSL *ssl)
{
	if (ssl->refs.fetch_sub(1, std::memory_order_relaxed) > 1)
		return;

	PSSL_CTX *ctx = ssl->ctx;
	delete ssl->ss;
	BIO_free_all(ssl->wbio);
	BIO_free_all(ssl->rbio);
	delete ssl;
	PSSL_CTX_free(ctx);
}

long
PSSL_ctrl(PSSL *ssl, int cmd, long larg, void *parg)
{
	long ret;

	switch (cmd) {
	case SSL_CTRL_SET_MSG_CALLBACK_ARG:
		ssl->msg_cb_arg = parg;
		ret = 1;
		break;
	default:
		abort();
	}
	return (ret);
}

void
PSSL_set_msg_callback(PSSL *ssl, void (*cb)(int, int, int, const void *,
    size_t, PSSL *, void *))
{
	if (ssl->msg_cb == cb)
		return;
	if (ssl->msg_cb == NULL) {
		ssl->msg_cb = cb;
		ssl->ss->waitForReply(SSLPROC_ENABLE_MSG_CB);
	} else if (cb == NULL) {
		ssl->ss->waitForReply(SSLPROC_DISABLE_MSG_CB);
		ssl->msg_cb = NULL;
	} else
		ssl->msg_cb = cb;
}

BIO *
PSSL_get_rbio(PSSL *ssl)
{
	return (ssl->rbio);
}

BIO *
PSSL_get_wbio(PSSL *ssl)
{
	return (ssl->wbio);
}

void
PSSL_set_bio(PSSL *ssl, BIO *rbio, BIO *wbio)
{

	/* Rule 1 */
	if (ssl->rbio == rbio && ssl->wbio == wbio)
		return;

	/* Rule 2 */
	if (rbio != wbio && rbio != ssl->rbio && wbio != ssl->wbio) {
		PSSL_set0_rbio(ssl, rbio);
		PSSL_set0_wbio(ssl, wbio);
		return;
	}

	if (rbio == wbio) {
		/* Rule 3 */
		if (rbio != ssl->rbio) {
			if (rbio != NULL)
				BIO_up_ref(rbio);
			PSSL_set0_rbio(ssl, rbio);
			PSSL_set0_wbio(ssl, wbio);
			return;
		}

		/* Rule 4 */
		if (wbio != NULL)
			BIO_up_ref(wbio);
		PSSL_set0_wbio(ssl, wbio);
		return;
	}

	/* Rule 5 */
	if (rbio == ssl->rbio) {
		PSSL_set0_wbio(ssl, wbio);
		return;
	}

	/* Rule 6 */
	if (wbio == ssl->wbio && ssl->rbio == ssl->wbio) {
		PSSL_set0_rbio(ssl, wbio);
		return;
	}

	/* Rule 7 */
	PSSL_set0_rbio(ssl, rbio);
	PSSL_set0_wbio(ssl, wbio);
}

void
PSSL_set0_rbio(PSSL *ssl, BIO *rbio)
{
	BIO_free_all(ssl->rbio);
	ssl->rbio = rbio;
}

void
PSSL_set0_wbio(PSSL *ssl, BIO *wbio)
{
	BIO_free_all(ssl->wbio);
	ssl->wbio = wbio;
}

int
PSSL_get_error(const PSSL *ssl, int i)
{
	return (ssl->last_error);
}

int
PSSL_accept(PSSL *ssl)
{
	const Message::Result *msg = ssl->ss->waitForReply(SSLPROC_ACCEPT);
	if (msg == nullptr) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	ssl->last_error = msg->error;
	return (msg->ret);
}

int
PSSL_connect(PSSL *ssl)
{
	const Message::Result *msg = ssl->ss->waitForReply(SSLPROC_CONNECT);
	if (msg == nullptr) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	ssl->last_error = msg->error;
	return (msg->ret);
}

int
PSSL_read(PSSL *ssl, void *buf, int len)
{
	int resid = len;
	const Message::Result *msg = ssl->ss->waitForReply(SSLPROC_READ,
	    &resid, sizeof(resid));
	if (msg == nullptr) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	if (msg->ret > 0) {
		char tmp[16], tmp2[16];

		if (msg->ret != msg->bodyLength()) {
			PROCerr(PROC_F_SSL_READ, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%ld", msg->ret);
			snprintf(tmp2, sizeof(tmp2), "%zu", msg->bodyLength());
			ERR_add_error_data(4, "ret=", tmp, " bodyLength=",
			    tmp2);
			ssl->last_error = SSL_ERROR_SSL;
			return (-1);
		}
		if (msg->ret > len) {
			PROCerr(PROC_F_SSL_READ, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%ld", msg->ret);
			snprintf(tmp2, sizeof(tmp2), "%d", len);
			ERR_add_error_data(4, "long read ret=", tmp, " len=",
			    tmp2);
			ssl->last_error = SSL_ERROR_SSL;
			return (-1);
		}
		memcpy(buf, msg->body(), msg->ret);
	}
	ssl->last_error = msg->error;
	return (msg->ret);
}

int
PSSL_write(PSSL *ssl, const void *buf, int len)
{
	const Message::Result *msg = ssl->ss->waitForReply(SSLPROC_WRITE, buf,
	    len);
	if (msg == nullptr) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	ssl->last_error = msg->error;
	return (msg->ret);
}
