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
		delete ctx;
		return (nullptr);
	}

	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds) == -1) {
		int save_error = errno;

		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		delete ctx;
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
		delete ctx;
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
		delete ctx;
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		return (nullptr);
	}

	ctx->servername_cb = nullptr;
	ctx->servername_cb_arg = nullptr;
	ctx->client_hello_cb = nullptr;
	ctx->client_hello_cb_arg = nullptr;
	ctx->srp_username_cb = nullptr;
	ctx->srp_cb_arg = nullptr;
	ctx->sess_new_cb = nullptr;
	ctx->sess_remove_cb = nullptr;
	ctx->sess_get_cb = nullptr;
	ctx->sess_cbs_enabled = false;
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
	delete ctx;
}

long
PSSL_CTX_set_options(PSSL_CTX *ctx, long options)
{
	const Message::Result *reply = ctx->cs->waitForReply(
	    SSLPROC_CTX_SET_OPTIONS, &options, sizeof(options));

	/* No way to return errors. */
	if (reply == nullptr)
		abort();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_CTX_clear_options(PSSL_CTX *ctx, long options)
{
	const Message::Result *reply = ctx->cs->waitForReply(
	    SSLPROC_CTX_CLEAR_OPTIONS, &options, sizeof(options));

	/* No way to return errors. */
	if (reply == nullptr)
		abort();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_CTX_get_options(PSSL_CTX *ctx)
{
	const Message::Result *reply = ctx->cs->waitForReply(
	    SSLPROC_CTX_GET_OPTIONS);

	/* No way to return errors. */
	if (reply == nullptr)
		abort();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_CTX_ctrl(PSSL_CTX *ctx, int cmd, long larg, void *parg)
{
	Message::CtrlBody body;
	const Message::Result *reply;

	body.cmd = cmd;
	body.larg = larg;
	switch (cmd) {
	case SSL_CTRL_SET_MIN_PROTO_VERSION:
	case SSL_CTRL_SET_MAX_PROTO_VERSION:
	case SSL_CTRL_GET_MIN_PROTO_VERSION:
	case SSL_CTRL_GET_MAX_PROTO_VERSION:
	case SSL_CTRL_MODE:
	case SSL_CTRL_CLEAR_MODE:
	case SSL_CTRL_SET_SESS_CACHE_MODE:
	case SSL_CTRL_GET_SESS_CACHE_MODE:
		reply = ctx->cs->waitForReply(SSLPROC_CTX_CTRL, &body,
		    sizeof(body));
		if (reply == nullptr)
			abort();
		return (reply->ret);
	case SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG:
		ctx->servername_cb_arg = parg;
		return (1);
	default:
		abort();
	}
}

long
PSSL_CTX_callback_ctrl(PSSL_CTX *ctx, int cmd, void (*cb)(void))
{
	const Message::Result *msg;

	switch (cmd) {
	case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
		ctx->servername_cb = (int (*)(PSSL *, int *, void *))cb;
		msg = ctx->cs->waitForReply(cb == NULL ?
		    SSLPROC_CTX_DISABLE_SERVERNAME_CB :
		    SSLPROC_CTX_ENABLE_SERVERNAME_CB);
		if (msg == nullptr)
			abort();
		return (msg->ret);
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

int
PSSL_CTX_use_certificate(PSSL_CTX *ctx, X509 *x)
{
	unsigned char *buf;
	int len, ret;

	buf = NULL;
	len = i2d_X509(x, &buf);
	if (len < 0) {
		PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to encode X509");
		return (0);
	}

	ret = PSSL_CTX_use_certificate_ASN1(ctx, len, buf);
	OPENSSL_free(buf);
	return (ret);
}

int
PSSL_CTX_use_certificate_ASN1(PSSL_CTX *ctx, int len, unsigned char *d)
{
	if (d == NULL) {
		PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE_ASN1,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	const Message::Result *reply = ctx->cs->waitForReply(
	    SSLPROC_CTX_USE_CERTIFICATE_ASN1, d, len);
	if (reply == nullptr)
		return (0);
	return (reply->ret);
}

int
PSSL_CTX_use_certificate_file(PSSL_CTX *ctx, const char *file, int type)
{
	BIO *bio;
	X509 *x;
	char tmp[16];
	int ret;

	bio = BIO_new_file(file, "r");
	if (bio == NULL) {
		PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE_FILE,
		    ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "failed to open file ", file);
		return (0);
	}

	switch (type) {
	case SSL_FILETYPE_PEM:
		x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (x == NULL)
			PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE_FILE,
			    ERR_R_PEM_LIB);
		break;
	case SSL_FILETYPE_ASN1:
		x = d2i_X509_bio(bio, NULL);
		if (x == NULL)
			PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE_FILE,
			    ERR_R_ASN1_LIB);
		break;
	default:
		x = NULL;
		PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE_FILE,
		    ERR_R_PASSED_INVALID_ARGUMENT);
		snprintf(tmp, sizeof(tmp), "%d", type);
		ERR_add_error_data(2, "type=", tmp);
		break;
	}
	BIO_free_all(bio);
	if (x == NULL)
		return (0);
	ret = PSSL_CTX_use_certificate(ctx, x);
	X509_free(x);
	return (ret);
}

int
PSSL_CTX_use_PrivateKey(PSSL_CTX *ctx, EVP_PKEY *pkey)
{
	unsigned char *buf;
	int len, ret;

	buf = NULL;
	len = i2d_PrivateKey(pkey, &buf);
	if (len < 0) {
		PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to encode private key");
		return (0);
	}

	ret = PSSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_base_id(pkey), ctx, buf,
	    len);
	OPENSSL_free(buf);
	return (ret);
}

int
PSSL_CTX_use_PrivateKey_ASN1(int type, PSSL_CTX *ctx, const unsigned char *d,
    int len)
{
	struct iovec iov[2];

	if (d == NULL) {
		PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY_ASN1,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);
	iov[1].iov_base = const_cast<unsigned char *>(d);
	iov[1].iov_len = len;
	const Message::Result *reply = ctx->cs->waitForReply(
	    SSLPROC_CTX_USE_PRIVATEKEY_ASN1, iov, 2);
	if (reply == nullptr)
		return (0);
	return (reply->ret);
}

int
PSSL_CTX_use_PrivateKey_file(PSSL_CTX *ctx, const char *file, int type)
{
	BIO *bio;
	EVP_PKEY *pkey;
	char tmp[16];
	int ret;

	bio = BIO_new_file(file, "r");
	if (bio == NULL) {
		PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY_FILE,
		    ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "failed to open file ", file);
		return (0);
	}

	switch (type) {
	case SSL_FILETYPE_PEM:
		pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
		if (pkey == NULL)
			PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY_FILE,
			    ERR_R_PEM_LIB);
		break;
	case SSL_FILETYPE_ASN1:
		pkey = d2i_PrivateKey_bio(bio, NULL);
		if (pkey == NULL)
			PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY_FILE,
			    ERR_R_ASN1_LIB);
		break;
	default:
		pkey = NULL;
		PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY_FILE,
		    ERR_R_PASSED_INVALID_ARGUMENT);
		snprintf(tmp, sizeof(tmp), "%d", type);
		ERR_add_error_data(2, "type=", tmp);
		break;
	}
	BIO_free_all(bio);
	if (pkey == NULL)
		return (0);
	ret = PSSL_CTX_use_PrivateKey(ctx, pkey);
	EVP_PKEY_free(pkey);
	return (ret);
}

int
PSSL_CTX_check_private_key(PSSL_CTX *ctx)
{
	const Message::Result *reply = ctx->cs->waitForReply(
	    SSLPROC_CTX_CHECK_PRIVATE_KEY);
	if (reply == nullptr)
		return (0);
	return (reply->ret);
}

void
PSSL_CTX_set_client_hello_cb(PSSL_CTX *ctx, PSSL_client_hello_cb_fn cb,
    void *arg)
{

	ctx->client_hello_cb = cb;
	ctx->client_hello_cb_arg = arg;
	(void)ctx->cs->waitForReply(cb == nullptr ?
	    SSLPROC_CTX_DISABLE_CLIENT_HELLO_CB :
	    SSLPROC_CTX_ENABLE_CLIENT_HELLO_CB);
}

int
PSSL_CTX_set_srp_username_callback(PSSL_CTX *ctx,
    int (*cb)(PSSL *, int *, void *))
{
	ctx->srp_username_cb = cb;

	const Message::Result *msg = ctx->cs->waitForReply(cb == nullptr ?
	    SSLPROC_CTX_DISABLE_SRP_USERNAME_CB :
	    SSLPROC_CTX_ENABLE_SRP_USERNAME_CB);
	if (msg == nullptr)
		return (0);
	if (msg->error != SSL_ERROR_NONE)
		return (0);
	return (1);
}

int
PSSL_CTX_set_srp_cb_arg(PSSL_CTX *ctx, void *arg)
{
	ctx->srp_cb_arg = arg;
	return (1);
}

static void
PSSL_CTX_sess_callbacks_updated(PSSL_CTX *ctx)
{
	if (ctx->sess_new_cb == nullptr && ctx->sess_remove_cb == nullptr &&
	    ctx->sess_get_cb == nullptr) {
		if (ctx->sess_cbs_enabled) {
			const Message::Result *msg = ctx->cs->waitForReply(
			    SSLPROC_CTX_DISABLE_SESS_CBS);
			if (msg == nullptr || msg->error != SSL_ERROR_NONE)
				abort();
			ctx->sess_cbs_enabled = false;
		}
	} else {
		if (!ctx->sess_cbs_enabled) {
			const Message::Result *msg = ctx->cs->waitForReply(
			    SSLPROC_CTX_ENABLE_SESS_CBS);
			if (msg == nullptr || msg->error != SSL_ERROR_NONE)
				abort();
			ctx->sess_cbs_enabled = true;
		}
	}
}

void
PSSL_CTX_sess_set_new_cb(PSSL_CTX *ctx, int (*cb)(PSSL *, PSSL_SESSION *))
{
	ctx->sess_new_cb = cb;
	PSSL_CTX_sess_callbacks_updated(ctx);
}

void
PSSL_CTX_sess_set_remove_cb(PSSL_CTX *ctx,
    void (*cb)(PSSL_CTX *, PSSL_SESSION *))
{
	ctx->sess_remove_cb = cb;
	PSSL_CTX_sess_callbacks_updated(ctx);
}

void
PSSL_CTX_sess_set_get_cb(PSSL_CTX *ctx,
    PSSL_SESSION * (*cb)(PSSL *, const unsigned char *, int, int *))
{
	ctx->sess_get_cb = cb;
	PSSL_CTX_sess_callbacks_updated(ctx);
}
