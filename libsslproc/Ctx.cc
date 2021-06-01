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

#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "sslproc.h"
#include "sslproc_internal.h"
#include "CommandSocket.h"
#include "TargetStore.h"

PSSL_CTX *
PSSL_CTX_new(const PSSL_METHOD *method)
{
	if (POPENSSL_init_ssl() != 0)
		return (nullptr);

	if (method == nullptr) {
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return (nullptr);
	}

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_NO_COMMAND_SOCKET);
		return (nullptr);
	}

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

	MessageRef ref = cs->waitForReply(Message::CREATE_CONTEXT,
	    &method->method, sizeof(method->method));
	if (!ref) {
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		delete ctx;
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to create remote context");
		return (nullptr);
	}

	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE || msg->bodyLength() != sizeof(int)) {
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		delete ctx;
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "failed to create remote context");
		return (nullptr);
	}

	ctx->target = *reinterpret_cast<const int *>(msg->body());
	if (!targets.insert(ctx->target, ctx)) {
		cs->waitForReply(Message::FREE_CONTEXT, ctx->target);
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx,
		    &ctx->ex_data);
		delete ctx;
		PROCerr(PROC_F_SSL_CTX_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "duplicate target");
		return (nullptr);
	}

	ctx->get0_cert = nullptr;
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
	ctx->tmp_dh_cb = nullptr;
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

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();
	MessageRef ref = cs->waitForReply(Message::FREE_CONTEXT, ctx->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	targets.remove(ctx->target);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, &ctx->ex_data);
	X509_free(ctx->get0_cert);
	delete ctx;
}

long
PSSL_CTX_set_options(PSSL_CTX *ctx, long options)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CTX_SET_OPTIONS, ctx->target,
	    &options, sizeof(options));

	/* No way to return errors. */
	if (!ref)
		abort();
	const Message::Result *reply = ref.result();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_CTX_clear_options(PSSL_CTX *ctx, long options)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CTX_CLEAR_OPTIONS,
	    ctx->target, &options, sizeof(options));

	/* No way to return errors. */
	if (!ref)
		abort();
	const Message::Result *reply = ref.result();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_CTX_get_options(PSSL_CTX *ctx)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CTX_GET_OPTIONS,
	    ctx->target);

	/* No way to return errors. */
	if (!ref)
		abort();
	const Message::Result *reply = ref.result();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_CTX_ctrl(PSSL_CTX *ctx, int cmd, long larg, void *parg)
{
	CommandSocket *cs = currentCommandSocket();
	Message::CtrlBody body;

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
	{
		if (cs == nullptr)
			abort();
		MessageRef ref = cs->waitForReply(Message::CTX_CTRL,
		    ctx->target, &body, sizeof(body));
		if (!ref)
			abort();
		return (ref.result()->ret);
	}
	case SSL_CTRL_SET_TMP_DH:
	{
		unsigned char *asn1 = nullptr;
		int len = i2d_DHparams(reinterpret_cast<DH *>(parg), &asn1);
		if (len <= 0)
			return (0);

		if (cs == nullptr) {
			PROCerr(PROC_F_SSL_CTX_CTRL, ERR_R_NO_COMMAND_SOCKET);
			return (0);
		}

		struct iovec iov[2];

		iov[0].iov_base = &body;
		iov[0].iov_len = sizeof(body);
		iov[1].iov_base = asn1;
		iov[1].iov_len = len;
		MessageRef ref = cs->waitForReply(Message::CTX_CTRL,
		    ctx->target, iov, 2);
		OPENSSL_free(asn1);
		if (!ref)
			return (0);
		return (ref.result()->ret);
	}
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
	CommandSocket *cs = currentCommandSocket();

	switch (cmd) {
	case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
	{
		if (cs == nullptr)
			abort();
		ctx->servername_cb = (int (*)(PSSL *, int *, void *))cb;
		MessageRef ref = cs->waitForReply(cb == NULL ?
		    Message::CTX_DISABLE_SERVERNAME_CB :
		    Message::CTX_ENABLE_SERVERNAME_CB, ctx->target);
		if (!ref)
			abort();
		return (ref.result()->ret);
	}
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

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_USE_CERTIFICATE_ASN1,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CTX_USE_CERTIFICATE_ASN1,
	    ctx->target, d, len);
	if (!ref)
		return (0);
	return (ref.result()->ret);
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

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_USE_PRIVATEKEY_ASN1,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);
	iov[1].iov_base = const_cast<unsigned char *>(d);
	iov[1].iov_len = len;
	MessageRef ref = cs->waitForReply(Message::CTX_USE_PRIVATEKEY_ASN1,
	    ctx->target, iov, 2);
	if (!ref)
		return (0);
	return (ref.result()->ret);
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
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_CHECK_PRIVATE_KEY,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CTX_CHECK_PRIVATE_KEY,
	    ctx->target);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

void
PSSL_CTX_set_client_hello_cb(PSSL_CTX *ctx, PSSL_client_hello_cb_fn cb,
    void *arg)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	ctx->client_hello_cb = cb;
	ctx->client_hello_cb_arg = arg;
	cs->waitForReply(cb == nullptr ?
	    Message::CTX_DISABLE_CLIENT_HELLO_CB :
	    Message::CTX_ENABLE_CLIENT_HELLO_CB, ctx->target);
}

int
PSSL_CTX_set_srp_username_callback(PSSL_CTX *ctx,
    int (*cb)(PSSL *, int *, void *))
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_SET_SRP_USERNAME_CALLBACK,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	ctx->srp_username_cb = cb;

	MessageRef ref = cs->waitForReply(cb == nullptr ?
	    Message::CTX_DISABLE_SRP_USERNAME_CB :
	    Message::CTX_ENABLE_SRP_USERNAME_CB, ctx->target);
	if (!ref)
		return (0);
	if (ref.result()->error != SSL_ERROR_NONE)
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
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	if (ctx->sess_new_cb == nullptr && ctx->sess_remove_cb == nullptr &&
	    ctx->sess_get_cb == nullptr) {
		if (ctx->sess_cbs_enabled) {
			MessageRef ref = cs->waitForReply(
			    Message::CTX_DISABLE_SESS_CBS, ctx->target);
			if (!ref || ref.result()->error != SSL_ERROR_NONE)
				abort();
			ctx->sess_cbs_enabled = false;
		}
	} else {
		if (!ctx->sess_cbs_enabled) {
			MessageRef ref = cs->waitForReply(
			    Message::CTX_ENABLE_SESS_CBS, ctx->target);
			if (!ref || ref.result()->error != SSL_ERROR_NONE)
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

void
PSSL_CTX_set_tmp_dh_callback(PSSL_CTX *ctx, DH *(*cb)(PSSL *, int, int))
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	ctx->tmp_dh_cb = cb;
	cs->waitForReply(cb == nullptr ? Message::CTX_DISABLE_TMP_DH_CB :
	    Message::CTX_ENABLE_TMP_DH_CB, ctx->target);
}

void
PSSL_CTX_set_info_callback(PSSL_CTX *ctx, void (*cb)(const PSSL *, int, int))
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	ctx->info_cb = cb;
	cs->waitForReply(cb == nullptr ? Message::CTX_DISABLE_INFO_CB :
	    Message::CTX_ENABLE_INFO_CB, ctx->target);
}

void
PSSL_CTX_set_alpn_select_cb(PSSL_CTX *ctx, PSSL_CTX_alpn_select_cb_func cb,
    void *arg)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	ctx->alpn_select_cb = cb;
	ctx->alpn_select_cb_arg = arg;
	cs->waitForReply(cb == nullptr ? Message::CTX_DISABLE_ALPN_SELECT_CB :
	    Message::CTX_ENABLE_ALPN_SELECT_CB, ctx->target);
}

int
PSSL_CTX_set_cipher_list(PSSL_CTX *ctx, const char *s)
{
	if (s == nullptr) {
		PROCerr(PROC_F_SSL_CTX_SET_CIPHER_LIST,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_SET_CIPHER_LIST,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CTX_SET_CIPHER_LIST,
	    ctx->target, s, strlen(s));
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

int
PSSL_CTX_set_ciphersuites(PSSL_CTX *ctx, const char *s)
{
	if (s == nullptr) {
		PROCerr(PROC_F_SSL_CTX_SET_CIPHERSUITES,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_SET_CIPHERSUITES,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CTX_SET_CIPHERSUITES,
	    ctx->target, s, strlen(s));
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

long
PSSL_CTX_set_timeout(PSSL_CTX *ctx, long time)
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CTX_SET_TIMEOUT, ctx->target,
	    &time, sizeof(time));
	if (!ref)
		abort();
	return (ref.result()->ret);
}

/*
 * This function doesn't return a reference to the caller.  Instead,
 * let this instance hang around until either the next call to this
 * function or until the context is freed.
 */
X509 *
PSSL_CTX_get0_certificate(const PSSL_CTX *ctxc)
{
	PSSL_CTX *ctx = const_cast<PSSL_CTX *>(ctxc);

	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CTX_GET0_CERTIFICATE,
		    ERR_R_NO_COMMAND_SOCKET);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CTX_GET0_CERTIFICATE,
	    ctx->target);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() == 0) {
		PROCerr(PROC_F_SSL_CTX_GET0_CERTIFICATE, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "empty reply body");
		return (nullptr);
	}
	const unsigned char *data =
	    reinterpret_cast<const unsigned char *>(msg->body());
	X509 *cert = d2i_X509(NULL, &data, msg->bodyLength());
	if (cert == nullptr)
		return (nullptr);
	X509_free(ctx->get0_cert);
	ctx->get0_cert = cert;
	return (cert);
}

void
PSSL_CTX_set_client_cert_cb(PSSL_CTX *ctx,
    int (*cb)(PSSL *, X509 **, EVP_PKEY **))
{
	CommandSocket *cs = currentCommandSocket();
	if (cs == nullptr)
		abort();

	ctx->client_cert_cb = cb;
	cs->waitForReply(cb == nullptr ? Message::CTX_DISABLE_CLIENT_CERT_CB :
	    Message::CTX_ENABLE_CLIENT_CERT_CB, ctx->target);
}
