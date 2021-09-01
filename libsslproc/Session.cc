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
#include <syslog.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/asn1t.h>

#include "sslproc.h"
#include "sslproc_internal.h"
#include "MessageHelpers.h"
#include "CommandChannel.h"
#include "TargetStore.h"

/* XXX: The normal version of this does not work with C++. */
#undef M_ASN1_free_of
#define	M_ASN1_free_of(x, type) \
	ASN1_item_free(reinterpret_cast<ASN1_VALUE *>(x), ASN1_ITEM_rptr(type))

PSSL_SESSION *
PSSL_SESSION_new(void)
{
	PSSL_SESSION *s;

	s = new PSSL_SESSION();
	s->target = NULL_TARGET;
	s->id = nullptr;
	s->id_len = 0;
	s->internal_repr = nullptr;
	s->internal_length = 0;
	s->refs = 1;
	return (s);
}

int
PSSL_SESSION_up_ref(PSSL_SESSION *s)
{
	int refs;

	refs = s->refs;
	for (;;) {
		if (refs == INT_MAX)
			return (0);
		if (s->refs.compare_exchange_weak(refs, refs + 1,
		    std::memory_order_relaxed))
			return (1);
	}
}

void
PSSL_SESSION_free(PSSL_SESSION *s)
{
	if (s == nullptr)
		return;

	if (s->refs.fetch_sub(1, std::memory_order_relaxed) > 1)
		return;

	free(s->id);
	free(s->internal_repr);
	delete s;
}

const unsigned char *
PSSL_SESSION_get_id(const PSSL_SESSION *s, unsigned int *len)
{
	if (len != nullptr)
		*len = s->id_len;
	return (s->id);
}

unsigned int
PSSL_SESSION_get_compress_id(const PSSL_SESSION *s)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SESSION_GET_COMPRESS_ID,
	    s->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	if (msg->bodyLength() != sizeof(unsigned int))
		abort();
	return (*reinterpret_cast<const unsigned int *>(msg->body()));
}

long
PSSL_SESSION_get_time(const PSSL_SESSION *s)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SESSION_GET_TIME, s->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	if (msg->bodyLength() != sizeof(long))
		abort();
	return (*reinterpret_cast<const long *>(msg->body()));
}

int
PSSL_SESSION_set_timeout(PSSL_SESSION *s, long tm)
{
	if (s == nullptr)
		return (0);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SESSION_SET_TIMEOUT,
	    s->target, &tm, sizeof(tm));
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	return (1);
}

#define	PSSL_SESSION_ASN1_VERSION	1

typedef struct {
	uint32_t version;
	ASN1_OCTET_STRING *id;
	ASN1_OCTET_STRING *internal;
} PSSL_SESSION_ASN1;

ASN1_SEQUENCE(PSSL_SESSION_ASN1) = {
	ASN1_EMBED(PSSL_SESSION_ASN1, version, UINT32),
	ASN1_SIMPLE(PSSL_SESSION_ASN1, id, ASN1_OCTET_STRING),
	ASN1_SIMPLE(PSSL_SESSION_ASN1, internal, ASN1_OCTET_STRING)
} static_ASN1_SEQUENCE_END(PSSL_SESSION_ASN1)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(PSSL_SESSION_ASN1);

PSSL_SESSION *
d2i_PSSL_SESSION(PSSL_SESSION **a, const unsigned char **pp,
    long length)
{
	PSSL_SESSION *s = nullptr;
	const unsigned char *p = *pp;
	PSSL_SESSION_ASN1 *as = d2i_PSSL_SESSION_ASN1(nullptr, &p, length);
	if (as == nullptr)
		goto error;

	if (a == nullptr || *a == nullptr) {
		s = PSSL_SESSION_new();
		if (s == nullptr)
			goto error;
	} else
		s = *a;

	if (as->version != PSSL_SESSION_ASN1_VERSION) {
		PROCerr(PROC_F_D2I_SSL_SESSION, ERR_R_BAD_VERSION);
		goto error;
	}

	free(s->id);
	free(s->internal_repr);

	s->id_len = as->id->length;
	s->id = reinterpret_cast<unsigned char *>(malloc(s->id_len));
	memcpy(s->id, as->id->data, s->id_len);
	s->internal_length = as->internal->length;
	s->internal_repr = reinterpret_cast<unsigned char *>
	    (malloc(s->internal_length));
	memcpy(s->internal_repr, as->internal->data, s->internal_length);

	M_ASN1_free_of(as, PSSL_SESSION_ASN1);

	if (a != nullptr)
		*a = s;
	*pp = p;
	return (s);
error:
	M_ASN1_free_of(as, PSSL_SESSION_ASN1);
	if (a == nullptr || *a == nullptr)
		PSSL_SESSION_free(s);
	return (nullptr);
}

int
i2d_PSSL_SESSION(PSSL_SESSION *in, unsigned char **pp)
{
	PSSL_SESSION_ASN1 as;
	ASN1_OCTET_STRING id;
	ASN1_OCTET_STRING internal;

	if (in == nullptr)
		return (0);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_I2D_SSL_SESSION, ERR_R_NO_COMMAND_CHANNEL);
		return (-1);
	}

	MessageRef ref = cs->waitForReply(Message::SESSION_GET_ASN1,
	    in->target);
	if (!ref)
		return (-1);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (-1);
	if (msg->bodyLength() == 0)
		return (0);

	memset(&as, 0, sizeof(as));

	as.version = PSSL_SESSION_ASN1_VERSION;
	as.id = &id;
	id.data = in->id;
	id.length = in->id_len;
	id.flags = 0;
	as.internal = &internal;
	internal.data = reinterpret_cast<unsigned char *>
	    (const_cast<void *>(msg->body()));
	internal.length = msg->bodyLength();
	internal.flags = 0;

	return (i2d_PSSL_SESSION_ASN1(&as, pp));
}

PSSL *
PSSL_new(PSSL_CTX *ctx)
{
	if (POPENSSL_init_ssl() != 0)
		return (nullptr);

	if (ctx == nullptr) {
		PROCerr(PROC_F_SSL_NEW, ERR_R_PASSED_NULL_PARAMETER);
		return (nullptr);
	}

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_NEW, ERR_R_NO_COMMAND_CHANNEL);
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

	if (CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, ssl, &ssl->ex_data) != 1) {
		delete ssl;
		PSSL_CTX_free(ctx);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(Message::CREATE_SESSION, ctx->target);
	if (!ref) {
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, ssl, &ssl->ex_data);
		delete ssl;
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to create remote session");
		return (nullptr);
	}

	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE || msg->bodyLength() != sizeof(int)) {
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, ssl, &ssl->ex_data);
		delete ssl;
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_NEW, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "failed to create remote session");
		return (nullptr);
	}

	ssl->target = *reinterpret_cast<const int *>(msg->body());
	if (!targets.insert(ssl->target, ssl)) {
		cs->waitForReply(Message::FREE_SESSION, ssl->target);
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, ssl, &ssl->ex_data);
		delete ssl;
		PSSL_CTX_free(ctx);
		PROCerr(PROC_F_SSL_NEW, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "duplicate target");
		return (nullptr);
	}

	ssl->ctx = ctx;
	ssl->rbio = nullptr;
	ssl->wbio = nullptr;
	ssl->servername = nullptr;
	ssl->srp_username = nullptr;
	ssl->srp_userinfo = nullptr;
	ssl->get_ciphers = nullptr;
	ssl->get_peer_cert_chain = nullptr;
	ssl->get_cert = nullptr;
	ssl->get_privatekey = nullptr;
	ssl->client_CA_list = nullptr;
	ssl->state_string_long = nullptr;
	ssl->session = nullptr;
	ssl->msg_cb = nullptr;
	ssl->msg_cb_arg = nullptr;
	ssl->verify_cb = ctx->verify_cb;
	ssl->default_passwd_cb = PEM_def_callback;
	ssl->default_passwd_cb_userdata = nullptr;
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
	if (ssl == nullptr)
		return;

	if (ssl->refs.fetch_sub(1, std::memory_order_relaxed) > 1)
		return;

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();
	MessageRef ref = cs->waitForReply(Message::FREE_SESSION, ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	targets.remove(ssl->target);

	PSSL_CTX *ctx = ssl->ctx;
	if (ssl->session != nullptr) {
		cs->waitForReply(Message::SESSION_REMOVE_TARGET,
		    ssl->session->target);
		PSSL_SESSION_free(ssl->session);
	}
	while (!ssl->client_hello_exts.empty()) {
		free(ssl->client_hello_exts.front());
		ssl->client_hello_exts.pop_front();
	}
	free(ssl->state_string_long);
	sk_X509_NAME_pop_free(ssl->client_CA_list, X509_NAME_free);
	EVP_PKEY_free(ssl->get_privatekey);
	X509_free(ssl->get_cert);
	sk_X509_pop_free(ssl->get_peer_cert_chain, X509_free);
	sk_PSSL_CIPHER_free(ssl->get_ciphers);
	free(ssl->srp_userinfo);
	free(ssl->srp_username);
	free(ssl->servername);
	BIO_free_all(ssl->wbio);
	BIO_free_all(ssl->rbio);
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, ssl, &ssl->ex_data);
	delete ssl;
	PSSL_CTX_free(ctx);
}

long
PSSL_set_options(PSSL *ssl, long options)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SET_OPTIONS, ssl->target,
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
PSSL_clear_options(PSSL *ssl, long options)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CLEAR_OPTIONS, ssl->target,
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
PSSL_get_options(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_OPTIONS, ssl->target);

	/* No way to return errors. */
	if (!ref)
		abort();
	const Message::Result *reply = ref.result();
	if (reply->ret != 0)
		abort();
	return (*reinterpret_cast<const long *>(reply->body()));
}

long
PSSL_ctrl(PSSL *ssl, int cmd, long larg, void *parg)
{
	CommandChannel *cs = currentCommandChannel();
	Message::CtrlBody body;

	body.cmd = cmd;
	body.larg = larg;
	switch (cmd) {
	case SSL_CTRL_SET_MSG_CALLBACK_ARG:
		ssl->msg_cb_arg = parg;
		return (1);
	case SSL_CTRL_GET_RI_SUPPORT:
	case SSL_CTRL_SET_CURRENT_CERT:
	{
		if (cs == nullptr)
			abort();
		MessageRef ref = cs->waitForReply(Message::CTRL, ssl->target,
		    &body, sizeof(body));
		if (!ref)
			abort();
		return (ref.result()->ret);
	}
	case SSL_CTRL_SET_TLSEXT_HOSTNAME:
	{
		struct iovec iov[2];
		int cnt;

		if (cs == nullptr) {
			PROCerr(PROC_F_SSL_CTRL, ERR_R_NO_COMMAND_CHANNEL);
			return (0);
		}

		iov[0].iov_base = &body;
		iov[0].iov_len = sizeof(body);
		cnt = 1;
		if (parg != NULL) {
			iov[1].iov_base = parg;
			iov[1].iov_len = strlen(reinterpret_cast<char *>(parg));
			cnt++;
		}

		MessageRef ref = cs->waitForReply(Message::CTRL, ssl->target,
		    iov, cnt);
		if (!ref)
			return (0);
		return (ref.result()->ret);
	}
	case SSL_CTRL_CHAIN:
	{
		STACK_OF(X509) *sk = reinterpret_cast<STACK_OF(X509) *>(parg);

		if (cs == nullptr) {
			PROCerr(PROC_F_SSL_CTRL, ERR_R_NO_COMMAND_CHANNEL);
			return (0);
		}

		SerializedStack stack;
		if (sk != nullptr) {
			stack = sk_X509_serialize(sk);
			if (stack.empty()) {
				PROCerr(PROC_F_SSL_CTRL, ERR_R_INTERNAL_ERROR);
				ERR_add_error_data(1,
				    "failed to serialize certificate chain");
				return (0);
			}
		}

		struct iovec iov[stack.cnt() + 1];

		iov[0].iov_base = &body;
		iov[0].iov_len = sizeof(body);
		memcpy(&iov[1], stack.iov(), stack.cnt() * sizeof(iov[0]));
		MessageRef ref = cs->waitForReply(Message::CTRL, ssl->target,
		    iov, stack.cnt() + 1);
		if (!ref)
			return (0);
		if (ref.result()->error != SSL_ERROR_NONE ||
		    ref.result()->ret != 1)
			return (0);

		/*
		 * Since we don't store the pointer internally, explicitly
		 * free the caller's reference for set0 and don't add a
		 * reference for the internal pointer for set1.
		 */
		if (larg == 0)
			sk_X509_pop_free(sk, X509_free);
		return (1);
	}
	case SSL_CTRL_CHAIN_CERT:
	{
		X509 *x = reinterpret_cast<X509 *>(parg);

		unsigned char *asn1 = nullptr;
		int len = i2d_X509(x, &asn1);
		if (len <= 0)
			return (0);

		if (cs == nullptr) {
			PROCerr(PROC_F_SSL_CTRL, ERR_R_NO_COMMAND_CHANNEL);
			return (0);
		}

		struct iovec iov[2];

		iov[0].iov_base = &body;
		iov[0].iov_len = sizeof(body);
		iov[1].iov_base = asn1;
		iov[1].iov_len = len;
		MessageRef ref = cs->waitForReply(Message::CTRL, ssl->target,
		    iov, 2);
		OPENSSL_free(asn1);
		if (!ref)
			return (0);
		if (ref.result()->error != SSL_ERROR_NONE ||
		    ref.result()->ret != 1)
			return (0);

		/*
		 * Since we don't store the pointer internally, explicitly
		 * free the caller's reference for add0 and don't add a
		 * reference for the internal pointer for add1.
		 */
		if (larg == 0)
			X509_free(x);
		return (1);
	}
	default:
		syslog(LOG_WARNING, "%s: unsupported cmd %d", __func__, cmd);
		abort();
	}
}

int
PSSL_set_ex_data(PSSL *ssl, int idx, void *data)
{
	return (CRYPTO_set_ex_data(&ssl->ex_data, idx, data));
}

void *
PSSL_get_ex_data(const PSSL *ssl, int idx)
{
	return (CRYPTO_get_ex_data(&ssl->ex_data, idx));
}

int
PSSL_use_certificate(PSSL *ssl, X509 *x)
{
	unsigned char *buf;
	int len, ret;

	buf = NULL;
	len = i2d_X509(x, &buf);
	if (len < 0) {
		PROCerr(PROC_F_SSL_USE_CERTIFICATE, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to encode X509");
		return (0);
	}

	ret = PSSL_use_certificate_ASN1(ssl, buf, len);
	OPENSSL_free(buf);
	return (ret);
}

int
PSSL_use_certificate_ASN1(PSSL *ssl, const unsigned char *d, int len)
{
	if (d == NULL) {
		PROCerr(PROC_F_SSL_USE_CERTIFICATE_ASN1,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_USE_CERTIFICATE_ASN1,
		    ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::USE_CERTIFICATE_ASN1,
	    ssl->target, d, len);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

int
PSSL_use_certificate_file(PSSL *ssl, const char *file, int type)
{
	BIO *bio;
	X509 *x;
	char tmp[16];
	int ret;

	bio = BIO_new_file(file, "r");
	if (bio == NULL) {
		PROCerr(PROC_F_SSL_USE_CERTIFICATE_FILE,
		    ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "failed to open file ", file);
		return (0);
	}

	switch (type) {
	case SSL_FILETYPE_PEM:
		x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (x == NULL)
			PROCerr(PROC_F_SSL_USE_CERTIFICATE_FILE,
			    ERR_R_PEM_LIB);
		break;
	case SSL_FILETYPE_ASN1:
		x = d2i_X509_bio(bio, NULL);
		if (x == NULL)
			PROCerr(PROC_F_SSL_USE_CERTIFICATE_FILE,
			    ERR_R_ASN1_LIB);
		break;
	default:
		x = NULL;
		PROCerr(PROC_F_SSL_USE_CERTIFICATE_FILE,
		    ERR_R_PASSED_INVALID_ARGUMENT);
		snprintf(tmp, sizeof(tmp), "%d", type);
		ERR_add_error_data(2, "type=", tmp);
		break;
	}
	BIO_free_all(bio);
	if (x == NULL)
		return (0);
	ret = PSSL_use_certificate(ssl, x);
	X509_free(x);
	return (ret);
}

int
PSSL_use_PrivateKey(PSSL *ssl, EVP_PKEY *pkey)
{
	unsigned char *buf;
	int len, ret;

	buf = NULL;
	len = i2d_PrivateKey(pkey, &buf);
	if (len < 0) {
		PROCerr(PROC_F_SSL_USE_PRIVATEKEY, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to encode private key");
		return (0);
	}

	ret = PSSL_use_PrivateKey_ASN1(EVP_PKEY_base_id(pkey), ssl, buf, len);
	OPENSSL_free(buf);
	return (ret);
}

int
PSSL_use_PrivateKey_ASN1(int type, PSSL *ssl, const unsigned char *d, int len)
{
	struct iovec iov[2];

	if (d == NULL) {
		PROCerr(PROC_F_SSL_USE_PRIVATEKEY_ASN1,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_USE_PRIVATEKEY_ASN1,
		    ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);
	iov[1].iov_base = const_cast<unsigned char *>(d);
	iov[1].iov_len = len;
	MessageRef ref = cs->waitForReply(Message::USE_PRIVATEKEY_ASN1,
	    ssl->target, iov, 2);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

int
PSSL_use_PrivateKey_file(PSSL *ssl, const char *file, int type)
{
	BIO *bio;
	EVP_PKEY *pkey;
	char tmp[16];
	int ret;

	bio = BIO_new_file(file, "r");
	if (bio == NULL) {
		PROCerr(PROC_F_SSL_USE_PRIVATEKEY_FILE,
		    ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "failed to open file ", file);
		return (0);
	}

	switch (type) {
	case SSL_FILETYPE_PEM:
		pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
		if (pkey == NULL)
			PROCerr(PROC_F_SSL_USE_PRIVATEKEY_FILE,
			    ERR_R_PEM_LIB);
		break;
	case SSL_FILETYPE_ASN1:
		pkey = d2i_PrivateKey_bio(bio, NULL);
		if (pkey == NULL)
			PROCerr(PROC_F_SSL_USE_PRIVATEKEY_FILE,
			    ERR_R_ASN1_LIB);
		break;
	default:
		pkey = NULL;
		PROCerr(PROC_F_SSL_USE_PRIVATEKEY_FILE,
		    ERR_R_PASSED_INVALID_ARGUMENT);
		snprintf(tmp, sizeof(tmp), "%d", type);
		ERR_add_error_data(2, "type=", tmp);
		break;
	}
	BIO_free_all(bio);
	if (pkey == NULL)
		return (0);
	ret = PSSL_use_PrivateKey(ssl, pkey);
	EVP_PKEY_free(pkey);
	return (ret);
}

int
PSSL_check_private_key(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CHECK_PRIVATE_KEY, ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::CHECK_PRIVATE_KEY,
	    ssl->target);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

PSSL_CTX *
PSSL_get_SSL_CTX(const PSSL *ssl)
{
	return (ssl->ctx);
}

PSSL_CTX *
PSSL_set_SSL_CTX(PSSL *ssl, PSSL_CTX *ctx)
{
	char tmp[16];

	if (ssl->ctx == ctx)
		return (ctx);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_SET_SSL_CTX, ERR_R_NO_COMMAND_CHANNEL);
		return (nullptr);
	}

	int ctx_target = ctx == nullptr ? NULL_TARGET : ctx->target;
	MessageRef ref = cs->waitForReply(Message::SET_SSL_CTX, ssl->target,
	    &ctx_target, sizeof(ctx_target));
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() != sizeof(ctx_target)) {
		PROCerr(PROC_F_SSL_SET_SSL_CTX, ERR_R_BAD_MESSAGE);
		snprintf(tmp, sizeof(tmp), "%zu", msg->bodyLength());
		ERR_add_error_data(2, "invalid length=", tmp);
		return (nullptr);
	}
	ctx_target = *reinterpret_cast<const int *>(msg->body());

	ctx = targets.lookup<PSSL_CTX>(ctx_target);
	if (ctx == nullptr) {
		PROCerr(PROC_F_SSL_SET_SSL_CTX, ERR_R_MISSING_TARGET);
		snprintf(tmp, sizeof(tmp), "%d", ctx_target);
		ERR_add_error_data(2, "target=", tmp);
		return (nullptr);
	}

	PSSL_CTX_up_ref(ctx);
	PSSL_CTX_free(ssl->ctx);
	ssl->ctx = ctx;
	return (ctx);
}

X509 *
PSSL_get_peer_certificate(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_GET_PEER_CERTIFICATE,
		    ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::GET_PEER_CERTIFICATE,
	    ssl->target);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() == 0) {
		PROCerr(PROC_F_SSL_GET_PEER_CERTIFICATE, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "empty reply body");
		return (nullptr);
	}

	const unsigned char *data =
	    reinterpret_cast<const unsigned char *>(msg->body());
	return (d2i_X509(NULL, &data, msg->bodyLength()));
}

long
PSSL_get_verify_result(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_GET_VERIFY_RESULT, ERR_R_NO_COMMAND_CHANNEL);
		return (X509_V_ERR_UNSPECIFIED);
	}

	MessageRef ref = cs->waitForReply(Message::GET_VERIFY_RESULT,
	    ssl->target);
	if (!ref)
		return (X509_V_ERR_UNSPECIFIED);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (X509_V_ERR_UNSPECIFIED);
	return (msg->ret);
}

void
PSSL_set_verify_result(PSSL *ssl, long result)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	cs->waitForReply(Message::SET_VERIFY_RESULT, ssl->target, &result,
	    sizeof(result));
}

int
PSSL_get_verify_mode(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_VERIFY_MODE,
	    ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	return (ref.result()->ret);
}

int
PSSL_get_verify_depth(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_VERIFY_DEPTH,
	    ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	return (ref.result()->ret);
}

void
PSSL_set_verify(PSSL *ssl, int mode, PSSL_verify_cb cb)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	if (cb != nullptr)
		ssl->verify_cb = cb;

	struct {
		int mode;
		int cb_set;
	} body;

	body.mode = mode;
	body.cb_set = cb != nullptr;
	cs->waitForReply(Message::SET_VERIFY, ssl->target, &body, sizeof(body));
}

int
PSSL_verify_client_post_handshake(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE,
		    ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::VERIFY_CLIENT_POST_HANDSHAKE,
	    ssl->target);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

int
PSSL_set_alpn_protos(PSSL *ssl, const unsigned char *protos, unsigned int len)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SET_ALPN_PROTOS, ssl->target,
	    protos, len);
	if (!ref)
		return (-1);
	return (ref.result()->ret);
}

int
PSSL_set_cipher_list(PSSL *ssl, const char *s)
{
	if (s == nullptr) {
		PROCerr(PROC_F_SSL_SET_CIPHER_LIST,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_SET_CIPHER_LIST, ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::SET_CIPHER_LIST, ssl->target,
	    s, strlen(s));
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

int
PSSL_set_ciphersuites(PSSL *ssl, const char *s)
{
	if (s == nullptr) {
		PROCerr(PROC_F_SSL_SET_CIPHERSUITES,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_SET_CIPHERSUITES, ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::SET_CIPHERSUITES,
	    ssl->target, s, strlen(s));
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

static void
serialize_BIGNUM(struct iovec *iov, const BIGNUM *bn, int len)
{
	len = roundup2(len, 4);
	iov->iov_base = malloc(len);
	iov->iov_len = len;
	int ret = BN_bn2binpad(bn,
	    reinterpret_cast<unsigned char *>(iov->iov_base), len);
	if (ret != len)
		abort();
}

int
PSSL_set_srp_server_param(PSSL *ssl, const BIGNUM *N, const BIGNUM *g,
    BIGNUM *sa, BIGNUM *v, char *info)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		return (-1);

	struct Message::SrpServerParamBody body;
	struct iovec iov[5];

	memset(&body, 0, sizeof(body));
	memset(iov, 0, sizeof(iov));

	if (N != nullptr) {
		body.N_len = BN_num_bytes(N);
		serialize_BIGNUM(&iov[0], N, body.N_len);
	}
	if (g != nullptr) {
		body.g_len = BN_num_bytes(g);
		serialize_BIGNUM(&iov[1], g, body.g_len);
	}
	if (sa != nullptr) {
		body.sa_len = BN_num_bytes(sa);
		serialize_BIGNUM(&iov[2], sa, body.sa_len);
	}
	if (v != nullptr) {
		body.v_len = BN_num_bytes(v);
		serialize_BIGNUM(&iov[3], v, body.v_len);
	}
	if (info != nullptr) {
		iov[4].iov_base = info;
		iov[4].iov_len = strlen(info);
	}

	MessageRef ref = cs->waitForReply(Message::SET_SRP_SERVER_PARAM,
	    ssl->target, iov, 5);

	free(iov[0].iov_base);
	free(iov[1].iov_base);
	free(iov[2].iov_base);
	free(iov[3].iov_base);

	if (!ref)
		return (-1);
	if (ref.result()->error != SSL_ERROR_NONE)
		return (-1);
	return (ref.result()->ret);
}

/*
 * SSL_get_srp_username() returns a pointer to an internal string that
 * is not reference-counted.  To avoid leaking memory, cache the
 * pointer in PSSL and free it when the PSSL is destroyed.  This does
 * assume the value doesn't change once it is set.
 */
char *
PSSL_get_srp_username(PSSL *ssl)
{
	if (ssl->srp_username != nullptr)
		return (ssl->srp_username);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_GET_SRP_USERNAME, ERR_R_NO_COMMAND_CHANNEL);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(Message::GET_SRP_USERNAME,
	    ssl->target);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() == 0) {
		PROCerr(PROC_F_SSL_GET_SRP_USERNAME, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "empty reply body");
		return (nullptr);
	}
	const char *name = reinterpret_cast<const char *>(msg->body());
	ssl->srp_username = strndup(name, msg->bodyLength());
	return (ssl->srp_username);
}

/*
 * SSL_get_srp_userinfo() returns a pointer to an internal string that
 * is not reference-counted.  To avoid leaking memory, cache the
 * pointer in PSSL and free it when the PSSL is destroyed.  This does
 * assume the value doesn't change once it is set.
 */
char *
PSSL_get_srp_userinfo(PSSL *ssl)
{
	if (ssl->srp_userinfo != nullptr)
		return (ssl->srp_userinfo);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_GET_SRP_USERINFO, ERR_R_NO_COMMAND_CHANNEL);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(Message::GET_SRP_USERINFO,
	    ssl->target);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() == 0) {
		PROCerr(PROC_F_SSL_GET_SRP_USERINFO, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "empty reply body");
		return (nullptr);
	}
	const char *info = reinterpret_cast<const char *>(msg->body());
	ssl->srp_userinfo = strndup(info, msg->bodyLength());
	return (ssl->srp_userinfo);
}

static const PSSL_CIPHER *
PSSL_fetch_cipher(const PSSL *ssl, enum Message::Type request)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_FETCH_CIPHER, ERR_R_NO_COMMAND_CHANNEL);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(request, ssl->target);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() != sizeof(int)) {
		PROCerr(PROC_F_SSL_FETCH_CIPHER, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "reply too short");
		return (nullptr);
	}

	int target = *reinterpret_cast<const int *>(msg->body());
	if (target == NULL_TARGET)
		return (nullptr);
	return (PSSL_CIPHER_find(cs, target));
}

const PSSL_CIPHER *
PSSL_get_current_cipher(const PSSL *ssl)
{
	return (PSSL_fetch_cipher(ssl, Message::GET_CURRENT_CIPHER));
}

const PSSL_CIPHER *
PSSL_get_pending_cipher(const PSSL *ssl)
{
	return (PSSL_fetch_cipher(ssl, Message::GET_PENDING_CIPHER));
}

int
PSSL_set_session_id_context(PSSL *ssl, const unsigned char *ctx,
    unsigned int len)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_SET_SESSION_ID_CONTEXT,
		    ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::SET_SESSION_ID_CONTEXT,
	    ssl->target, ctx, len);
	if (!ref)
		return (0);
	return (ref.result()->ret);
}

void
PSSL_set_msg_callback(PSSL *ssl, void (*cb)(int, int, int, const void *,
    size_t, PSSL *, void *))
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	ssl->msg_cb = cb;
	cs->waitForReply(cb == nullptr ? Message::DISABLE_MSG_CB :
	    Message::ENABLE_MSG_CB, ssl->target);
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

void
PSSL_set_connect_state(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SET_CONNECT_STATE,
	    ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
}

void
PSSL_set_accept_state(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SET_ACCEPT_STATE,
	    ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
}

int
PSSL_is_server(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::IS_SERVER, ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

int
PSSL_do_handshake(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_DO_HANDSHAKE, ERR_R_NO_COMMAND_CHANNEL);
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}

	MessageRef ref = cs->waitForReply(Message::DO_HANDSHAKE, ssl->target);
	if (!ref) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	const Message::Result *msg = ref.result();
	ssl->last_error = msg->error;
	return (msg->ret);
}

int
PSSL_accept(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_ACCEPT, ERR_R_NO_COMMAND_CHANNEL);
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}

	MessageRef ref = cs->waitForReply(Message::ACCEPT, ssl->target);
	if (!ref) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	const Message::Result *msg = ref.result();
	ssl->last_error = msg->error;
	return (msg->ret);
}

int
PSSL_connect(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_CONNECT, ERR_R_NO_COMMAND_CHANNEL);
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}

	MessageRef ref = cs->waitForReply(Message::CONNECT, ssl->target);
	if (!ref) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	const Message::Result *msg = ref.result();
	ssl->last_error = msg->error;
	return (msg->ret);
}

int
PSSL_in_init(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::IN_INIT, ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

int
PSSL_in_before(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::IN_BEFORE, ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

int
PSSL_is_init_finished(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::IS_INIT_FINISHED,
	    ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

int
PSSL_client_version(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CLIENT_VERSION, ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

static const char *
version_string(int version)
{
	switch (version) {
	case SSL3_VERSION:
		return ("SSLv3");
	case TLS1_VERSION:
		return ("TLSv1");
	case TLS1_1_VERSION:
		return ("TLSv1.1");
	case TLS1_2_VERSION:
		return ("TLSv1.2");
	case TLS1_3_VERSION:
		return ("TLSv1.3");
	default:
		return ("unknown");
	}
}

const char *
PSSL_get_version(const PSSL *ssl)
{
	return (version_string(PSSL_version(ssl)));
}

int
PSSL_version(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::VERSION, ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

const char *
PSSL_get_servername(const PSSL *sslc, const int type)
{
	PSSL *ssl = const_cast<PSSL *>(sslc);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_GET_SERVERNAME, ERR_R_NO_COMMAND_CHANNEL);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(Message::GET_SERVERNAME, ssl->target,
	    &type, sizeof(type));
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() == 0) {
		PROCerr(PROC_F_SSL_GET_SERVERNAME, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "empty reply body");
		return (nullptr);
	}
	const char *name = reinterpret_cast<const char *>(msg->body());
	if (ssl->servername != NULL &&
	    strlen(ssl->servername) == msg->bodyLength() &&
	    strncmp(ssl->servername, name, msg->bodyLength()) == 0)
		return (ssl->servername);
	free(ssl->servername);
	ssl->servername = strndup(name, msg->bodyLength());
	return (ssl->servername);
}

int
PSSL_get_servername_type(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_SERVERNAME_TYPE,
	    ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	return (msg->ret);
}

static int
PSSL_do_read(PSSL *ssl, enum Message::Type type, void *buf, int len)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_READ, ERR_R_NO_COMMAND_CHANNEL);
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}

	int resid = len;
	MessageRef ref = cs->waitForReply(type, ssl->target, &resid,
	    sizeof(resid));
	if (!ref) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	const Message::Result *msg = ref.result();
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
PSSL_read(PSSL *ssl, void *buf, int len)
{
	return (PSSL_do_read(ssl, Message::READ, buf, len));
}

int
PSSL_peek(PSSL *ssl, void *buf, int len)
{
	return (PSSL_do_read(ssl, Message::PEEK, buf, len));
}

int
PSSL_write(PSSL *ssl, const void *buf, int len)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_WRITE, ERR_R_NO_COMMAND_CHANNEL);
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}

	MessageRef ref = cs->waitForReply(Message::WRITE, ssl->target, buf,
	    len);
	if (!ref) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	const Message::Result *msg = ref.result();
	ssl->last_error = msg->error;
	return (msg->ret);
}

void
PSSL_set_shutdown(PSSL *ssl, int mode)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SET_SHUTDOWN, ssl->target,
	    &mode, sizeof(mode));
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
}

int
PSSL_get_shutdown(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_SHUTDOWN, ssl->target);
	if (!ref)
		abort();
	return (ref.result()->ret);
}

int
PSSL_shutdown(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_SHUTDOWN, ERR_R_NO_COMMAND_CHANNEL);
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}

	MessageRef ref = cs->waitForReply(Message::SHUTDOWN, ssl->target);
	if (!ref) {
		ssl->last_error = SSL_ERROR_SYSCALL;
		return (-1);
	}
	const Message::Result *msg = ref.result();
	ssl->last_error = msg->error;
	return (msg->ret);
}

static int X509_ex_data_PSSL_idx;

int
PSSL_get_ex_data_X509_STORE_CTX_idx(void)
{
	return (X509_ex_data_PSSL_idx);
}

void
PSSL_set_default_passwd_cb(PSSL *ssl, pem_password_cb *cb)
{
	ssl->default_passwd_cb = cb == nullptr ? PEM_def_callback : cb;
}

void
PSSL_set_default_passwd_cb_userdata(PSSL *ssl, void *data)
{
	ssl->default_passwd_cb_userdata = data;
}

STACK_OF(PSSL_CIPHER) *
PSSL_get_ciphers(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_GET_CIPHERS, ERR_R_NO_COMMAND_CHANNEL);
		return (nullptr);
	}

	MessageRef ref = cs->waitForReply(Message::GET_CIPHERS, ssl->target);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (nullptr);
	if (msg->bodyLength() % 4 != 0) {
		PROCerr(PROC_F_SSL_GET_CIPHERS, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1,
		    "message body is not an array of targets");
		return (nullptr);
	}
	if (msg->bodyLength() == 0)
		return (nullptr);

	const int *targets = reinterpret_cast<const int *>(msg->body());
	int count = msg->bodyLength() / 4;
	STACK_OF(PSSL_CIPHER) *sk = sk_PSSL_CIPHER_new_reserve(nullptr, count);
	for (int i = 0; i < count; i++) {
		const PSSL_CIPHER *cipher = PSSL_CIPHER_find(cs, targets[i]);
		if (cipher == nullptr) {
			sk_PSSL_CIPHER_free(sk);
			return (nullptr);
		}
		sk_PSSL_CIPHER_push(sk, cipher);
	}
	sk_PSSL_CIPHER_free(ssl->get_ciphers);
	ssl->get_ciphers = sk;
	return (sk);
}

STACK_OF(X509) *
PSSL_get_peer_cert_chain(PSSL *ssl)
{
	/* XXX: Need a way to invalidate this if a session is reused. */
	if (ssl->get_peer_cert_chain != nullptr)
		return (ssl->get_peer_cert_chain);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_PEER_CERT_CHAIN,
	    ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	if (msg->bodyLength() == 0)
		return (nullptr);

	STACK_OF(X509) *sk = sk_X509_parse(msg->body(), msg->bodyLength());
	if (sk == nullptr)
		abort();
	ssl->get_peer_cert_chain = sk;
	return (sk);
}

int
PSSL_renegotiate(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr) {
		PROCerr(PROC_F_SSL_RENEGOTIATE, ERR_R_NO_COMMAND_CHANNEL);
		return (0);
	}

	MessageRef ref = cs->waitForReply(Message::RENEGOTIATE, ssl->target);
	if (!ref)
		return (0);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (0);
	return (msg->ret);
}

X509 *
PSSL_get_certificate(const PSSL *sslc)
{
	PSSL *ssl = const_cast<PSSL *>(sslc);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_CERTIFICATE, ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	if (msg->bodyLength() == 0)
		return (nullptr);

	const unsigned char *data =
	    reinterpret_cast<const unsigned char *>(msg->body());
	X509 *cert = d2i_X509(NULL, &data, msg->bodyLength());
	if (cert == nullptr)
		abort();

	X509_free(ssl->get_cert);
	ssl->get_cert = cert;
	return (cert);
}

EVP_PKEY *
PSSL_get_privatekey(PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_PRIVATEKEY, ssl->target);
	if (!ref)
		abort();
	const Message::Result *hdr = ref.result();
	if (hdr->error != SSL_ERROR_NONE)
		abort();
	if (hdr->bodyLength() == 0)
		return (nullptr);

	if (hdr->length < sizeof(Message::PKeyResult))
		abort();
	const Message::PKeyResult *msg =
	    reinterpret_cast<const Message::PKeyResult *>(hdr);
	const unsigned char *pp =
	    reinterpret_cast<const unsigned char *>(msg->key());
	EVP_PKEY *pkey = d2i_PrivateKey(msg->pktype, nullptr, &pp,
	    msg->keyLength());
	if (pkey == nullptr)
		abort();

	EVP_PKEY_free(ssl->get_privatekey);
	ssl->get_privatekey = pkey;
	return (pkey);
}

STACK_OF(X509_NAME) *
PSSL_get_client_CA_list(const PSSL *sslc)
{
	PSSL *ssl = const_cast<PSSL *>(sslc);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::GET_CLIENT_CA_LIST,
	    ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();
	if (msg->bodyLength() == 0)
		return (nullptr);
	STACK_OF(X509_NAME) *sk = sk_X509_NAME_parse(msg->body(),
	    msg->bodyLength());
	if (sk == nullptr)
		abort();

	/*
	 * Cache the returned result since the caller doesn't
	 * explicitly free the returned list.
	 */
	if (ssl->client_CA_list != nullptr)
		sk_X509_NAME_pop_free(ssl->client_CA_list, X509_NAME_free);
	ssl->client_CA_list = sk;
	return (sk);
}

const char *
PSSL_state_string_long(const PSSL *sslc)
{
	PSSL *ssl = const_cast<PSSL *>(sslc);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::STATE_STRING_LONG,
	    ssl->target);
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();

	char *s = strndup(reinterpret_cast<const char *>(msg->body()),
	    msg->bodyLength());
	free(ssl->state_string_long);
	ssl->state_string_long = s;
	return (s);
}

int
PSSL_client_hello_get0_ext(PSSL *ssl, int type, const unsigned char **out,
    size_t *outlen)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::CLIENT_HELLO_GET0_EXT,
	    ssl->target, &type, sizeof(type));
	if (!ref)
		abort();
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		abort();

	if (msg->ret != 1)
		return (msg->ret);

	void *buf = malloc(msg->bodyLength());
	memcpy(buf, msg->body(), msg->bodyLength());
	ssl->client_hello_exts.push_back(buf);

	*out = reinterpret_cast<const unsigned char *>(buf);
	*outlen = msg->bodyLength();
	return (1);
}

PSSL_SESSION *
PSSL_get_session(const PSSL *sslc)
{
	PSSL *ssl = const_cast<PSSL *>(sslc);

	if (ssl->session != nullptr)
		return (ssl->session);

	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		return (nullptr);

	MessageRef ref = cs->waitForReply(Message::GET_SESSION, ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		return (nullptr);
	if (ref.result()->length < sizeof(Message::GetSessionResult))
		return (nullptr);

	const Message::GetSessionResult *msg =
	    reinterpret_cast<const Message::GetSessionResult *>(ref.result());

	PSSL_SESSION *s = PSSL_SESSION_new();
	if (s == nullptr)
		return (nullptr);

	s->target = msg->session;
	s->id_len = msg->idLength();
	s->id = reinterpret_cast<unsigned char *>(malloc(s->id_len));
	if (s->id == nullptr) {
		PSSL_SESSION_free(s);
		return (nullptr);
	}
	ssl->session = s;
	return (s);
}

int
PSSL_session_reused(const PSSL *ssl)
{
	CommandChannel *cs = currentCommandChannel();
	if (cs == nullptr)
		abort();

	MessageRef ref = cs->waitForReply(Message::SESSION_REUSED, ssl->target);
	if (!ref || ref.result()->error != SSL_ERROR_NONE)
		abort();
	return (ref.result()->ret);
}

void
SSL_init(void)
{
	X509_ex_data_PSSL_idx = X509_STORE_CTX_get_ex_new_index(0, NULL, NULL,
	    NULL, NULL);
}
