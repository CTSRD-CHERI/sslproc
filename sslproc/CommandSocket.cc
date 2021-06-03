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

#include <sys/event.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <syslog.h>

#include <openssl/ssl.h>

#include "local.h"
#include "Messages.h"
#include "TargetStore.h"
#include "CommandSocket.h"

static pthread_attr_t attr;
static TargetStore targets;
static thread_local CommandSocket *currentSocket;
static BIO_METHOD *readBioMethod, *writeBioMethod;

static void
msg_cb(int write_p, int version, int content_type, const void *buf,
    size_t len, SSL *ssl, void *arg)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return;
	}

	struct {
		int write_p;
		int version;
		int content_type;
	} args;
	struct iovec iov[2];

	args.write_p = write_p;
	args.version = version;
	args.content_type = content_type;

	iov[0].iov_base = &args;
	iov[0].iov_len = sizeof(args);
	iov[1].iov_base = const_cast<void *>(buf);
	iov[1].iov_len = len;
	cs->sendRequest(Message::MSG_CB, ssl, iov, 2);
}

static int
servername_cb(SSL *ssl, int *al, void *arg)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}

	MessageRef ref = cs->sendRequest(Message::SERVERNAME_CB, ssl, al,
	    sizeof(*al));
	if (!ref)
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	const Message::Result *msg = ref.result();
	if (msg->bodyLength() == sizeof(*al))
		*al = *reinterpret_cast<const int *>(msg->body());
	return (msg->ret);
}

static int
client_hello_cb(SSL *ssl, int *al, void *arg)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		*al = SSL_AD_INTERNAL_ERROR;
		return (0);
	}

	MessageRef ref = cs->sendRequest(Message::CLIENT_HELLO_CB, ssl, al,
	    sizeof(*al));
	if (!ref) {
		*al = SSL_AD_INTERNAL_ERROR;
		return (0);
	}
	const Message::Result *msg = ref.result();
	if (msg->bodyLength() == sizeof(*al))
		*al = *reinterpret_cast<const int *>(msg->body());
	return (msg->ret);
}

static int
srp_username_cb(SSL *ssl, int *ad, void *arg)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		*ad = SSL_AD_INTERNAL_ERROR;
		return (SSL3_AL_FATAL);
	}

	MessageRef ref = cs->sendRequest(Message::SRP_USERNAME_CB, ssl,
	    ad, sizeof(*ad));
	if (!ref) {
		*ad = SSL_AD_INTERNAL_ERROR;
		return (SSL3_AL_FATAL);
	}
	const Message::Result *msg = ref.result();
	if (msg->bodyLength() == sizeof(*ad))
		*ad = *reinterpret_cast<const int *>(msg->body());
	return (msg->ret);
}

static int
sess_new_cb(SSL *ssl, SSL_SESSION *s)
{
	struct {
		long	time;
		int	compress_id;
		unsigned int id_len;
		long	internal_length;
	} body;
	struct iovec iov[3];

	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (0);
	}

	iov[0].iov_base = &body;
	iov[0].iov_len = sizeof(body);
	body.time = SSL_SESSION_get_time(s);
	body.compress_id = SSL_SESSION_get_compress_id(s);

	iov[1].iov_base = const_cast<unsigned char *>(SSL_SESSION_get_id(s,
	    &body.id_len));
	if (iov[1].iov_base == nullptr)
		return (0);
	iov[1].iov_len = body.id_len;

	unsigned char *asn1 = nullptr;
	iov[2].iov_len = i2d_SSL_SESSION(s, &asn1);
	if (iov[2].iov_len == 0)
		return (0);
	iov[2].iov_base = asn1;
	body.internal_length = iov[2].iov_len;

	cs->sendRequest(Message::SESS_NEW_CB, ssl, iov, 3);

	OPENSSL_free(asn1);

	return (0);
}

static void
sess_remove_cb(SSL_CTX *ctx, SSL_SESSION *s)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return;
	}

	unsigned int id_len;
	const unsigned char *id = SSL_SESSION_get_id(s, &id_len);
	if (id == nullptr || id_len == 0)
		return;

	cs->sendRequest(Message::SESS_REMOVE_CB, ctx, id, id_len);
}

SSL_SESSION *
sess_get_cb(SSL *ssl, const unsigned char *data, int len, int *copy)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (0);
	}

	MessageRef ref = cs->sendRequest(Message::SESS_GET_CB, ssl, data, len);
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE || msg->bodyLength() == 0)
		return (nullptr);

	const unsigned char *pp = reinterpret_cast<const unsigned char *>
	    (msg->body());
	*copy = 0;
	return (d2i_SSL_SESSION(nullptr, &pp, msg->bodyLength()));
}

static DH *
tmp_dh_cb(SSL *ssl, int is_export, int keylength)
{
	struct {
		int is_export;
		int keylength;
	} body;

	body.is_export = is_export;
	body.keylength = keylength;

	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (nullptr);
	}

	MessageRef ref = cs->sendRequest(Message::TMP_DH_CB, ssl, &body,
	    sizeof(body));
	if (!ref)
		return (nullptr);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE || msg->bodyLength() == 0)
		return (nullptr);

	const unsigned char *pp = reinterpret_cast<const unsigned char *>
	    (msg->body());
	return (d2i_DHparams(nullptr, &pp, msg->bodyLength()));
}

static void
info_cb(const SSL *ssl, int where, int ret)
{
	struct {
		int where;
		int ret;
	} body;

	body.where = where;
	body.ret = ret;

	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return;
	}

	cs->sendRequest(Message::INFO_CB, ssl, &body, sizeof(body));
}

static int
alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}

	MessageRef ref = cs->sendRequest(Message::ALPN_SELECT_CB, ssl, in,
	    inlen);
	if (!ref)
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	const Message::Result *msg = ref.result();
	if (msg->error != SSL_ERROR_NONE)
		return (SSL_TLSEXT_ERR_ALERT_FATAL);

	/*
	 * XXX: It's not really ideal to return the pointer to the
	 * caller as the message will be freed into the stack of free
	 * messages when this function returns.  However, the caller
	 * should consume the data in this buffer before returning or
	 * invoking another callback.
	 */
	*out = reinterpret_cast<const unsigned char *>(msg->body());
	*outlen = msg->bodyLength();
	return (msg->ret);
}

static int
client_cert_cb(SSL *ssl, X509 **certp, EVP_PKEY **pkeyp)
{
	CommandSocket *cs = currentSocket;
	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (-1);
	}

	MessageRef ref = cs->sendRequest(Message::CLIENT_CERT_CB, ssl);
	if (!ref)
		return (-1);
	const Message::Result *hdr = ref.result();
	if (hdr->ret != 1)
		return (hdr->ret);
	if (hdr->length < sizeof(Message::ClientCertCbResult))
		return (-1);

	const Message::ClientCertCbResult *msg =
	    reinterpret_cast<const Message::ClientCertCbResult *>(hdr);
	const unsigned char *pp = reinterpret_cast<const unsigned char *>
	    (msg->cert());
	X509 *cert = d2i_X509(nullptr, &pp, msg->cert_len);
	if (cert == nullptr)
		return (-1);
	pp = reinterpret_cast<const unsigned char *>(msg->pkey());
	EVP_PKEY *pkey = d2i_PrivateKey(msg->pktype, nullptr, &pp, msg->pk_len);
	if (pkey == nullptr) {
		X509_free(cert);
		return (-1);
	}

	*certp = cert;
	*pkeyp = pkey;
	return (1);
}

static void *
commandSocketRun(void *arg)
{
	CommandSocket *cs = reinterpret_cast<CommandSocket *>(arg);

	currentSocket = cs;
	cs->run();
	delete cs;
	return (nullptr);
}

bool
CommandSocket::init()
{
	if (!allocateMessages(4, 64))
		return (false);

	pthread_t thread;
	int error = pthread_create(&thread, &attr, commandSocketRun, this);
	if (error != 0)
		return (false);

	return (true);
}

static SSL *
findSSL(const Message::Targeted *thdr)
{
	if (thdr == nullptr)
		return (nullptr);
	return (targets.lookup<SSL>(thdr->target));
}

static SSL_CTX *
findSSL_CTX(const Message::Targeted *thdr)
{
	if (thdr == nullptr)
		return (nullptr);
	return (targets.lookup<SSL_CTX>(thdr->target));
}

bool
CommandSocket::handleMessage(const Message::Header *hdr)
{
	const Message::Targeted *thdr;
	SSL_CTX *ctx;
	SSL *ssl;
	long ret;

	if (hdr->length < sizeof(Message::Targeted))
		thdr = nullptr;
	else
		thdr = reinterpret_cast<const Message::Targeted *>(hdr);
	switch (hdr->type) {
	case Message::CREATE_CONTEXT:
	{
		if (hdr->length != sizeof(Message::CreateContext)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		const Message::CreateContext *msg =
		    reinterpret_cast<const Message::CreateContext *>(hdr);
		const SSL_METHOD *method = nullptr;
		switch (msg->method) {
		case Message::METHOD_TLS:
			method = TLS_method();
			break;
		case Message::METHOD_TLS_SERVER:
			method = TLS_server_method();
			break;
		case Message::METHOD_TLS_CLIENT:
			method = TLS_client_method();
			break;
		}
		if (method == nullptr) {
			writeErrnoReply(hdr->type, -1, EINVAL);
			break;
		}

		ctx = SSL_CTX_new(method);
		if (ctx == nullptr) {
			writeSSLErrorReply(hdr->type, -1, SSL_ERROR_SSL);
			break;
		}

		int target = targets.allocate(ctx);
		SSL_CTX_set_app_data(ctx, reinterpret_cast<void *>(target));
		writeReplyMessage(hdr->type, 0, &target, sizeof(target));
		break;
	}
	case Message::FREE_CONTEXT:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		targets.remove(thdr->target);
		SSL_CTX_free(ctx);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_SET_OPTIONS:
	case Message::CTX_CLEAR_OPTIONS:
	{
		if (hdr->length != sizeof(Message::Options)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::Options *msg =
		    reinterpret_cast<const Message::Options *>(hdr);
		long options;

		if (hdr->type == Message::CTX_SET_OPTIONS)
			options = SSL_CTX_set_options(ctx, msg->options);
		else
			options = SSL_CTX_clear_options(ctx, msg->options);
		writeReplyMessage(hdr->type, 0, &options, sizeof(options));
		break;
	}
	case Message::CTX_GET_OPTIONS:
	{
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		long options = SSL_CTX_get_options(ctx);
		writeReplyMessage(hdr->type, 0, &options, sizeof(options));
		break;
	}
	case Message::CTX_CTRL:
	{
		if (hdr->length < sizeof(Message::Ctrl)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		/* Permit explicit NULL contexts. */
		if (thdr->target == NULL_TARGET)
			ctx = nullptr;
		else {
			ctx = findSSL_CTX(thdr);
			if (ctx == nullptr) {
				writeErrnoReply(hdr->type, -1, ENOENT);
				break;
			}
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);

		switch (msg->cmd) {
		case SSL_CTRL_SET_MIN_PROTO_VERSION:
		case SSL_CTRL_SET_MAX_PROTO_VERSION:
		case SSL_CTRL_GET_MIN_PROTO_VERSION:
		case SSL_CTRL_GET_MAX_PROTO_VERSION:
		case SSL_CTRL_MODE:
		case SSL_CTRL_CLEAR_MODE:
		case SSL_CTRL_SET_SESS_CACHE_MODE:
		case SSL_CTRL_GET_SESS_CACHE_MODE:
			ret = SSL_CTX_ctrl(ctx, msg->cmd, msg->larg, nullptr);
			writeReplyMessage(hdr->type, ret);
			break;
		case SSL_CTRL_SET_TMP_DH:
		{
			const unsigned char *pp =
			    reinterpret_cast<const unsigned char *>
			    (msg->body());
			DH *dh = d2i_DHparams(nullptr, &pp, msg->bodyLength());
			if (dh == nullptr) {
				writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
				break;
			}
			ret = SSL_CTX_set_tmp_dh(ctx, dh);
			DH_free(dh);
			if (ret == 0)
				writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
			else
				writeReplyMessage(hdr->type, ret);
			break;
		}
		default:
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			break;
		}
		break;
	}
	case Message::CTX_USE_CERTIFICATE_ASN1:
		if (thdr == nullptr || thdr->bodyLength() == 0) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_CTX_use_certificate_ASN1(ctx, thdr->bodyLength(),
		    reinterpret_cast<const unsigned char *>(thdr->body()));
		if (ret != 1)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 1);
		break;
	case Message::CTX_USE_PRIVATEKEY_ASN1:
	{
		if (hdr->length <= sizeof(Message::PKey)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::PKey *msg =
		    reinterpret_cast<const Message::PKey *>(hdr);
		ret = SSL_CTX_use_PrivateKey_ASN1(msg->pktype, ctx,
		    reinterpret_cast<const unsigned char *>(msg->key()),
		    msg->keyLength());
		if (ret != 1)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 1);
		break;
	}
	case Message::CTX_CHECK_PRIVATE_KEY:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_CTX_check_private_key(ctx);
		if (ret != 1)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 1);
		break;
	case Message::CTX_ENABLE_SERVERNAME_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_CTX_set_tlsext_servername_callback(ctx,
		    servername_cb);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::CTX_DISABLE_SERVERNAME_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_CTX_set_tlsext_servername_callback(ctx, nullptr);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::CTX_ENABLE_CLIENT_HELLO_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_CLIENT_HELLO_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_client_hello_cb(ctx, nullptr, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_ENABLE_SRP_USERNAME_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_srp_username_callback(ctx, srp_username_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_SRP_USERNAME_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_srp_username_callback(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_ENABLE_SESS_CBS:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}
		SSL_CTX_sess_set_new_cb(ctx, sess_new_cb);
		SSL_CTX_sess_set_remove_cb(ctx, sess_remove_cb);
		SSL_CTX_sess_set_get_cb(ctx, sess_get_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_SESS_CBS:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}
		SSL_CTX_sess_set_new_cb(ctx, nullptr);
		SSL_CTX_sess_set_remove_cb(ctx, nullptr);
		SSL_CTX_sess_set_get_cb(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_ENABLE_TMP_DH_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_tmp_dh_callback(ctx, tmp_dh_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_TMP_DH_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_tmp_dh_callback(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_ENABLE_INFO_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_info_callback(ctx, info_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_INFO_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_info_callback(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_ENABLE_ALPN_SELECT_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_ALPN_SELECT_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_alpn_select_cb(ctx, nullptr, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_SET_CIPHER_LIST:
	{
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, 0, ENOENT);
			break;
		}

		char *s = strndup(reinterpret_cast<const char *>(thdr->body()),
		    thdr->bodyLength());
		ret = SSL_CTX_set_cipher_list(ctx, s);
		free(s);
		if (ret == 0)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, ret);
		break;
	}
	case Message::CTX_SET_CIPHERSUITES:
	{
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, 0, ENOENT);
			break;
		}

		char *s = strndup(reinterpret_cast<const char *>(thdr->body()),
		    thdr->bodyLength());
		ret = SSL_CTX_set_ciphersuites(ctx, s);
		free(s);
		if (ret == 0)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, ret);
		break;
	}
	case Message::CTX_SET_TIMEOUT:
	{
		long time;

		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (thdr->bodyLength() != sizeof(time)) {
			syslog(LOG_WARNING,
		    "invalid message size for Message::CTX_SET_TIMEOUT");
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		time = *reinterpret_cast<const long *>(thdr->body());
		ret = SSL_CTX_set_timeout(ctx, time);
		writeReplyMessage(hdr->type, ret);
		break;
	}
	case Message::CTX_GET0_CERTIFICATE:
	{
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		X509 *cert = SSL_CTX_get0_certificate(ctx);
		if (cert == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		unsigned char *buf = NULL;
		int len = i2d_X509(cert, &buf);
		if (len < 0) {
			writeSSLErrorReply(hdr->type, -1, SSL_ERROR_SSL);
			break;
		}
		writeReplyMessage(hdr->type, 0, buf, len);
		OPENSSL_free(buf);
		break;
	}
	case Message::CTX_ENABLE_CLIENT_CERT_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_client_cert_cb(ctx, client_cert_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CTX_DISABLE_CLIENT_CERT_CB:
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_CTX_set_client_cert_cb(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CREATE_SESSION:
	{
		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		BIO *rbio = BIO_new(readBioMethod);
		if (rbio == nullptr) {
			writeSSLErrorReply(hdr->type, -1, SSL_ERROR_SSL);
			break;
		}

		BIO *wbio = BIO_new(writeBioMethod);
		if (wbio == nullptr) {
			BIO_free(rbio);
			writeSSLErrorReply(hdr->type, -1, SSL_ERROR_SSL);
			break;
		}

		ssl = SSL_new(ctx);
		if (ssl == nullptr) {
			BIO_free(rbio);
			BIO_free(wbio);
			writeSSLErrorReply(hdr->type, -1, SSL_ERROR_SSL);
			break;
		}
		SSL_set_bio(ssl, rbio, wbio);
		BIO_set_data(rbio, ssl);
		BIO_set_data(wbio, ssl);

		/*
		 * Since subsequent writes can use different
		 * MessageBuffers (and MessageBuffer pointers can move
		 * due to realloc()s), the pointer may not be the same
		 * when a partial SSL_write() is re-attempted.
		 */
		SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

		int target = targets.allocate(ssl);
		SSL_set_app_data(ssl, reinterpret_cast<void *>(target));
		writeReplyMessage(hdr->type, 0, &target, sizeof(target));
		break;
	}
	case Message::FREE_SESSION:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		targets.remove(thdr->target);
		SSL_free(ssl);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CONNECT:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_connect(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case Message::DO_HANDSHAKE:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_do_handshake(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case Message::ACCEPT:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_accept(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case Message::SHUTDOWN:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_shutdown(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case Message::READ:
	{
		if (hdr->length != sizeof(Message::Read)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::Read *msg =
		    reinterpret_cast<const Message::Read *>(hdr);
		if (msg->resid > 0) {
			/*
			 * XXX: We could perhaps just perform a
			 * short read with whatever capacity we
			 * have if it is not zero.
			 */
			if (!readBuffer.grow(msg->resid)) {
				syslog(LOG_WARNING,
				    "failed to grow read buffer");
				writeErrnoReply(hdr->type, -1, ENOMEM);
				break;
			}
		}
		ret = SSL_read(ssl, readBuffer.data(), msg->resid);
		if (ret > 0)
			writeReplyMessage(hdr->type, ret, readBuffer.data(),
			    ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	}
	case Message::WRITE:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_write(ssl, thdr->body(), thdr->bodyLength());
		if (ret > 0)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case Message::ENABLE_MSG_CB:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_set_msg_callback(ssl, msg_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::DISABLE_MSG_CB:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_set_msg_callback(ssl, NULL);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::SET_CONNECT_STATE:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_set_connect_state(ssl);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::SET_ACCEPT_STATE:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		SSL_set_accept_state(ssl);
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::IS_SERVER:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_is_server(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::IN_INIT:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_in_init(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::IN_BEFORE:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_in_before(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::IS_INIT_FINISHED:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_is_init_finished(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::GET_SERVERNAME:
	{
		int type;

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (thdr->bodyLength() != sizeof(type)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for Message::GET_SERVERNAME",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		type = *reinterpret_cast<const int *>(thdr->body());
		const char *servername = SSL_get_servername(ssl, type);
		if (servername == nullptr)
			writeReplyMessage(hdr->type, 0);
		else
			writeReplyMessage(hdr->type, 0, servername,
			    strlen(servername));
		break;
	}
	case Message::GET_SERVERNAME_TYPE:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_get_servername_type(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::CTRL:
	{
		if (hdr->length < sizeof(Message::Ctrl)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for Message::CTRL",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		/* Permit explicit NULL contexts. */
		if (thdr->target == NULL_TARGET)
			ssl = nullptr;
		else {
			ssl = findSSL(thdr);
			if (ssl == nullptr) {
				writeErrnoReply(hdr->type, -1, ENOENT);
				break;
			}
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);

		switch (msg->cmd) {
		case SSL_CTRL_SET_TLSEXT_HOSTNAME:
		{
			char *name;

			if (msg->bodyLength() == 0)
				name = nullptr;
			else
				name = strndup(
				    reinterpret_cast<const char *>(msg->body()),
				    msg->bodyLength());
			ret = SSL_ctrl(ssl, msg->cmd, msg->larg, name);
			free(name);
			writeReplyMessage(hdr->type, ret);
			break;
		}
		default:
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			break;
		}
		break;
	}
	case Message::SET_SHUTDOWN:
	{
		int mode;

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (thdr->bodyLength() != sizeof(mode)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for Message::SET_SHUTDOWN",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		mode = *reinterpret_cast<const int *>(thdr->body());
		SSL_set_shutdown(ssl, mode);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::GET_SHUTDOWN:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_get_shutdown(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::GET_PEER_CERTIFICATE:
	{
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		X509 *x = SSL_get_peer_certificate(ssl);
		if (x == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		unsigned char *buf = nullptr;
		int len = i2d_X509(x, &buf);
		X509_free(x);
		if (len < 0) {
			writeReplyMessage(hdr->type, -1);
			break;
		}
		writeReplyMessage(hdr->type, 0, buf, len);
		OPENSSL_free(buf);
		break;
	}
	case Message::GET_VERIFY_RESULT:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_get_verify_result(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::SET_VERIFY_RESULT:
	{
		long result;

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (thdr->bodyLength() != sizeof(long)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for Message::SET_VERIFY_RESULT",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		result = *reinterpret_cast<const long *>(thdr->body());
		SSL_set_verify_result(ssl, result);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::SET_ALPN_PROTOS:
	{
		const unsigned char *protos;

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (thdr->bodyLength() == 0)
			protos = nullptr;
		else
			protos = reinterpret_cast<const unsigned char *>
			    (thdr->body());
		ret = SSL_set_alpn_protos(ssl, protos, thdr->bodyLength());
		if (ret != 0)
			writeSSLErrorReply(hdr->type, ret, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::GET_SRP_USERNAME:
	{
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const char *s = SSL_get_srp_username(ssl);
		if (s != nullptr)
			writeReplyMessage(hdr->type, 0, s, strlen(s));
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::GET_SRP_USERINFO:
	{
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const char *s = SSL_get_srp_userinfo(ssl);
		if (s != nullptr)
			writeReplyMessage(hdr->type, 0, s, strlen(s));
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::GET_CURRENT_CIPHER:
	case Message::GET_PENDING_CIPHER:
	{
		const SSL_CIPHER *cipher;

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (hdr->type == Message::GET_CURRENT_CIPHER)
			cipher = SSL_get_current_cipher(ssl);
		else
			cipher = SSL_get_pending_cipher(ssl);
		if (cipher == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		Message::CipherResultBody body;
		body.bits = SSL_CIPHER_get_bits(cipher, &body.alg_bits);
		const char *name = SSL_CIPHER_get_name(cipher);

		struct iovec iov[2];
		iov[0].iov_base = &body;
		iov[0].iov_len = sizeof(body);
		iov[1].iov_base = const_cast<char *>(name);
		iov[1].iov_len = name == nullptr ? 0 : strlen(name);
		writeReplyMessage(hdr->type, 0, iov, 2);
		break;
	}
	case Message::SET_SESSION_ID_CONTEXT:
		const unsigned char *ctx_id;

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (thdr->bodyLength() == 0)
			ctx_id = nullptr;
		else
			ctx_id = reinterpret_cast<const unsigned char *>
			    (thdr->body());
		ret = SSL_set_session_id_context(ssl, ctx_id,
		    thdr->bodyLength());
		if (ret != 0)
			writeSSLErrorReply(hdr->type, ret, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, ret);
		break;
	case Message::CLIENT_VERSION:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_client_version(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case Message::VERSION:
		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ret = SSL_version(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	default:
		syslog(LOG_WARNING, "unknown session request %d", hdr->type);
		return (false);
	}

	return (true);
}

void
CommandSocket::run()
{
	for (;;) {
		MessageRef ref;

		int rc = readMessage(ref);
		if (rc == 0 || rc == -1)
			return;

		if (!handleMessage(ref.hdr()) || writeFailed)
			return;
	}
}

void
CommandSocket::observeReadError(enum ReadError error,
    const Message::Header *hdr)
{
	switch (error) {
	case NO_BUFFER:
		syslog(LOG_WARNING, "out of message buffers on command socket");
		break;
	case READ_ERROR:
		syslog(LOG_WARNING, "failed to read from command socket: %m");
		break;
	case GROW_FAIL:
		syslog(LOG_WARNING,
		    "failed to grow command socket message buffer");
		break;
	case SHORT:
		syslog(LOG_WARNING, "command socket message too short");
		break;
	case TRUNCATED:
		syslog(LOG_WARNING, "command socket message truncated");
		break;
	case BAD_MSG_LENGTH:
		syslog(LOG_WARNING, "invalid command socket message length %d",
		    hdr->length);
		break;
	case LENGTH_MISMATCH:
		syslog(LOG_WARNING, "command socket message length mismatch");
		break;
	}
}

void
CommandSocket::observeWriteError()
{
	syslog(LOG_WARNING, "failed to write message on command socket: %m");
	writeFailed = true;
}

MessageRef
CommandSocket::sendRequest(enum Message::Type type, int target,
    struct iovec *iov, int iovCnt)
{
	if (!writeMessage(type, target, iov, iovCnt)) {
		syslog(LOG_DEBUG, "%s: failed to send request %d: %m", __func__,
		    type);
		return {};
	}

	return (_waitForReply(type));
}

MessageRef
CommandSocket::sendRequest(enum Message::Type type, int target,
    const void *payload, size_t payloadLen)
{
	if (!writeMessage(type, target, payload, payloadLen)) {
		syslog(LOG_DEBUG, "%s: failed to send request %d: %m", __func__,
		    type);
		return {};
	}

	return (_waitForReply(type));
}

MessageRef
CommandSocket::_waitForReply(enum Message::Type type)
{
	MessageRef ref;
	const Message::Header *hdr;
	const Message::Result *msg;
	int rc;

	rc = readMessage(ref);
	if (rc == 0) {
		syslog(LOG_DEBUG, "%s: EOF", __func__);
		return {};
	}
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read reply: %m", __func__);
		return {};
	}
	hdr = ref.hdr();
	if (hdr->type != Message::RESULT) {
		syslog(LOG_DEBUG, "%s: unexpected reply message %d", __func__,
		    msg->type);
		return {};
	}
	msg = ref.result();
	if (msg == nullptr) {
		syslog(LOG_DEBUG, "%s: reply too short", __func__);
		return {};
	}
	if (msg->request != type) {
		syslog(LOG_DEBUG, "%s: reply mismatch", __func__);
		return {};
	}
	return (ref);
}

MessageRef
CommandSocket::sendRequest(enum Message::Type type, const SSL *ssl,
    struct iovec *iov, int iovCnt)
{
	int target = reinterpret_cast<uintptr_t>(SSL_get_app_data(ssl));

	return (sendRequest(type, target, iov, iovCnt));
}

MessageRef
CommandSocket::sendRequest(enum Message::Type type, const SSL *ssl,
    const void *payload, size_t payloadLen)
{
	int target = reinterpret_cast<uintptr_t>(SSL_get_app_data(ssl));

	return (sendRequest(type, target, payload, payloadLen));
}

MessageRef
CommandSocket::sendRequest(enum Message::Type type, const SSL_CTX *ctx,
    const void *payload, size_t payloadLen)
{
	int target = reinterpret_cast<uintptr_t>(SSL_CTX_get_app_data(ctx));

	return (sendRequest(type, target, payload, payloadLen));
}

/*
 * BIO flags to copy from the other end.
 */
#define	BIO_FLAGS_RETRY	(BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)

static int
readBioRead(BIO *bio, char *out, int outl)
{
	CommandSocket *cs = currentSocket;
	SSL *ssl = reinterpret_cast<SSL *>(BIO_get_data(bio));

	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		return (-1);
	}

	if (out == nullptr || outl == 0)
		return (0);

	BIO_clear_retry_flags(bio);

	int resid = outl;
	MessageRef ref = cs->sendRequest(Message::BIO_READ, ssl, &resid,
	    sizeof(resid));
	if (!ref) {
		/* XXX: Do we need to terminate the session? */
		return (-1);
	}
	const Message::Result *msg = ref.result();
	if (msg->ret == 0)
		BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
	else if (msg->ret == -1) {
		int flags;

		if (msg->bodyLength() == sizeof(flags)) {
			flags = *reinterpret_cast<const int *>(msg->body());
			BIO_set_flags(bio, flags & BIO_FLAGS_RETRY);
		} else {
			syslog(LOG_DEBUG, "%s: no flags in error reply",
			    __func__);
			/* XXX: Do we need to terminate the session? */
		}
	} else if (msg->ret > 0) {
		if (msg->ret > outl) {
			syslog(LOG_DEBUG,
			    "%s: returned too much data %ld vs %d", __func__,
			    msg->ret, outl);
			return (-1);
		}

		if (msg->ret != msg->bodyLength()) {
			syslog(LOG_DEBUG,
			    "%s: body length mismatch %ld vs %zu", __func__,
			    msg->ret, msg->bodyLength());
			return (-1);
		}

		/* Copy, ugh */
		memcpy(out, msg->body(), msg->ret);
	}
	return (msg->ret);
}

static int
readBioWrite(BIO *bio, const char *in, int inl)
{
	syslog(LOG_DEBUG, "%s should not be called", __func__);
	return (-2);
}

static int
readBioPuts(BIO *bio, const char *str)
{
	syslog(LOG_DEBUG, "%s should not be called", __func__);
	return (-2);
}

static long
readBioCtrl(BIO *bio, int cmd, long num, void *ptr)
{
	CommandSocket *cs = currentSocket;
	SSL *ssl = reinterpret_cast<SSL *>(BIO_get_data(bio));
	long ret;

	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		abort();
	}

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
	case BIO_CTRL_SET_CLOSE:
	case BIO_CTRL_FLUSH:
	{
		Message::CtrlBody body;
		body.cmd = cmd;
		body.larg = num;
		MessageRef ref = cs->sendRequest(Message::BIO_CTRL_READ, ssl,
		    &body, sizeof(body));
		if (!ref) {
			syslog(LOG_DEBUG, "%s: failed to get a reply",
			    __func__);
			abort();
		}
		ret = ref.result()->ret;
		break;
	}
	case BIO_CTRL_EOF:
		ret = (BIO_get_flags(bio) & BIO_FLAGS_IN_EOF) ? 1 : 0;
		break;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
		ret = 0;
		break;
	default:
		syslog(LOG_DEBUG, "%s: cmd = %d, num = %ld", __func__, cmd,
		    num);
		ret = 0;
	}
	return (ret);
}

static int
writeBioRead(BIO *bio, char *out, int outl)
{
	syslog(LOG_DEBUG, "%s should not be called", __func__);
	return (-2);
}

static int
writeBioWrite(BIO *bio, const char *in, int inl)
{
	CommandSocket *cs = currentSocket;
	SSL *ssl = reinterpret_cast<SSL *>(BIO_get_data(bio));

	if (in == nullptr || inl == 0)
		return (0);

	BIO_clear_retry_flags(bio);

	MessageRef ref = cs->sendRequest(Message::BIO_WRITE, ssl,
	    const_cast<char *>(in), inl);
	if (!ref) {
		/* XXX: Do we need to terminate the session? */
		return (-1);
	}
	const Message::Result *msg = ref.result();
	if (msg->ret == 0)
		BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
	else if (msg->ret == -1) {
		int flags;

		if (msg->bodyLength() == sizeof(flags)) {
			flags = *reinterpret_cast<const int *>(msg->body());
			BIO_set_flags(bio, flags & BIO_FLAGS_RETRY);
		} else {
			syslog(LOG_DEBUG, "%s: no flags in error reply",
			    __func__);
			/* XXX: Do we need to terminate the session? */
		}
	} else if (msg->ret > inl) {
		syslog(LOG_DEBUG, "%s: wrote too much data %ld vs %d",
		    __func__, msg->ret, inl);
		return (-1);
	}
	return (msg->ret);
}

static int
writeBioPuts(BIO *bio, const char *str)
{
	return (writeBioWrite(bio, str, strlen(str)));
}

static long
writeBioCtrl(BIO *bio, int cmd, long num, void *ptr)
{
	CommandSocket *cs = currentSocket;
	SSL *ssl = reinterpret_cast<SSL *>(BIO_get_data(bio));
	long ret;

	if (cs == nullptr) {
		syslog(LOG_WARNING, "%s: invoked without active command socket",
		    __func__);
		abort();
	}

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
	case BIO_CTRL_SET_CLOSE:
	case BIO_CTRL_FLUSH:
	{
		Message::CtrlBody body;
		body.cmd = cmd;
		body.larg = num;
		MessageRef ref = cs->sendRequest(Message::BIO_CTRL_WRITE, ssl,
		    &body, sizeof(body));
		if (!ref) {
			syslog(LOG_DEBUG, "%s: failed to get a reply",
			    __func__);
			abort();
		}
		ret = ref.result()->ret;
		break;
	}
	case BIO_CTRL_EOF:
		ret = (BIO_get_flags(bio) & BIO_FLAGS_IN_EOF) ? 1 : 0;
		break;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
		ret = 0;
		break;
	default:
		syslog(LOG_DEBUG, "%s: cmd = %d, num = %ld", __func__, cmd,
		    num);
		ret = 0;
	}
	return (ret);
}

bool
initOpenSSL()
{
	OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN, nullptr);

	readBioMethod = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
		"sslproc read");
	if (readBioMethod == nullptr)
		return (false);
	BIO_meth_set_read(readBioMethod, readBioRead);
	BIO_meth_set_write(readBioMethod, readBioWrite);
	BIO_meth_set_puts(readBioMethod, readBioPuts);
	BIO_meth_set_ctrl(readBioMethod, readBioCtrl);

	writeBioMethod = BIO_meth_new(BIO_get_new_index() |
	    BIO_TYPE_SOURCE_SINK, "sslproc write");
	if (writeBioMethod == nullptr)
		return (false);
	BIO_meth_set_read(writeBioMethod, writeBioRead);
	BIO_meth_set_write(writeBioMethod, writeBioWrite);
	BIO_meth_set_puts(writeBioMethod, writeBioPuts);
	BIO_meth_set_ctrl(writeBioMethod, writeBioCtrl);

	int error = pthread_attr_init(&attr);
	if (error != 0)
		return (false);
	error = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (error != 0)
		return (false);

	return (true);
}
