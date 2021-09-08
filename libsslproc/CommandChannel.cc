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

#include <openssl/ssl.h>

#include <Messages.h>
#include "CommandChannel.h"
#include "TargetStore.h"
#include "sslproc_internal.h"

bool
CommandChannel::init()
{
#ifdef HAVE_COCALL
	if (!MessageCoCall::init())
		return (false);

	/*
	 * cocall cannot resize buffers for receive on demand as the
	 * messages just get truncated and dropped instead.  The 16k
	 * is just hoping that BIO_read/write don't request more than
	 * that.
	 */
	if (!allocateMessages(4, 16384 + 512))
		return (false);
#else
	if (!allocateMessages(4, 64))
		return (false);
#endif
	return (true);
}

static PSSL *
findSSL(const Message::Targeted *thdr)
{
	return (targets.lookup<PSSL>(thdr->target));
}

static PSSL_CTX *
findSSL_CTX(const Message::Targeted *thdr)
{
	return (targets.lookup<PSSL_CTX>(thdr->target));
}

void
CommandChannel::handleMessage(const Message::Header *hdr)
{
	const Message::Targeted *thdr;
	PSSL_CTX *ctx;
	PSSL *ssl;
	char tmp[16];
	long ret;

	if (hdr->length < sizeof(Message::Targeted))
		thdr = nullptr;
	else
		thdr = reinterpret_cast<const Message::Targeted *>(hdr);
	switch (hdr->type) {
	case Message::BIO_READ:
	{
		if (hdr->length != sizeof(Message::Read)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(2, "Message::BIO_READ bad length=",
			    tmp);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_MISSING_TARGET);
			snprintf(tmp, sizeof(tmp), "%d", thdr->target);
			ERR_add_error_data(2, "target=", tmp);
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
				PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
				    ERR_R_MALLOC_FAILURE);
				ERR_add_error_data(1,
				    "failed to grow read buffer");
				break;
			}
		}

		ret = BIO_read(ssl->rbio, readBuffer.data(), msg->resid);
		if (ret > 0)
			writeReplyMessage(hdr->type, ret, readBuffer.data(),
			    ret);
		else {
			int flags = BIO_get_flags(ssl->rbio);
			writeReplyMessage(hdr->type, ret, &flags,
			    sizeof(flags));
		}
		break;
	}
	case Message::BIO_WRITE:
	{
		if (thdr == nullptr) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(2, "Message::BIO_WRITE bad length=",
			    tmp);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_MISSING_TARGET);
			snprintf(tmp, sizeof(tmp), "%d", thdr->target);
			ERR_add_error_data(2, "target=", tmp);
			break;
		}

		ret = BIO_write(ssl->wbio, thdr->body(), thdr->bodyLength());
		int flags = BIO_get_flags(ssl->wbio);
		writeReplyMessage(hdr->type, ret, &flags, sizeof(flags));
		break;
	}
	case Message::BIO_CTRL_READ:
	case Message::BIO_CTRL_WRITE:
	{
		if (hdr->length != sizeof(Message::Ctrl)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(3,
			    hdr->type == Message::BIO_CTRL_READ ?
			    "Message::BIO_CTRL_READ" :
			    "Message::BIO_CTRL_WRITE",
			    " bad length=", tmp);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_MISSING_TARGET);
			snprintf(tmp, sizeof(tmp), "%d", thdr->target);
			ERR_add_error_data(2, "target=", tmp);
			break;
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);
		BIO *bio;

		if (hdr->type == Message::BIO_CTRL_READ)
			bio = ssl->rbio;
		else
			bio = ssl->wbio;

		switch (msg->cmd) {
		case BIO_CTRL_GET_CLOSE:
		case BIO_CTRL_SET_CLOSE:
		case BIO_CTRL_FLUSH:
			ret = BIO_ctrl(bio, msg->cmd, msg->larg, nullptr);
			writeReplyMessage(hdr->type, ret);
			break;
		default:
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE,
			    ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", msg->cmd);
			ERR_add_error_data(3,
			    hdr->type == Message::BIO_CTRL_READ ?
			    "Message::BIO_CTRL_READ" :
			    "Message::BIO_CTRL_WRITE",
			    " unsupported cmd=", tmp);
			break;
		}
		break;
	}
	case Message::MSG_CB:
	{
		if (hdr->length < sizeof(Message::MsgCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::MsgCb *msg =
		    reinterpret_cast<const Message::MsgCb *>(hdr);

		if (ssl->msg_cb != NULL)
			ssl->msg_cb(msg->write_p, msg->version, msg->content_type,
			    msg->body(), msg->bodyLength(), ssl, ssl->msg_cb_arg);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::SERVERNAME_CB:
	{
		int al;

		if (thdr == nullptr || thdr->bodyLength() != sizeof(al)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		al = *reinterpret_cast<const int *>(thdr->body());
		if (ssl->ctx->servername_cb == NULL)
			ret = SSL_TLSEXT_ERR_ALERT_FATAL;
		else
			ret = ssl->ctx->servername_cb(ssl, &al,
			    ssl->ctx->servername_cb_arg);
		writeReplyMessage(hdr->type, ret, &al, sizeof(al));
		break;
	}
	case Message::CLIENT_HELLO_CB:
	{
		int al;

		if (thdr == nullptr || thdr->bodyLength() != sizeof(al)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		al = *reinterpret_cast<const int *>(thdr->body());
		if (ssl->ctx->client_hello_cb == NULL)
			ret = 0;
		else {
			ret = ssl->ctx->client_hello_cb(ssl, &al,
			    ssl->ctx->client_hello_cb_arg);
			while (!ssl->client_hello_exts.empty()) {
				free(ssl->client_hello_exts.front());
				ssl->client_hello_exts.pop_front();
			}
		}
		writeReplyMessage(hdr->type, ret, &al, sizeof(al));
		break;
	}
	case Message::SRP_USERNAME_CB:
	{
		int ad;

		if (thdr == nullptr || thdr->bodyLength() != sizeof(ad)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		ad = *reinterpret_cast<const int *>(thdr->body());
		if (ssl->ctx->srp_username_cb == NULL)
			ret = SSL_ERROR_NONE;
		else
			ret = ssl->ctx->srp_username_cb(ssl, &ad,
			    ssl->ctx->srp_cb_arg);
		writeReplyMessage(hdr->type, ret, &ad, sizeof(ad));
		break;
	}
	case Message::SESS_NEW_CB:
	{
		if (hdr->length < sizeof(Message::SessCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		const Message::SessCb *msg =
		    reinterpret_cast<const Message::SessCb *>(hdr);

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		PSSL_SESSION *s = PSSL_SESSION_new();
		if (s == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOMEM);
			break;
		}

		s->target = msg->session;
		s->id_len = msg->idLength();
		s->id = reinterpret_cast<unsigned char *>(malloc(s->id_len));
		if (s->id == nullptr) {
			PSSL_SESSION_free(s);
			writeErrnoReply(hdr->type, -1, ENOMEM);
			break;
		}
		memcpy(s->id, msg->id(), s->id_len);

		/*
		 * Locally created PSSL_SESSION objects are stored in
		 * a hash table so that the original pointer passed to
		 * the new session callback below is also passed in a
		 * future remove callback.
		 */
		auto res = ssl->ctx->sessions.emplace(
		    session_map_key(s->id, s->id_len), s);
		if (!res.second) {
			PSSL_SESSION_free(s);
			writeErrnoReply(hdr->type, -1, EEXIST);
			break;
		}

		if (ssl->ctx->sess_new_cb != nullptr) {
			PSSL_SESSION_up_ref(s);
			if (ssl->ctx->sess_new_cb(ssl, s) == 0)
				PSSL_SESSION_free(s);
		}
		s->target = NULL_TARGET;
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::SESS_REMOVE_CB:
	{
		if (hdr->length < sizeof(Message::SessCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		const Message::SessCb *msg =
		    reinterpret_cast<const Message::SessCb *>(hdr);

		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		auto it = ctx->sessions.find(session_map_key(
		    reinterpret_cast<const unsigned char *>(msg->id()),
		    msg->idLength()));
		if (it == ctx->sessions.end()) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		PSSL_SESSION *s = it->second;
		ctx->sessions.erase(it);
		s->target = msg->session;
		if (ctx->sess_remove_cb != nullptr)
			ctx->sess_remove_cb(ctx, s);
		PSSL_SESSION_free(s);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::SESS_GET_CB:
	{
		if (thdr == nullptr || thdr->bodyLength() == 0) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (ssl->ctx->sess_get_cb == nullptr) {
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			break;
		}

		int copy = 1;
		PSSL_SESSION *s = ssl->ctx->sess_get_cb(ssl,
		    reinterpret_cast<const unsigned char *>(thdr->body()),
		    thdr->bodyLength(), &copy);
		if (s == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}
		if (copy)
			PSSL_SESSION_up_ref(s);
		if (s->internal_length == 0 || s->id_len == 0 ||
		    s->internal_repr == nullptr || s->id == nullptr) {
			PSSL_SESSION_free(s);
			writeErrnoReply(hdr->type, -1, EINVAL);
			break;
		}

		/*
		 * XXX: Is it correct to assume that newly created
		 * sessions via the get callback should be assumed to
		 * already be cached and subject to a future remove
		 * callback?
		 */
		auto res = ssl->ctx->sessions.emplace(
		    session_map_key(s->id, s->id_len), s);
		if (!res.second) {
			PSSL_SESSION_free(s);
			writeErrnoReply(hdr->type, -1, EEXIST);
			break;
		}
		writeReplyMessage(hdr->type, 0, s->internal_repr,
		    s->internal_length);
		break;
	}
	case Message::TMP_DH_CB:
	{
		if (hdr->length != sizeof(Message::TmpDhCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::TmpDhCb *msg =
		    reinterpret_cast<const Message::TmpDhCb *>(hdr);

		if (ssl->ctx->tmp_dh_cb == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		DH *dh = ssl->ctx->tmp_dh_cb(ssl, msg->is_export,
		    msg->keylength);
		if (dh == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		unsigned char *asn1 = nullptr;
		int len = i2d_DHparams(dh, &asn1);
		DH_free(dh);
		if (len <= 0) {
			writeReplyMessage(hdr->type, 0);
			break;
		}
		writeReplyMessage(hdr->type, 0, asn1, len);
		OPENSSL_free(asn1);
		break;
	}
	case Message::INFO_CB:
	{
		if (hdr->length != sizeof(Message::InfoCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::InfoCb *msg =
		    reinterpret_cast<const Message::InfoCb *>(hdr);

		if (ssl->ctx->info_cb != nullptr)
			ssl->ctx->info_cb(ssl, msg->where, msg->ret);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::ALPN_SELECT_CB:
	{
		if (thdr == nullptr) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (ssl->ctx->alpn_select_cb == nullptr) {
			writeReplyMessage(hdr->type, SSL_TLSEXT_ERR_NOACK);
			break;
		}

		const unsigned char *out = nullptr;
		unsigned char outlen = 0;
		ret = ssl->ctx->alpn_select_cb(ssl, &out, &outlen,
		    reinterpret_cast<const unsigned char *>(thdr->body()),
		    thdr->bodyLength(), ssl->ctx->alpn_select_cb_arg);
		writeReplyMessage(hdr->type, ret, out, outlen);
		break;
	}
	case Message::CLIENT_CERT_CB:
	{
		if (thdr == nullptr) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		if (ssl->ctx->client_cert_cb == nullptr) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		X509 *cert = nullptr;
		EVP_PKEY *pkey = nullptr;
		int ret = ssl->ctx->client_cert_cb(ssl, &cert, &pkey);
		if (ret != 1) {
			X509_free(cert);
			EVP_PKEY_free(pkey);
			writeReplyMessage(hdr->type, ret);
			break;
		}

		Message::ClientCertCbResultBody body;
		unsigned char *cert_buf = nullptr;
		body.cert_len = i2d_X509(cert, &cert_buf);
		if (body.cert_len < 0) {
			X509_free(cert);
			EVP_PKEY_free(pkey);
			writeReplyMessage(hdr->type, -1);
			break;
		}
		X509_free(cert);

		unsigned char *pkey_buf = nullptr;
		body.pk_len = i2d_PrivateKey(pkey, &pkey_buf);
		if (body.pk_len < 0) {
			OPENSSL_free(cert_buf);
			EVP_PKEY_free(pkey);
			writeReplyMessage(hdr->type, -1);
			break;
		}
		body.pktype = EVP_PKEY_base_id(pkey);
		EVP_PKEY_free(pkey);

		struct iovec iov[3];
		iov[0].iov_base = &body;
		iov[0].iov_len = sizeof(body);
		iov[1].iov_base = cert_buf;
		iov[1].iov_len = body.cert_len;
		iov[2].iov_base = pkey_buf;
		iov[2].iov_len = body.pk_len;
		writeReplyMessage(hdr->type, 1, iov, 3);
		OPENSSL_free(cert_buf);
		OPENSSL_free(pkey_buf);
		break;
	}
	case Message::VERIFY_CB:
	{
		if (hdr->length < sizeof(Message::VerifyCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::VerifyCb *msg =
		    reinterpret_cast<const Message::VerifyCb *>(hdr);

		X509 *cert;
		const unsigned char *pp =
		    reinterpret_cast<const unsigned char *>(msg->cert());
		if (msg->certLength() == 0) {
			cert = nullptr;
		} else {
			cert = d2i_X509(nullptr, &pp, msg->certLength());
			if (cert == nullptr) {
				writeErrnoReply(hdr->type, -1, EBADMSG);
				break;
			}
		}

		X509_STORE_CTX *x509_ctx = X509_STORE_CTX_new();
		if (x509_ctx == nullptr) {
			X509_free(cert);
			writeErrnoReply(hdr->type, -1, ENOMEM);
			break;
		}

		X509_STORE_CTX_set_ex_data(x509_ctx,
		    PSSL_get_ex_data_X509_STORE_CTX_idx(), ssl);

		X509_STORE_CTX_set_error(x509_ctx, msg->x509_error);
		X509_STORE_CTX_set_error_depth(x509_ctx, msg->x509_error_depth);
		X509_STORE_CTX_set_current_cert(x509_ctx, cert);

		ret = ssl->verify_cb(msg->preverify_ok, x509_ctx);

		X509_STORE_CTX_free(x509_ctx);
		X509_free(cert);

		int x509_error = X509_STORE_CTX_get_error(x509_ctx);
		writeReplyMessage(hdr->type, ret, &x509_error,
		    sizeof(x509_error));
		break;
	}
	case Message::DEFAULT_PASSWD_CB:
	{
		if (hdr->length < sizeof(Message::DefaultPasswdCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ssl = findSSL(thdr);
		if (ssl == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::DefaultPasswdCb *msg =
		    reinterpret_cast<const Message::DefaultPasswdCb *>(hdr);

		char buf[msg->bufLength()];
		memcpy(buf, msg->buf(), msg->bufLength());

		int ret = ssl->default_passwd_cb(buf, sizeof(buf), msg->rwflag,
		    ssl->default_passwd_cb_userdata);
		if (ret <= 0)
			writeReplyMessage(hdr->type, ret);
		else if (ret > sizeof(buf))
			writeErrnoReply(hdr->type, -1, E2BIG);
		else
			writeReplyMessage(hdr->type, ret, buf, ret);
		break;
	}
	case Message::CTX_DEFAULT_PASSWD_CB:
	{
		if (hdr->length < sizeof(Message::DefaultPasswdCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ctx = findSSL_CTX(thdr);
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		const Message::DefaultPasswdCb *msg =
		    reinterpret_cast<const Message::DefaultPasswdCb *>(hdr);

		char buf[msg->bufLength()];
		memcpy(buf, msg->buf(), msg->bufLength());

		int ret = ctx->default_passwd_cb(buf, sizeof(buf), msg->rwflag,
		    ctx->default_passwd_cb_userdata);
		if (ret <= 0)
			writeReplyMessage(hdr->type, ret);
		else if (ret > sizeof(buf))
			writeErrnoReply(hdr->type, -1, E2BIG);
		else
			writeReplyMessage(hdr->type, ret, buf, ret);
		break;
	}
	default:
		PROCerr(PROC_F_CMDSOCK_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
		snprintf(tmp, sizeof(tmp), "%d", hdr->type);
		ERR_add_error_data(2, "unknown message type=", tmp);
		break;
	}
}
