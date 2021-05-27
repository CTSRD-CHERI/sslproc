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

#include <Messages.h>
#include "SSLSession.h"
#include "sslproc_internal.h"

SSLSession::~SSLSession()
{
	close(fd);
}

bool
SSLSession::handleMessage(const Message::Header *hdr)
{
	char tmp[16];
	long ret;

	switch (hdr->type) {
	case Message::BIO_READ:
	{
		if (hdr->length != sizeof(Message::Read)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(2, "Message::BIO_READ bad length=",
			    tmp);
			return (false);
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
				PROCerr(PROC_F_SSL_HANDLE_MESSAGE,
				    ERR_R_MALLOC_FAILURE);
				ERR_add_error_data(1,
				    "failed to grow read buffer");
				return (false);
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
		ret = BIO_write(ssl->wbio, hdr->body(), hdr->bodyLength());
		int flags = BIO_get_flags(ssl->wbio);
		writeReplyMessage(hdr->type, ret, &flags, sizeof(flags));
		break;
	}
	case Message::BIO_CTRL_READ:
	case Message::BIO_CTRL_WRITE:
	{
		if (hdr->length != sizeof(Message::Ctrl)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(3,
			    hdr->type == Message::BIO_CTRL_READ ?
			    "Message::BIO_CTRL_READ" :
			    "Message::BIO_CTRL_WRITE",
			    " bad length=", tmp);
			return (false);
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);
		long ret;
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
			PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", msg->cmd);
			ERR_add_error_data(3,
			    hdr->type == Message::BIO_CTRL_READ ?
			    "Message::BIO_CTRL_READ" :
			    "Message::BIO_CTRL_WRITE",
			    " unsupported cmd=", tmp);
			return (false);
		}
		break;
	}
	case Message::MSG_CB:
	{
		if (hdr->length < sizeof(Message::MsgCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
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

		if (hdr->bodyLength() != sizeof(al)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		al = *reinterpret_cast<const int *>(hdr->body());
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

		if (hdr->bodyLength() != sizeof(al)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		al = *reinterpret_cast<const int *>(hdr->body());
		if (ssl->ctx->client_hello_cb == NULL)
			ret = 0;
		else
			ret = ssl->ctx->client_hello_cb(ssl, &al,
			    ssl->ctx->client_hello_cb_arg);
		writeReplyMessage(hdr->type, ret, &al, sizeof(al));
		break;
	}
	case Message::SRP_USERNAME_CB:
	{
		int ad;

		if (hdr->bodyLength() != sizeof(ad)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		ad = *reinterpret_cast<const int *>(hdr->body());
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
		if (hdr->length < sizeof(Message::SessNewCb)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		const Message::SessNewCb *msg =
		    reinterpret_cast<const Message::SessNewCb *>(hdr);

		if (msg->id_len <= 0 || msg->internal_length <= 0) {
			writeErrnoReply(hdr->type, -1, EBADMSG);
			break;
		}
		if (msg->length != sizeof(Message::SessNewCb) + msg->id_len +
		    msg->internal_length) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		PSSL_SESSION *s = PSSL_SESSION_new();
		if (s == nullptr) {
			writeErrnoReply(hdr->type, -1, ENOMEM);
			break;
		}

		s->time = msg->time;
		s->compress_id = msg->compress_id;
		s->id_len = msg->id_len;
		s->internal_length = msg->internal_length;
		s->id = reinterpret_cast<unsigned char *>(malloc(s->id_len));
		s->internal_repr = reinterpret_cast<unsigned char *>
		    (malloc(s->internal_length));
		if (s->id == nullptr || s->internal_repr == nullptr) {
			PSSL_SESSION_free(s);
			writeErrnoReply(hdr->type, -1, ENOMEM);
			break;
		}
		memcpy(s->id, msg->id(), s->id_len);
		memcpy(s->internal_repr, msg->internal(), s->internal_length);

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
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::SESS_REMOVE_CB:
	{
		if (hdr->bodyLength() == 0) {
			writeErrnoReply(hdr->type, -1, EBADMSG);
			break;
		}

		auto it = ssl->ctx->sessions.find(session_map_key(
		    reinterpret_cast<const unsigned char *>(hdr->body()),
		    hdr->bodyLength()));
		if (it == ssl->ctx->sessions.end()) {
			writeErrnoReply(hdr->type, -1, ENOENT);
			break;
		}

		PSSL_SESSION *s = it->second;
		ssl->ctx->sessions.erase(it);
		if (ssl->ctx->sess_remove_cb != nullptr)
			ssl->ctx->sess_remove_cb(ssl->ctx, s);
		PSSL_SESSION_free(s);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::SESS_GET_CB:
	{
		if (hdr->bodyLength() == 0) {
			writeErrnoReply(hdr->type, -1, EBADMSG);
			break;
		}

		if (ssl->ctx->sess_get_cb == nullptr) {
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			break;
		}

		int copy = 1;
		PSSL_SESSION *s = ssl->ctx->sess_get_cb(ssl,
		    reinterpret_cast<const unsigned char *>(hdr->body()),
		    hdr->bodyLength(), &copy);
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
		 * sessions via the get callback should be assume to
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

		const Message::InfoCb *msg =
		    reinterpret_cast<const Message::InfoCb *>(hdr);

		if (ssl->ctx->info_cb != nullptr)
			ssl->ctx->info_cb(ssl, msg->where, msg->ret);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::ALPN_SELECT_CB:
	{
		if (ssl->ctx->alpn_select_cb == nullptr) {
			writeReplyMessage(hdr->type, SSL_TLSEXT_ERR_NOACK);
			break;
		}

		const unsigned char *out = nullptr;
		unsigned char outlen = 0;
		ret = ssl->ctx->alpn_select_cb(ssl, &out, &outlen,
		    reinterpret_cast<const unsigned char *>(hdr->body()),
		    hdr->bodyLength(), ssl->ctx->alpn_select_cb_arg);
		writeReplyMessage(hdr->type, ret, out, outlen);
		break;
	}
	case Message::CLIENT_CERT_CB:
	{
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
	default:
		PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
		snprintf(tmp, sizeof(tmp), "%d", hdr->type);
		ERR_add_error_data(2, "unknown message type=", tmp);
		return (false);
	}

	return (true);
}
