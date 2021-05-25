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

#include <assert.h>
#include <capsicum_helpers.h>
#include <errno.h>
#include <syslog.h>

#include <openssl/ssl.h>

#include "local.h"
#include "KEvent.h"
#include "Messages.h"
#include "MessageBuffer.h"
#include "MessageSocket.h"
#include "ControlSocket.h"
#include "SSLSession.h"

bool
ControlSocket::init()
{
	if (!inputBuffer.grow(64) ||
	    !inputBuffer.controlAlloc(CMSG_SPACE(sizeof(int))))
		return (false);
	if (!readEvent.init())
		return (false);
	return (true);
}

void
ControlSocket::handleMessage(const Message::Header *hdr,
    const struct cmsghdr *cmsg)
{
	int *fds;

	switch (hdr->type) {
	case SSLPROC_NOP:
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_CREATE_CONTEXT:
	{
		if (hdr->length != sizeof(Message::CreateContext)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		if (ctx != nullptr) {
			writeErrnoReply(hdr->type, -1, EBUSY);
			break;
		}

		const Message::CreateContext *msg =
		    reinterpret_cast<const Message::CreateContext *>(hdr);
		const SSL_METHOD *method = nullptr;
		switch (msg->method) {
		case SSLPROC_METHOD_TLS:
			method = TLS_method();
			break;
		case SSLPROC_METHOD_TLS_SERVER:
			method = TLS_server_method();
			break;
		case SSLPROC_METHOD_TLS_CLIENT:
			method = TLS_client_method();
			break;
		}
		if (method == nullptr) {
			writeErrnoReply(hdr->type, -1, EINVAL);
			break;
		}

		ctx = SSL_CTX_new(method);
		if (ctx == NULL)
			writeSSLErrorReply(hdr->type, -1, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_CTX_SET_OPTIONS:
	case SSLPROC_CTX_CLEAR_OPTIONS:
	{
		if (hdr->length != sizeof(Message::Options)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		const Message::Options *msg =
		    reinterpret_cast<const Message::Options *>(hdr);
		long options;

		if (hdr->type == SSLPROC_CTX_SET_OPTIONS)
			options = SSL_CTX_set_options(ctx, msg->options);
		else
			options = SSL_CTX_clear_options(ctx, msg->options);
		writeReplyMessage(hdr->type, 0, &options, sizeof(options));
		break;
	}
	case SSLPROC_CTX_GET_OPTIONS:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		long options = SSL_CTX_get_options(ctx);
		writeReplyMessage(hdr->type, 0, &options, sizeof(options));
		break;
	}
	case SSLPROC_CTX_CTRL:
	{
		if (hdr->length != sizeof(Message::Ctrl)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);
		long ret;

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
		default:
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			break;
		}
		break;
	}
	case SSLPROC_CTX_USE_CERTIFICATE_ASN1:
	{
		if (hdr->bodyLength() == 0) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		int ret = SSL_CTX_use_certificate_ASN1(ctx, hdr->bodyLength(),
		    reinterpret_cast<const unsigned char *>(hdr->body()));
		if (ret != 1)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 1);
		break;
	}
	case SSLPROC_CTX_USE_PRIVATEKEY_ASN1:
	{
		if (hdr->length <= sizeof(Message::PKey)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		const Message::PKey *msg =
		    reinterpret_cast<const Message::PKey *>(hdr);
		int ret = SSL_CTX_use_PrivateKey_ASN1(msg->pktype, ctx,
		    reinterpret_cast<const unsigned char *>(msg->key()),
		    msg->keyLength());
		if (ret != 1)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 1);
		break;
	}
	case SSLPROC_CTX_CHECK_PRIVATE_KEY:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		int ret = SSL_CTX_check_private_key(ctx);
		if (ret != 1)
			writeSSLErrorReply(hdr->type, 0, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 1);
		break;
	}
	case SSLPROC_CTX_ENABLE_SERVERNAME_CB:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		int ret = SSL_CTX_set_tlsext_servername_callback(ctx,
		    servername_cb);
		writeReplyMessage(hdr->type, ret);
		break;
	}
	case SSLPROC_CTX_DISABLE_SERVERNAME_CB:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		int ret = SSL_CTX_set_tlsext_servername_callback(ctx, nullptr);
		writeReplyMessage(hdr->type, ret);
		break;
	}
	case SSLPROC_CTX_ENABLE_CLIENT_HELLO_CB:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_CTX_DISABLE_CLIENT_HELLO_CB:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		SSL_CTX_set_client_hello_cb(ctx, nullptr, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_CTX_ENABLE_SRP_USERNAME_CB:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		SSL_CTX_set_srp_username_callback(ctx, srp_username_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_CTX_DISABLE_SRP_USERNAME_CB:
	{
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}

		SSL_CTX_set_srp_username_callback(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_CTX_ENABLE_SESS_CBS:
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}
		SSL_CTX_sess_set_new_cb(ctx, sess_new_cb);
		SSL_CTX_sess_set_remove_cb(ctx, sess_remove_cb);
		SSL_CTX_sess_set_get_cb(ctx, sess_get_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_CTX_DISABLE_SESS_CBS:
		if (ctx == nullptr) {
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}
		SSL_CTX_sess_set_new_cb(ctx, nullptr);
		SSL_CTX_sess_set_remove_cb(ctx, nullptr);
		SSL_CTX_sess_set_get_cb(ctx, nullptr);
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_CREATE_SESSION:
	{
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
			syslog(LOG_WARNING,
		    "invalid control message for SSLPROC_CREATE_SESSION");
			writeErrnoReply(hdr->type, -1, EBADMSG);
			break;
		}

		fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));

		cap_rights_t rights;
		cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
		if (caph_rights_limit(fds[0], &rights) < 0) {
			int error = errno;
			close(fds[0]);
			syslog(LOG_WARNING,
			    "failed to restrict session socket: %m");
			writeErrnoReply(hdr->type, -1, error);
			break;
		}

		SSLSession *ss = new SSLSession(kq, fds[0]);
		if (!ss->init(ctx)) {
			syslog(LOG_WARNING, "failed to init SSL sesssion");
			delete ss;
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}
		writeReplyMessage(hdr->type, 0);
		break;
	}
	default:
		syslog(LOG_WARNING, "unknown control request %d", hdr->type);
	}
}

void
ControlSocket::onEvent(const struct kevent *kevent)
{
	int rc, resid;

	if (kevent->flags & EV_EOF)
		exit(0);

	resid = kevent->data;
	while (resid > 0) {
		rc = readMessage(inputBuffer);
		if (rc == 0)
			exit(0);
		if (rc == -1)
			exit(1);

		assert(inputBuffer.length() <= resid);
		resid -= inputBuffer.length();

		handleMessage(inputBuffer.hdr(), inputBuffer.cmsg());
	}
}

void
ControlSocket::observeReadError(enum ReadError error,
    const Message::Header *hdr)
{
	switch (error) {
	case READ_ERROR:
		syslog(LOG_WARNING, "failed to read from control socket: %m");
		break;
	case SHORT:
		syslog(LOG_WARNING, "control message too short");
		break;
	case TRUNCATED:
		syslog(LOG_WARNING, "control message truncated");
		break;
	case BAD_MSG_LENGTH:
		syslog(LOG_WARNING, "invalid control message length %d",
		    hdr->length);
		break;
	case LENGTH_MISMATCH:
		syslog(LOG_WARNING, "control message length mismatch");
		break;
	}
}

void
ControlSocket::observeWriteError()
{
	syslog(LOG_WARNING, "failed to write message on control socket: %m");
	exit(1);
}
