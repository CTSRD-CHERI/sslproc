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
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <unordered_map>

#include <openssl/ssl.h>

#include "local.h"
#include "Messages.h"
#include "SSLSession.h"

static std::unordered_map<SSL *, SSLSession *> sessions;
static BIO_METHOD *readBioMethod, *writeBioMethod;

static void
msg_cb(int write_p, int version, int content_type, const void *buf,
    size_t len, SSL *ssl, void *arg)
{
	SSLSession *ss = reinterpret_cast<SSLSession *>(arg);
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
	(void)ss->sendRequest(SSLPROC_MSG_CB, iov, 2);
}

int
servername_cb(SSL *ssl, int *al, void *arg)
{
	auto it = sessions.find(ssl);
	if (it == sessions.end()) {
		syslog(LOG_WARNING, "%s: unable to locate session", __func__);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}

	SSLSession *ss = it->second;
	const Message::Result *msg = ss->sendRequest(SSLPROC_SERVERNAME_CB,
	    al, sizeof(*al));
	if (msg == nullptr)
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	if (msg->bodyLength() == sizeof(*al))
		*al = *reinterpret_cast<const int *>(msg->body());
	return (msg->ret);
}

bool
SSLSession::init(SSL_CTX *ctx)
{
	if (!inputBuffer.grow(64) || !replyBuffer.grow(64))
		return (false);

	BIO *rbio = BIO_new(readBioMethod);
	if (rbio == nullptr)
		return (false);
	BIO_set_data(rbio, this);

	BIO *wbio = BIO_new(writeBioMethod);
	if (wbio == nullptr) {
		BIO_free(rbio);
		return (false);
	}
	BIO_set_data(wbio, this);

	ssl = SSL_new(ctx);
	if (ssl == nullptr) {
		BIO_free(rbio);
		BIO_free(wbio);
		return (false);
	}
	sessions.insert({ssl, this});
	SSL_set_bio(ssl, rbio, wbio);

	/*
	 * Since inputBuffer's pointer can move due to realloc()'s,
	 * the pointer may not be the same when a partial SSL_write()
	 * is re-attempted.
	 */
	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	if (!readEvent.init())
		return (false);
	return (true);
}

SSLSession::~SSLSession()
{
	if (ssl != nullptr)
		sessions.erase(ssl);

	SSL_free(ssl);

	close(fd);
}

bool
SSLSession::handleMessage(const Message::Header *hdr)
{
	const Message::Read *readMsg;
	int ret;

	switch (hdr->type) {
	case SSLPROC_CONNECT:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_CONNECT",
			    hdr->length);
			return (false);
		}
		ret = SSL_connect(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case SSLPROC_DO_HANDSHAKE:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for SSLPROC_DO_HANDSHAKE",
			    hdr->length);
			return (false);
		}
		ret = SSL_do_handshake(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case SSLPROC_ACCEPT:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_ACCEPT",
			    hdr->length);
			return (false);
		}
		ret = SSL_accept(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case SSLPROC_SHUTDOWN:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_SHUTDOWN",
			    hdr->length);
			return (false);
		}
		ret = SSL_shutdown(ssl);
		if (ret == 1)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case SSLPROC_READ:
		if (hdr->length != sizeof(*readMsg)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_READ",
			    hdr->length);
			return (false);
		}
		readMsg = reinterpret_cast<const Message::Read *>(hdr);
		if (readMsg->resid > 0) {
			/*
			 * XXX: We could perhaps just perform a
			 * short read with whatever capacity we
			 * have if it is not zero.
			 */
			if (!readBuffer.grow(readMsg->resid)) {
				syslog(LOG_WARNING,
				    "failed to grow read buffer");
				return (false);
			}
		}
		ret = SSL_read(ssl, readBuffer.data(), readMsg->resid);
		if (ret > 0)
			writeReplyMessage(hdr->type, ret, readBuffer.data(),
			    ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case SSLPROC_WRITE:
		ret = SSL_write(ssl, hdr->body(), hdr->bodyLength());
		if (ret > 0)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	case SSLPROC_ENABLE_MSG_CB:
		SSL_set_msg_callback_arg(ssl, this);
		SSL_set_msg_callback(ssl, msg_cb);
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_DISABLE_MSG_CB:
		SSL_set_msg_callback(ssl, NULL);
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_SET_CONNECT_STATE:
		SSL_set_connect_state(ssl);
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_SET_ACCEPT_STATE:
		SSL_set_accept_state(ssl);
		writeReplyMessage(hdr->type, 0);
		break;
	case SSLPROC_IS_SERVER:
		ret = SSL_is_server(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_IN_INIT:
		ret = SSL_in_init(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_IN_BEFORE:
		ret = SSL_in_before(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_IS_INIT_FINISHED:
		ret = SSL_is_init_finished(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_GET_SERVERNAME:
	{
		int type;

		if (hdr->bodyLength() != sizeof(type)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for SSLPROC_GET_SERVERNAME",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		type = *reinterpret_cast<const int *>(hdr->body());
		const char *servername = SSL_get_servername(ssl, type);
		if (servername == nullptr)
			writeReplyMessage(hdr->type, 0);
		else
			writeReplyMessage(hdr->type, 0, servername,
			    strlen(servername));
		break;
	}
	case SSLPROC_GET_SERVERNAME_TYPE:
		ret = SSL_get_servername_type(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_CTRL:
	{
		if (hdr->length < sizeof(Message::Ctrl)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_CTRL",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);
		long ret;

		switch (msg->cmd) {
		case SSL_CTRL_SET_TLSEXT_HOSTNAME:
		{
			char *name;

			if (msg->bodyLength() == 0)
				name = NULL;
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
	case SSLPROC_SET_SHUTDOWN:
	{
		int mode;

		if (hdr->bodyLength() != sizeof(mode)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for SSLPROC_SET_SHUTDOWN",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		mode = *reinterpret_cast<const int *>(hdr->body());
		SSL_set_shutdown(ssl, mode);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_GET_SHUTDOWN:
		ret = SSL_get_shutdown(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_GET_PEER_CERTIFICATE:
	{
		X509 *x = SSL_get_peer_certificate(ssl);
		if (x == NULL) {
			writeReplyMessage(hdr->type, 0);
			break;
		}

		unsigned char *buf = NULL;
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
	case SSLPROC_GET_VERIFY_RESULT:
		ret = SSL_get_verify_result(ssl);
		writeReplyMessage(hdr->type, ret);
		break;
	case SSLPROC_SET_VERIFY_RESULT:
	{
		long result;

		if (hdr->bodyLength() != sizeof(long)) {
			syslog(LOG_WARNING,
		    "invalid message length %d for SSLPROC_SET_VERIFY_RESULT",
			    hdr->length);
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			break;
		}
		result = *reinterpret_cast<const long *>(hdr->body());
		SSL_set_verify_result(ssl, result);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_SET_ALPN_PROTOS:
	{
		const unsigned char *protos;

		if (hdr->bodyLength() == 0)
			protos = nullptr;
		else
			protos = reinterpret_cast<const unsigned char *>
			    (hdr->body());
		ret = SSL_set_alpn_protos(ssl, protos, hdr->bodyLength());
		if (ret != 0)
			writeSSLErrorReply(hdr->type, ret, SSL_ERROR_SSL);
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_GET_SRP_USERNAME:
	{
		const char *s = SSL_get_srp_username(ssl);
		if (s != nullptr)
			writeReplyMessage(hdr->type, 0, s, strlen(s));
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	case SSLPROC_GET_SRP_USERINFO:
	{
		const char *s = SSL_get_srp_userinfo(ssl);
		if (s != nullptr)
			writeReplyMessage(hdr->type, 0, s, strlen(s));
		else
			writeReplyMessage(hdr->type, 0);
		break;
	}
	default:
		syslog(LOG_WARNING, "unknown session request %d", hdr->type);
		return (false);
	}

	return (true);
}

void
SSLSession::onEvent(const struct kevent *kevent)
{
	int rc, resid;

	if (kevent->flags & EV_EOF) {
		delete this;
		return;
	}

	resid = kevent->data;
	while (resid > 0) {
		rc = readMessage(inputBuffer);
		if (rc == 0 || rc == -1) {
			delete this;
			return;
		}

		assert(inputBuffer.length() <= resid);
		resid -= inputBuffer.length();

		if (!handleMessage(inputBuffer.hdr()) || writeFailed) {
			delete this;
			return;
		}
	}
}

void
SSLSession::observeReadError(enum ReadError error, const Message::Header *hdr)
{
	switch (error) {
	case READ_ERROR:
		syslog(LOG_WARNING, "failed to read from session message: %m");
		break;
	case SHORT:
		syslog(LOG_WARNING, "session message too short");
		break;
	case TRUNCATED:
		syslog(LOG_WARNING, "session message truncated");
		break;
	case BAD_MSG_LENGTH:
		syslog(LOG_WARNING, "invalid session message length %d",
		    hdr->length);
		break;
	case LENGTH_MISMATCH:
		syslog(LOG_WARNING, "session message length mismatch");
		break;
	}
}

void
SSLSession::observeWriteError()
{
	syslog(LOG_WARNING, "failed to write message on session socket: %m");
	writeFailed = true;
}

const Message::Result *
SSLSession::sendRequest(int type, struct iovec *iov, int iovCnt)
{
	if (!writeMessage(type, iov, iovCnt)) {
		syslog(LOG_DEBUG, "%s: failed to send request %d: %m", __func__,
		    type);
		return (nullptr);
	}

	return (_waitForReply(type));
}

const Message::Result *
SSLSession::sendRequest(int type, const void *payload, size_t payloadLen)
{
	if (!writeMessage(type, payload, payloadLen)) {
		syslog(LOG_DEBUG, "%s: failed to send request %d: %m", __func__,
		    type);
		return (nullptr);
	}

	return (_waitForReply(type));
}

const Message::Result *
SSLSession::_waitForReply(int type)
{
	const Message::Result *msg;
	int rc;

	rc = readMessage(replyBuffer);
	if (rc == 0) {
		syslog(LOG_DEBUG, "%s: EOF from session fd", __func__);
		return (nullptr);
	}
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read reply: %m", __func__);
		return (nullptr);
	}
	msg = reinterpret_cast<const Message::Result *>(replyBuffer.hdr());
	if (msg->type != SSLPROC_RESULT) {
		syslog(LOG_DEBUG, "%s: unexpected reply message %d", __func__,
		    msg->type);
		return (nullptr);
	}
	if (msg->request != type) {
		syslog(LOG_DEBUG, "%s: reply mismatch", __func__);
		return (nullptr);
	}
	return (msg);
}

/*
 * BIO flags to copy from the other end.
 */
#define	BIO_FLAGS_RETRY	(BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY)

static int
readBioRead(BIO *bio, char *out, int outl)
{
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	const Message::Result *msg;
	int resid;

	if (out == nullptr || outl == 0)
		return (0);

	BIO_clear_retry_flags(bio);

	resid = outl;
	msg = ss->sendRequest(SSLPROC_BIO_READ, &resid, sizeof(resid));
	if (msg == nullptr) {
		/* XXX: Do we need to terminate the session? */
		return (-1);
	}
	if (msg->ret == 0)
		BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
	else if (msg->ret == -1) {
		int flags;

		if (msg->bodyLength() == sizeof(flags)) {
			flags = *reinterpret_cast<const int *>(msg->body());
			BIO_set_flags(bio, flags & BIO_FLAGS_RETRY);
		} else {
			syslog(LOG_DEBUG, "%s: no flags in error reply", __func__);
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
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	Message::CtrlBody body;
	const Message::Result *msg;
	long ret;

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
	case BIO_CTRL_SET_CLOSE:
	case BIO_CTRL_FLUSH:
		body.cmd = cmd;
		body.larg = num;
		msg = ss->sendRequest(SSLPROC_BIO_CTRL_READ, &body,
		    sizeof(body));
		if (msg == nullptr) {
			syslog(LOG_DEBUG, "%s: failed to get a reply",
			    __func__);

			/* XXX: Only terminate session instead? */
			abort();
		}
		ret = msg->ret;
		break;
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
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	const Message::Result *msg;

	if (in == nullptr || inl == 0)
		return (0);

	BIO_clear_retry_flags(bio);

	msg = ss->sendRequest(SSLPROC_BIO_WRITE, const_cast<char *>(in), inl);
	if (msg == nullptr) {
		/* XXX: Do we need to terminate the session? */
		return (-1);
	}
	if (msg->ret == 0)
		BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
	else if (msg->ret == -1) {
		int flags;

		if (msg->bodyLength() == sizeof(flags)) {
			flags = *reinterpret_cast<const int *>(msg->body());
			BIO_set_flags(bio, flags & BIO_FLAGS_RETRY);
		} else {
			syslog(LOG_DEBUG, "%s: no flags in error reply", __func__);
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
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	Message::CtrlBody body;
	const Message::Result *msg;
	long ret;

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
	case BIO_CTRL_SET_CLOSE:
	case BIO_CTRL_FLUSH:
		body.cmd = cmd;
		body.larg = num;
		msg = ss->sendRequest(SSLPROC_BIO_CTRL_WRITE, &body,
		    sizeof(body));
		if (msg == nullptr) {
			syslog(LOG_DEBUG, "%s: failed to get a reply",
			    __func__);

			/* XXX: Only terminate session instead? */
			abort();
		}
		ret = msg->ret;
		break;
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
	return (true);
}
