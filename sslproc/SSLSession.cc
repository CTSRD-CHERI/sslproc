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

#include <openssl/ssl.h>

#include <sslproc_msg.h>

#include "local.h"
#include "SSLSession.h"

static BIO_METHOD *rawBioMethod;

bool
SSLSession::init()
{
	if (!inputBuffer.grow(64) || !replyBuffer.grow(64))
		return (false);

	BIO *bio = BIO_new(rawBioMethod);
	if (bio == nullptr)
		return (false);
	BIO_set_data(bio, this);

	ssl = SSL_new(sslCtx);
	if (ssl == nullptr) {
		BIO_free(bio);
		return (false);
	}
	SSL_set_bio(ssl, bio, bio);

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
	SSL_free(ssl);

	close(fd);
}

bool
SSLSession::handleMessage(const struct sslproc_message_header *hdr)
{
	const struct sslproc_message_read *readMsg;
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
		readMsg = reinterpret_cast<const struct sslproc_message_read *>
		    (hdr);
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
		if (hdr->length < sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_WRITE",
			    hdr->length);
			return (false);
		}
		ret = SSL_write(ssl, hdr + 1, hdr->length - sizeof(*hdr));
		if (ret > 0)
			writeReplyMessage(hdr->type, ret);
		else
			writeSSLErrorReply(hdr->type, ret,
			    SSL_get_error(ssl, ret));
		break;
	default:
		syslog(LOG_WARNING, "unknown app request %d", hdr->type);
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
		if (rc == 0) {
			syslog(LOG_WARNING, "session fd is closed");
			delete this;
			return;
		}
		if (rc == -1) {
			syslog(LOG_WARNING,
			    "failed to read session message: %m");
			delete this;
			return;
		}

		assert(inputBuffer.length() <= resid);
		resid -= inputBuffer.length();

		if (!handleMessage(inputBuffer.hdr()) || hasWriteError()) {
			delete this;
			return;
		}
	}
}

int
SSLSession::rawRead(char *out, int outl)
{
	const struct sslproc_message_result *resultMsg;
	int rc, resid;

	resid = outl;
	if (!writeMessage(SSLPROC_READ_RAW, &resid, sizeof(resid))) {
		syslog(LOG_DEBUG,
		    "failed to send SSLPROC_READ_RAW request: %m");
		errno = EIO;
		return (-1);
	}

	rc = readMessage(replyBuffer);
	if (rc == 0) {
		syslog(LOG_DEBUG, "%s: EOF from session fd", __func__);
		errno = EIO;
		return (-1);
	}
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read reply: %m", __func__);
		errno = EIO;
		return (-1);
	}
	resultMsg = reinterpret_cast<const struct sslproc_message_result *>
	    (replyBuffer.hdr());
	if (resultMsg->type != SSLPROC_RESULT) {
		syslog(LOG_DEBUG, "%s: unexpected reply message %d", __func__,
		    resultMsg->type);
		errno = EIO;
		return (-1);
	}
	if (resultMsg->request != SSLPROC_READ_RAW) {
		syslog(LOG_DEBUG, "%s: reply mismatch", __func__);
		errno = EIO;
		return (-1);
	}

	if (resultMsg->ret == -1) {
		errno = *(int *)(resultMsg + 1);
		return (-1);
	}

	if (resultMsg->ret < 0) {
		syslog(LOG_DEBUG, "%s: invalid result %d", __func__,
		    resultMsg->ret);
		errno = EIO;
		return (-1);
	}
	if (resultMsg->ret > outl) {
		syslog(LOG_DEBUG, "%s: returned too much data %d vs %d",
		    __func__, resultMsg->ret, outl);
		errno = EIO;
		return (-1);
	}

	/* Copy, ugh */
	memcpy(out, resultMsg + 1, resultMsg->ret);
	return (resultMsg->ret);
}

int
SSLSession::rawWrite(const char *in, int inl)
{
	const struct sslproc_message_result *resultMsg;
	int rc;

	if (!writeMessage(SSLPROC_WRITE_RAW, const_cast<char *>(in), inl)) {
		syslog(LOG_DEBUG,
		    "failed to send SSLPROC_WRITE_RAW request: %m");
		errno = EIO;
		return (-1);
	}

	rc = readMessage(replyBuffer);
	if (rc == 0) {
		syslog(LOG_DEBUG, "%s: EOF from session fd", __func__);
		errno = EIO;
		return (-1);
	}
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read reply: %m", __func__);
		errno = EIO;
		return (-1);
	}
	resultMsg = reinterpret_cast<const struct sslproc_message_result *>
	    (replyBuffer.hdr());
	if (resultMsg->type != SSLPROC_RESULT) {
		syslog(LOG_DEBUG, "%s: unexpected reply message %d", __func__,
		    resultMsg->type);
		errno = EIO;
		return (-1);
	}
	if (resultMsg->request != SSLPROC_WRITE_RAW) {
		syslog(LOG_DEBUG, "%s: reply mismatch", __func__);
		errno = EIO;
		return (-1);
	}

	if (resultMsg->ret == -1) {
		errno = *(int *)(resultMsg + 1);
		return (-1);
	}

	if (resultMsg->ret < 0) {
		syslog(LOG_DEBUG, "%s: invalid result %d", __func__,
		    resultMsg->ret);
		errno = EIO;
		return (-1);
	}
	if (resultMsg->ret > inl) {
		syslog(LOG_DEBUG, "%s: write too much data %d vs %d",
		    __func__, resultMsg->ret, inl);
		errno = EIO;
		return (-1);
	}

	return (resultMsg->ret);
}

static int
rawBioRead(BIO *bio, char *out, int outl)
{
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	int ret;

	if (out == nullptr || outl == 0)
		return (0);

	ret = ss->rawRead(out, outl);

	BIO_clear_retry_flags(bio);
	if (ret == 0)
		BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
	else if (ret == -1 && (errno == EAGAIN || errno == EINTR))
		BIO_set_retry_read(bio);
	return (ret);
}

static int
rawBioWrite(BIO *bio, const char *in, int inl)
{
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	int ret;

	if (in == nullptr || inl == 0)
		return (0);

	ret = ss->rawWrite(in, inl);

	BIO_clear_retry_flags(bio);
	if (ret == 0)
		BIO_set_flags(bio, BIO_FLAGS_IN_EOF);
	else if (ret == -1 && (errno == EAGAIN || errno == EINTR))
		BIO_set_retry_write(bio);
	return (ret);
}

static long
rawBioCtrl(BIO *bio, int cmd, long num, void *ptr)
{
	long ret;

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
		ret = (long)BIO_get_shutdown(bio);
		break;
	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(bio, (int)num);
		break;
	case BIO_CTRL_EOF:
		ret = (BIO_get_flags(bio) & BIO_FLAGS_IN_EOF) ? 1 : 0;
		break;
	default:
		syslog(LOG_DEBUG, "rawBioCtrl: cmd = %d, num = %ld", cmd, num);
		ret = 0;
	}
	return (ret);
}

bool
initOpenSSL()
{
	OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN, nullptr);
	rawBioMethod = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
		"sslproc raw");
	if (rawBioMethod == nullptr)
		return (false);
	BIO_meth_set_read(rawBioMethod, rawBioRead);
	BIO_meth_set_write(rawBioMethod, rawBioWrite);
	BIO_meth_set_ctrl(rawBioMethod, rawBioCtrl);
	return (true);
}
