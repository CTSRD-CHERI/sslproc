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
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <sslproc.h>

#include "local.h"
#include "IOBuffer.h"
#include "SSLSession.h"

static BIO_METHOD *rawBioMethod;

bool
SSLSession::init()
{
	if (!setFdNonBlocking(appFd, "SSL session app fd"))
		return (false);

	if (!inputBuffer.grow(64) || !outputBuffer.grow(64))
		return (false);

	BIO *bio = BIO_new(rawBioMethod);
	if (bio == NULL)
		return (false);
	BIO_set_data(bio, this);

	/* XXX: SSL_ctx_new? */
	/* XXX: SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER? */

	ssl = SSL_new(sslCtx);
	if (ssl == NULL) {
		BIO_free(bio);
		return (false);
	}
	SSL_set_bio(ssl, bio, bio);

	if (!appRead.init())
		return (false);
	if (!appWrite.initDisabled())
		return (false);
	return (true);
}

SSLSession::~SSLSession()
{
	SSL_free(ssl);

	close(rawFd);
	close(appFd);
}

void
SSLSession::drainOutput()
{
	if (outputBuffer.empty())
		return;

	ssize_t rc = write(appFd, outputBuffer.data(), outputBuffer.length());
	if (rc == -1) {
		if (errno == EAGAIN) {
			appRead.disable();
			appWrite.enable();
			return;
		}
		syslog(LOG_WARNING, "failed to write app data: %m");
		delete this;
		return;
	}

	if (rc == 0) {
		syslog(LOG_WARNING, "app data fd is closed");
		delete this;
		return;
	}

	outputBuffer.advance(rc);
	if (outputBuffer.empty()) {
		appRead.enable();
		appWrite.disable();
	} else {
		appRead.disable();
		appWrite.enable();
	}
}

bool
SSLSession::handleMessage(const struct sslproc_message_header *hdr)
{
	const struct sslproc_message_read *readMsg;
	struct sslproc_message_result resultMsg;
	int error, len;

	assert(outputBuffer.empty());

	resultMsg.type = SSLPROC_RESULT;
	resultMsg.request = hdr->type;

	switch (hdr->type) {
	case SSLPROC_CONNECT:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_CONNECT",
			    hdr->length);
			return (false);
		}
		resultMsg.ret = SSL_connect(ssl);
		if (resultMsg.ret == 1) {
			resultMsg.length = sizeof(resultMsg);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)))
				goto growfail;
		} else {
			resultMsg.length = sizeof(resultMsg) + sizeof(error);
			error = SSL_get_error(ssl, resultMsg.ret);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)) ||
			    !outputBuffer.appendData(&error, sizeof(error)))
				goto growfail;
		}
		break;
	case SSLPROC_ACCEPT:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_ACCEPT",
			    hdr->length);
			return (false);
		}
		resultMsg.ret = SSL_accept(ssl);	
		if (resultMsg.ret == 1) {
			resultMsg.length = sizeof(resultMsg);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)))
				goto growfail;
		} else {
			resultMsg.length = sizeof(resultMsg) + sizeof(error);
			error = SSL_get_error(ssl, resultMsg.ret);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)) ||
			    !outputBuffer.appendData(&error, sizeof(error)))
				goto growfail;
		}
		break;
	case SSLPROC_SHUTDOWN:
		if (hdr->length != sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_SHUTDOWN",
			    hdr->length);
			return (false);
		}
		resultMsg.ret = SSL_shutdown(ssl);	
		if (resultMsg.ret == 0 || resultMsg.ret == 1) {
			resultMsg.length = sizeof(resultMsg);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)))
				goto growfail;
		} else {
			resultMsg.length = sizeof(resultMsg) + sizeof(error);
			error = SSL_get_error(ssl, resultMsg.ret);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)) ||
			    !outputBuffer.appendData(&error, sizeof(error)))
				goto growfail;
		}
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
		if (readMsg->resid < 0) {
			if (!outputBuffer.grow(sizeof(resultMsg) +
			    sizeof(error)))
				goto growfail;
		} else {
			if (!outputBuffer.grow(sizeof(resultMsg) +
			    readMsg->resid))
				goto growfail;
		}
		resultMsg.ret = SSL_read(ssl, outputBuffer.end() +
		    sizeof(resultMsg), readMsg->resid);
		if (resultMsg.ret <= 0) {
			resultMsg.length = sizeof(resultMsg) + sizeof(error);
			error = SSL_get_error(ssl, resultMsg.ret);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)) ||
			    !outputBuffer.appendData(&error, sizeof(error)))
				goto growfail;
		} else {
			resultMsg.length = sizeof(resultMsg) + resultMsg.ret;
			outputBuffer.appendData(&resultMsg, sizeof(resultMsg));
			outputBuffer.advanceEnd(resultMsg.ret);
		}
		break;
	case SSLPROC_WRITE:
		if (hdr->length < sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message length %d for SSLPROC_WRITE",
			    hdr->length);
			return (false);
		}
		resultMsg.ret = SSL_write(ssl, hdr + 1, hdr->length -
		    sizeof(*hdr));
		if (resultMsg.ret > 0) {
			resultMsg.length = sizeof(resultMsg);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)))
				goto growfail;
		} else {
			resultMsg.length = sizeof(resultMsg) + sizeof(error);
			error = SSL_get_error(ssl, resultMsg.ret);
			if (!outputBuffer.appendData(&resultMsg,
			    sizeof(resultMsg)) ||
			    !outputBuffer.appendData(&error, sizeof(error)))
				goto growfail;
		}
		break;		
	default:
		syslog(LOG_WARNING, "unknown app request %d", hdr->type);
		return (false);
	}

	drainOutput();
	return (true);

growfail:
	syslog(LOG_WARNING, "failed to grow app output buffer");
	return (false);
}

void
SSLSession::onEvent(const struct kevent *kevent)
{
	const struct sslproc_message_header *hdr;
	size_t toRead;
	ssize_t rc;

	if (kevent->flags & EV_EOF) {
		delete this;
		return;
	}

	if (kevent->filter == EVFILT_WRITE) {
		drainOutput();
		return;
	}

	for (;;) {
		/* Figure out how much data to read this time. */
		if (inputBuffer.length() < sizeof(*hdr)) {
			toRead = sizeof(*hdr) - inputBuffer.length();
		} else {
			hdr = reinterpret_cast<const struct sslproc_message_header *>
			    (inputBuffer.data());
			toRead = hdr->length - inputBuffer.length();
		}

		if (!inputBuffer.grow(toRead)) {
			syslog(LOG_WARNING, "%s: failed to grow message buffer",
			    __func__);
			delete this;
			return;
		}
		rc = read(appFd, inputBuffer.end(), toRead);
		if (rc == -1) {
			if (errno == EAGAIN)
				return;
			syslog(LOG_WARNING, "%s: failed to read app data: %m",
			    __func__);
			delete this;
			return;
		}
		if (rc == 0) {
			syslog(LOG_WARNING, "app data fd is closed");
			delete this;
			return;
		}
		inputBuffer.advanceEnd(rc);

		if (inputBuffer.length() >= sizeof(*hdr)) {
			hdr = reinterpret_cast<const struct sslproc_message_header *>
			    (inputBuffer.data());
			if (hdr->length < sizeof(*hdr)) {
				syslog(LOG_WARNING,
				    "%s: invalid message length %d", __func__,
				    hdr->length);
				delete this;
				return;
			}

			if (inputBuffer.length() == hdr->length) {
				if (!handleMessage(hdr)) {
					delete this;
					return;
				}
				inputBuffer.reset();
				if (!outputBuffer.empty())
					return;
			}
		}
	}
}

int
SSLSession::rawRead(char *out, int outl)
{
	struct sslproc_message_read readMsg;
	struct sslproc_message_result resultMsg;
	int error;
	ssize_t rc;

	readMsg.type = SSLPROC_READ_RAW;
	readMsg.length = sizeof(readMsg);
	readMsg.resid = outl;

	rc = write(rawFd, &readMsg, sizeof(readMsg));
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s failed to write to raw fd: %m", __func__);
		errno = EIO;
		return (-1);
	}
	if (rc != sizeof(readMsg)) {
		syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
		errno = EIO;
		return (-1);
	}

	rc = read(rawFd, &resultMsg, sizeof(resultMsg));
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read from raw fd: %m",
		    __func__);
		errno = EIO;
		return (-1);
	}
	if (rc != sizeof(resultMsg)) {
		syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
		errno = EIO;
		return (-1);
	}
	if (resultMsg.type != SSLPROC_RESULT) {
		syslog(LOG_DEBUG, "%s: unexpected message %d", __func__,
		    resultMsg.type);
		errno = EIO;
		return (-1);
	}
	if (resultMsg.request != SSLPROC_READ_RAW) {
		syslog(LOG_DEBUG, "%s: reply mismatch", __func__);
		errno = EIO;
		return (-1);
	}

	if (resultMsg.ret == -1) {
		rc = read(rawFd, &error, sizeof(error));
		if (rc == -1) {
			syslog(LOG_DEBUG, "%s: failed to read from raw fd: %m",
			    __func__);
			return (-1);
		}
		if (rc < sizeof(error)) {
			syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
			errno = EIO;
			return (-1);
		}
		errno = error;
		return (-1);
	}

	if (resultMsg.ret < 0) {
		syslog(LOG_DEBUG, "%s: invalid result %d", __func__,
		    resultMsg.ret);
		errno = EIO;
		return (-1);
	}		
	if (resultMsg.ret > outl) {
		syslog(LOG_DEBUG, "%s: returned too much data %d vs %d",
		    __func__, resultMsg.ret, outl);
		errno = EIO;
		return (-1);
	}

	rc = read(rawFd, out, resultMsg.ret);
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read from raw fd: %m",
		    __func__);
		errno = EIO;
		return (-1);
	}
	if (rc != resultMsg.ret) {
		syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
		errno = EIO;
		return (-1);
	}

	return (resultMsg.ret);
}

int
SSLSession::rawWrite(const char *in, int inl)
{
	struct sslproc_message_header writeMsg;
	struct sslproc_message_result resultMsg;
	int error;
	ssize_t rc;

	writeMsg.type = SSLPROC_WRITE_RAW;
	writeMsg.length = sizeof(writeMsg) + inl;

	rc = write(rawFd, &writeMsg, sizeof(writeMsg));
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s failed to write to raw fd: %m", __func__);
		errno = EIO;
		return (-1);
	}
	if (rc != sizeof(writeMsg)) {
		syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
		errno = EIO;
		return (-1);
	}

	rc = write(rawFd, in, inl);
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s failed to write to raw fd: %m", __func__);
		errno = EIO;
		return (-1);
	}
	if (rc != inl) {
		syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
		errno = EIO;
		return (-1);
	}

	rc = read(rawFd, &resultMsg, sizeof(resultMsg));
	if (rc == -1) {
		syslog(LOG_DEBUG, "%s: failed to read from raw fd: %m",
		    __func__);
		errno = EIO;
		return (-1);
	}
	if (rc < sizeof(resultMsg)) {
		syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
		errno = EIO;
		return (-1);
	}
	if (resultMsg.type != SSLPROC_RESULT) {
		syslog(LOG_DEBUG, "%s: unexpected message %d", __func__,
		    resultMsg.type);
		errno = EIO;
		return (-1);
	}
	if (resultMsg.request != SSLPROC_WRITE_RAW) {
		syslog(LOG_DEBUG, "%s: reply mismatch", __func__);
		errno = EIO;
		return (-1);
	}

	if (resultMsg.ret == -1) {
		rc = read(rawFd, &error, sizeof(error));
		if (rc == -1) {
			syslog(LOG_DEBUG, "%s: failed to read from raw fd: %m",
			    __func__);
			return (-1);
		}
		if (rc < sizeof(error)) {
			syslog(LOG_DEBUG, "%s: EOF from raw fd", __func__);
			errno = EIO;
			return (-1);
		}
		errno = error;
		return (-1);
	}

	if (resultMsg.ret < 0) {
		syslog(LOG_DEBUG, "%s: invalid result %d", __func__,
		    resultMsg.ret);
		errno = EIO;
		return (-1);
	}		
	if (resultMsg.ret > inl) {
		syslog(LOG_DEBUG, "%s: returned too much data %d vs %d",
		    __func__, resultMsg.ret, inl);
		errno = EIO;
		return (-1);
	}

	return (resultMsg.ret);
}

static int
rawBioRead(BIO *bio, char *out, int outl)
{
	SSLSession *ss = reinterpret_cast<SSLSession *>(BIO_get_data(bio));
	int ret;

	if (out == NULL || outl == 0)
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

	if (in == NULL || inl == 0)
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
	OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
	rawBioMethod = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
		"sslproc raw");
	if (rawBioMethod == NULL)
		return (false);
	BIO_meth_set_read(rawBioMethod, rawBioRead);
	BIO_meth_set_write(rawBioMethod, rawBioWrite);
	BIO_meth_set_ctrl(rawBioMethod, rawBioCtrl);
	return (true);
}
