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

#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sslproc_msg.h>

#include "MessageSocket.h"

int
MessageSocket::readMessage(MessageBuffer &buffer)
{
	const struct sslproc_message_header *hdr;
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t nread;

	buffer.reset();
	iov[0].iov_base = buffer.data();
	iov[0].iov_len = buffer.capacity();
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buffer.controlData();
	msg.msg_controllen = buffer.controlCapacity();
	msg.msg_flags = 0;
	nread = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_PEEK);
	if (nread == 0 || nread == -1)
		return (nread);
	assert(nread >= sizeof(*hdr));
	if (msg.msg_flags & MSG_TRUNC) {
		hdr = buffer.hdr();
		if (hdr->length >= sizeof(*hdr))
			buffer.grow(hdr->length);
	}

	iov[0].iov_base = buffer.data();
	iov[0].iov_len = buffer.capacity();
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buffer.controlData();
	msg.msg_controllen = buffer.controlCapacity();
	msg.msg_flags = 0;
	nread = recvmsg(fd, &msg, MSG_DONTWAIT);
	assert(nread > 0);
	if (nread < sizeof(*hdr)) {
		syslog(LOG_WARNING, "message too short");
		errno = EBADMSG;
		return (-1);
	}
	if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
		syslog(LOG_WARNING, "message truncated");
		errno = EBADMSG;
		return (-1);
	}
	hdr = buffer.hdr();
	if (hdr->length < sizeof(*hdr)) {
		syslog(LOG_WARNING, "invalid message length %d", hdr->length);
		errno = EBADMSG;
		return (-1);
	}
	if (nread != hdr->length) {
		syslog(LOG_WARNING, "message length mismatch");
		errno = EMSGSIZE;
		return (-1);
	}

	buffer.setLength(nread);
	buffer.setControlLength(msg.msg_controllen);
	return (1);
}

bool
MessageSocket::writeMessage(struct iovec *iov, int iovCnt, void *control,
    size_t controlLen)
{
	struct msghdr msg;
	ssize_t nwritten;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = iovCnt;
	msg.msg_control = control;
	msg.msg_controllen = controlLen;
	msg.msg_flags = 0;
	nwritten = sendmsg(fd, &msg, 0);
	if (nwritten == -1) {
		syslog(LOG_WARNING, "failed to write message");
		writeError = true;
		return (false);
	}

	if (nwritten == 0) {
		syslog(LOG_WARNING, "message fd is closed on write");
		writeError = true;
		return (false);
	}
	return (true);
}

bool
MessageSocket::writeMessage(int type, void *payload, size_t payloadLen,
    void *control, size_t controlLen)
{
	struct sslproc_message_header hdr;
	struct iovec iov[2];
	int cnt;

	hdr.type = type;
	hdr.length = sizeof(hdr) + payloadLen;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = payload;
	iov[1].iov_len = payloadLen;
	if (payload == nullptr)
		cnt = 1;
	else
		cnt = 2;
	return (writeMessage(iov, cnt, control, controlLen));
}

void
MessageSocket::writeReplyMessage(int type, int ret, void *payload,
    size_t payloadLen)
{
	struct sslproc_message_result result;
	struct iovec iov[2];
	int cnt;

	result.type = SSLPROC_RESULT;
	result.length = sizeof(result) + payloadLen;
	result.request = type;
	result.ret = ret;
	iov[0].iov_base = &result;
	iov[0].iov_len = sizeof(result);
	iov[1].iov_base = payload;
	iov[1].iov_len = payloadLen;
	if (payload == nullptr)
		cnt = 1;
	else
		cnt = 2;
	writeMessage(iov, cnt, nullptr, 0);
}

struct errorBody {
	int	ssl_error;
	long	error;
};

void
MessageSocket::writeErrnoReply(int type, int ret, int error)
{
	errorBody body;

	body.ssl_error = SSL_ERROR_SYSCALL;
	body.error = error;
	writeReplyMessage(type, ret, &body, sizeof(body));
}

void
MessageSocket::writeSSLErrorReply(int type, int ret, int error)
{
	errorBody body;

	body.ssl_error = error;
	switch (error) {
	case SSL_ERROR_SYSCALL:
		body.error = errno;
		break;
	case SSL_ERROR_SSL:
		body.error = ERR_get_error();
		break;
	default:
		body.error = 0;
	}
	writeReplyMessage(type, ret, &body, sizeof(body));
}
