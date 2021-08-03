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
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "Messages.h"
#include "MessageSocket.h"

int MessageSocket::traceFd = -1;

MessageSocket::~MessageSocket()
{
	while (!messages.empty()) {
		MessageBuffer *buffer = messages.top();
		messages.pop();
		delete buffer;
	}
	close(fd);
}

void
MessageSocket::enableTracing(int fd)
{
	traceFd = fd;
}

void
MessageSocket::trace(const char *fmt, ...)
{
	if (traceFd == -1)
		return;

	int save_error = errno;
	va_list ap;
	va_start(ap, fmt);
	vdprintf(traceFd, fmt, ap);
	va_end(ap);
	errno = save_error;
}

bool
MessageSocket::allocateMessages(int count, size_t size, size_t controlSize)
{
	assert(size >= sizeof(Message::Header));
	for (int i = 0; i < count; i++) {
		MessageBuffer *buffer = new MessageBuffer();
		if (!buffer->grow(size)) {
			delete buffer;
			return (false);
		}
		if (controlSize != 0 && !buffer->controlAlloc(controlSize)) {
			delete buffer;
			return (false);
		}
		freeMessage(buffer);
	}
	return (true);
}

int
MessageDatagramSocket::readMessage(MessageRef &ref)
{
	MessageBuffer *buffer;
	const Message::Header *hdr;
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t nread;

	if (messages.empty()) {
		trace("RCV %d: out of message buffers\n", fd);
		observeReadError(NO_BUFFER, nullptr);
		return (-1);
	}
	buffer = messages.top();
	buffer->reset();
	iov[0].iov_base = buffer->data();
	iov[0].iov_len = buffer->capacity();
	for (;;) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buffer->controlData();
		msg.msg_controllen = buffer->controlCapacity();
		msg.msg_flags = 0;
		nread = recvmsg(fd, &msg, MSG_PEEK);
		if (nread == -1 && errno == EINTR)
			continue;
		break;
	}
	if (nread == 0)
		return (0);
	if (nread == -1) {
		trace("RCV %d: recvmsg failed: %m\n", fd);
		observeReadError(READ_ERROR, nullptr);
		return (-1);
	}
	buffer->setLength(nread);
	assert(nread >= sizeof(*hdr));
	if (msg.msg_flags & MSG_TRUNC) {
		hdr = buffer->hdr();
		if (hdr->length >= sizeof(*hdr)) {
			if (!buffer->grow(hdr->length)) {
				trace("RCV %d: failed to grow buffer to %u\n",
				    fd, hdr->length);
				observeReadError(GROW_FAIL, hdr);
				errno = ENOMEM;
				return (-1);
			}
		}
	}

	iov[0].iov_base = buffer->data();
	iov[0].iov_len = buffer->capacity();
	for (;;) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = buffer->controlData();
		msg.msg_controllen = buffer->controlCapacity();
		msg.msg_flags = 0;
		nread = recvmsg(fd, &msg, 0);
		if (nread == -1 && errno == EINTR)
			continue;
		break;
	}
	assert(nread > 0);
	buffer->setLength(nread);
	buffer->setControlLength(msg.msg_controllen);
	if (nread < sizeof(*hdr)) {
		trace("RCV %d: nread %zd < header\n", fd, nread);
		observeReadError(SHORT, nullptr);
		errno = EBADMSG;
		return (-1);
	}
	if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
		trace("RCV %d: message truncated\n", fd);
		observeReadError(TRUNCATED, nullptr);
		errno = EBADMSG;
		return (-1);
	}
	hdr = buffer->hdr();
	if (hdr->length < sizeof(*hdr)) {
		trace("RCV %d: header length %u too short\n", fd, hdr->length);
		observeReadError(BAD_MSG_LENGTH, hdr);
		errno = EBADMSG;
		return (-1);
	}
	if (nread != hdr->length) {
		trace("RCV %d: header length %u != nread %zd\n", fd,
		    hdr->length, nread);
		observeReadError(LENGTH_MISMATCH, hdr);
		errno = EMSGSIZE;
		return (-1);
	}

	if (buffer->controlCapacity())
		trace("RCV %d: type %u len %zd controllen %u\n", fd, hdr->type,
		    nread, msg.msg_controllen);
	else
		trace("RCV %d: type %u len %zd\n", fd, hdr->type, nread);
	buffer->setLength(nread);
	buffer->setControlLength(msg.msg_controllen);
	messages.pop();
	ref.reset(this, buffer);
	return (1);
}

static ssize_t
readBuffer(int fd, void *buf, size_t len)
{
	char *cp;
	ssize_t nread, total;

	cp = reinterpret_cast<char *>(buf);
	total = 0;
	while (len != 0) {
		nread = read(fd, cp, len);
		if (nread == 0)
			return (total);
		if (nread == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		total += nread;
		cp += nread;
		len -= nread;
	}
	return (total);
}

int
MessageStreamSocket::readMessage(MessageRef &ref)
{
	MessageBuffer *buffer;
	const Message::Header *hdr;
	size_t payloadLen;
	ssize_t nread;

	buffer = messages.top();
	if (buffer == nullptr) {
		trace("RCV %d: out of message buffers\n", fd);
		observeReadError(NO_BUFFER, nullptr);
		return (-1);
	}
	buffer->reset();

	/* Read the header. */
	nread = readBuffer(fd, buffer->data(), sizeof(*hdr));
	if (nread == 0)
		return (0);
	if (nread == -1) {
		trace("RCV %d: header read failed: %m\n", fd);
		observeReadError(READ_ERROR, nullptr);
		return (-1);
	}
	if (nread != sizeof(*hdr)) {
		trace("RCV %d: nread %zd < header\n", fd, nread);
		observeReadError(SHORT, nullptr);
		return (-1);
	}
	buffer->setLength(nread);

	/* Validate the header. */
	hdr = buffer->hdr();
	if (hdr->length < sizeof(*hdr)) {
		trace("RCV %d: header length %u too short\n", fd, hdr->length);
		observeReadError(BAD_MSG_LENGTH, hdr);
		errno = EBADMSG;
		return (-1);
	}
	if (buffer->capacity() < hdr->length) {
		if (!buffer->grow(hdr->length)) {
			trace("RCV %d: failed to grow buffer to %u\n", fd,
			    hdr->length);
			observeReadError(GROW_FAIL, hdr);
			errno = ENOMEM;
			return (-1);
		}
		hdr = buffer->hdr();
	}

	/* Read the payload. */
	payloadLen = hdr->length - sizeof(*hdr);
	if (payloadLen != 0) {
		nread = readBuffer(fd,
		    reinterpret_cast<char *>(buffer->data()) + sizeof(*hdr),
		    payloadLen);
		if (nread == -1) {
			trace("RCV %d: payload read failed: %m\n", fd);
			observeReadError(READ_ERROR, nullptr);
			return (-1);
		}
		if (nread != payloadLen) {
			trace("RCV %d: message truncated\n", fd);
			observeReadError(TRUNCATED, nullptr);
			errno = EBADMSG;
			return (-1);
		}
		buffer->setLength(sizeof(*hdr) + nread);
	}

	trace("RCV %d: type %u len %u\n", fd, hdr->type, hdr->length);
	messages.pop();
	ref.reset(this, buffer);
	return (1);
}

void
MessageSocket::freeMessage(MessageBuffer *buffer)
{
	if (buffer != nullptr)
		messages.push(buffer);
}

bool
MessageSocket::writeMessage(struct iovec *iov, int iovCnt)
{
	ssize_t nwritten;

	nwritten = writev(fd, iov, iovCnt);
	if (nwritten == -1) {
		observeWriteError();
		return (false);
	}
	return (true);
}

bool
MessageDatagramSocket::writeMessage(enum Message::Type type,
    const void *payload, size_t payloadLen, const void *control,
    size_t controlLen)
{
	Message::Header hdr;
	struct msghdr msg;
	ssize_t nwritten;
	struct iovec iov[2];

	hdr.type = type;
	hdr.length = sizeof(hdr) + payloadLen;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = const_cast<void *>(payload);
	iov[1].iov_len = payloadLen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	if (payload == nullptr)
		msg.msg_iovlen = 1;
	else
		msg.msg_iovlen = 2;
	msg.msg_control = const_cast<void *>(control);
	msg.msg_controllen = controlLen;
	msg.msg_flags = 0;
	trace("SND %d: type %u len %d controlLen %zu\n", fd, hdr.type,
	    hdr.length, controlLen);
	nwritten = sendmsg(fd, &msg, 0);
	if (nwritten == -1) {
		observeWriteError();
		return (false);
	}
	return (true);
}

bool
MessageSocket::writeMessage(enum Message::Type type,
    const void *payload, size_t payloadLen)
{
	Message::Header hdr;
	struct iovec iov[2];
	int cnt;

	hdr.type = type;
	hdr.length = sizeof(hdr) + payloadLen;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = const_cast<void *>(payload);
	iov[1].iov_len = payloadLen;
	if (payload == nullptr)
		cnt = 1;
	else
		cnt = 2;
	trace("SND %d: type %u len %d\n", fd, hdr.type, hdr.length);
	return (writeMessage(iov, cnt));
}

bool
MessageSocket::writeMessage(enum Message::Type type, int target,
    const void *payload,  size_t payloadLen)
{
	Message::Targeted hdr;
	struct iovec iov[2];
	int cnt;

	hdr.type = type;
	hdr.length = sizeof(hdr) + payloadLen;
	hdr.target = target;
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = const_cast<void *>(payload);
	iov[1].iov_len = payloadLen;
	if (payload == nullptr)
		cnt = 1;
	else
		cnt = 2;
	trace("SND %d: type %u target %u, len %d\n", fd, hdr.type, hdr.target,
	    hdr.length);
	return (writeMessage(iov, cnt));
}

bool
MessageSocket::writeMessage(enum Message::Type type, int target,
    const struct iovec *iov, int iovCnt)
{
	Message::Targeted hdr;
	struct iovec iov2[iovCnt + 1];
	int i;

	hdr.type = type;
	hdr.length = sizeof(hdr);
	hdr.target = target;
	for (i = 0; i < iovCnt; i++)
		hdr.length += iov[i].iov_len;
	iov2[0].iov_base = &hdr;
	iov2[0].iov_len = sizeof(hdr);
	memcpy(iov2 + 1, iov, sizeof(*iov) * iovCnt);
	trace("SND %d: type %u target %u, len %d\n", fd, hdr.type, hdr.target,
	    hdr.length);
	return (writeMessage(iov2, iovCnt + 1));
}

void
MessageSocket::writeReplyMessage(enum Message::Type type, long ret, int error,
    const void *payload, size_t payloadLen)
{
	Message::Result result;
	struct iovec iov[2];
	int cnt;

	result.type = Message::RESULT;
	result.length = sizeof(result) + payloadLen;
	result.request = type;
	result.error = error;
	result.ret = ret;
	iov[0].iov_base = &result;
	iov[0].iov_len = sizeof(result);
	iov[1].iov_base = const_cast<void *>(payload);
	iov[1].iov_len = payloadLen;
	if (payload == nullptr)
		cnt = 1;
	else
		cnt = 2;
	trace("SND %d: RESULT type %u error %d len %d\n", fd, result.request,
	    result.error, result.length);
	writeMessage(iov, cnt);
}

void
MessageSocket::writeReplyMessage(enum Message::Type type, long ret,
    const void *payload, size_t payloadLen)
{
	writeReplyMessage(type, ret, SSL_ERROR_NONE, payload, payloadLen);
}

void
MessageSocket::writeReplyMessage(enum Message::Type type, long ret,
    const struct iovec *iov, int iovCnt)
{
	Message::Result result;
	struct iovec iov2[iovCnt + 1];
	int i;

	result.type = Message::RESULT;
	result.length = sizeof(result);
	result.request = type;
	result.error = SSL_ERROR_NONE;
	result.ret = ret;
	for (i = 0; i < iovCnt; i++)
		result.length += iov[i].iov_len;
	iov2[0].iov_base = &result;
	iov2[0].iov_len = sizeof(result);
	memcpy(iov2 + 1, iov, sizeof(*iov) * iovCnt);
	trace("SND %d: RESULT type %u error %d len %d\n", fd, result.request,
	    result.error, result.length);
	writeMessage(iov2, iovCnt + 1);
}

void
MessageSocket::writeErrorReply(enum Message::Type type, long ret, int errorType,
    const void *payload, size_t payloadLen)
{
	writeReplyMessage(type, ret, errorType, payload, payloadLen);
}

void
MessageSocket::writeErrnoReply(enum Message::Type type, long ret, int error)
{
	writeErrorReply(type, ret, SSL_ERROR_SYSCALL, &error, sizeof(error));
}
