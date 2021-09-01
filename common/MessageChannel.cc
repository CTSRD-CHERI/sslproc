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

#include <openssl/ssl.h>

#include "Messages.h"
#include "MessageChannel.h"

int MessageChannel::traceFd = -1;

MessageChannel::~MessageChannel()
{
	while (!messages.empty()) {
		MessageBuffer *buffer = messages.top();
		messages.pop();
		delete buffer;
	}
}

void
MessageChannel::enableTracing(int fd)
{
	traceFd = fd;
}

void
MessageChannel::trace(const char *fmt, ...)
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

void
MessageChannel::setId(int value)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%d", value);
	id = std::string(buf);
}

bool
MessageChannel::allocateMessages(int count, size_t size, size_t controlSize)
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

void
MessageChannel::freeMessage(MessageBuffer *buffer)
{
	if (buffer != nullptr)
		messages.push(buffer);
}

bool
MessageChannel::writeMessage(enum Message::Type type,
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
	trace("SND %s: type %s len %d\n", id.c_str(),
	    Message::typeName(hdr.type), hdr.length);
	return (writeRawMessage(iov, cnt));
}

bool
MessageChannel::writeMessage(enum Message::Type type, int target,
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
	trace("SND %s: type %s len %d target %u\n", id.c_str(),
	    Message::typeName(hdr.type), hdr.length, hdr.target);
	return (writeRawMessage(iov, cnt));
}

bool
MessageChannel::writeMessage(enum Message::Type type, int target,
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
	trace("SND %s: type %s len %d target %u\n", id.c_str(),
	    Message::typeName(hdr.type), hdr.length, hdr.target);
	return (writeRawMessage(iov2, iovCnt + 1));
}

void
MessageChannel::writeReplyMessage(enum Message::Type type, long ret, int error,
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
	trace("SND %s: type RESULT len %d request %s error %d\n", id.c_str(),
	    result.length, Message::typeName(result.request), result.error);
	writeRawMessage(iov, cnt);
}

void
MessageChannel::writeReplyMessage(enum Message::Type type, long ret,
    const void *payload, size_t payloadLen)
{
	writeReplyMessage(type, ret, SSL_ERROR_NONE, payload, payloadLen);
}

void
MessageChannel::writeReplyMessage(enum Message::Type type, long ret,
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
	trace("SND %s: type RESULT len %d request %s error %d\n", id.c_str(),
	    result.length, Message::typeName(result.request), result.error);
	writeRawMessage(iov2, iovCnt + 1);
}

void
MessageChannel::writeErrorReply(enum Message::Type type, long ret,
    int errorType, const void *payload, size_t payloadLen)
{
	writeReplyMessage(type, ret, errorType, payload, payloadLen);
}

void
MessageChannel::writeErrnoReply(enum Message::Type type, long ret, int error)
{
	writeErrorReply(type, ret, SSL_ERROR_SYSCALL, &error, sizeof(error));
}
