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

#include <sys/param.h>
#include <unistd.h>

#include "Messages.h"
#include "MessageCoproc.h"

#ifdef USE_COCALL_SLOW
#define	coaccept	coaccept_slow
#define	cocall		cocall_slow
#endif

/* cocall() and coaccept() require buffer sizes to be multiple of 8 bytes */
#define	ROUND_SIZE(x)	roundup2((x), 8)

static const Message::Header retryMessage = {
	.type = Message::RETRY,
	.length = sizeof(retryMessage)
};

bool
MessageCoprocBase::allocateMessages(int count, size_t size)
{
	/*
	 * cocall/coaccept need an extra message for the pending write
	 * buffer.
	 */
	return (MessageChannel::allocateMessageBuffers(count + 1,
	    ROUND_SIZE(size), 0));
}

bool
MessageCoprocBase::writeRawMessage(struct iovec *iov, int iovCnt)
{
	if (pendingWrite != nullptr) {
		trace("SND %s: already have a pending write\n", name.c_str());
		observeWriteError();
		return (false);
	}

	if (messages.empty()) {
		trace("SND %s: out of message buffers\n", name.c_str());
		observeWriteError();
		return (false);
	}

	MessageBuffer *buffer = messages.top();
	buffer->reset();

	size_t length = 0;
	char *cp = reinterpret_cast<char *>(buffer->data());
	for (int i = 0; i < iovCnt; i++) {
		if (ROUND_SIZE(length + iov[i].iov_len) > buffer->capacity()) {
			if (!buffer->grow(ROUND_SIZE(length +
			    iov[i].iov_len))) {
				trace("SND %s: failed to grow buffer\n",
				    name.c_str());
				observeWriteError();
				return (false);
			}
			cp = reinterpret_cast<char *>(buffer->data()) + length;
		}
		memcpy(cp, iov[i].iov_base, iov[i].iov_len);
		length += iov[i].iov_len;
		cp += iov[i].iov_len;
	}
	size_t padding = ROUND_SIZE(length) - length;
	memset(cp, 0, padding);
	length += padding;
	buffer->setLength(length);
	pendingWrite = buffer;
	messages.pop();
	return (true);
}

void
MessageCoprocBase::logRecvMessage(MessageBuffer *buffer)
{
	const Message::Header *hdr = buffer->hdr();
	if (hdr->type == Message::RESULT && buffer->result() != nullptr) {
		const Message::Result *result = buffer->result();
		trace("RCV %s: type RESULT len %d request %s error %d\n",
		    name.c_str(), result->length,
		    Message::typeName(result->request), result->error);
	} else
		trace("RCV %s: type %s len %d\n", name.c_str(),
		    Message::typeName(hdr->type), hdr->length);
}

bool
MessageCoAccept::initThread()
{
	if (cosetup(COSETUP_COACCEPT) != 0)
		return (false);
	return (true);
}

bool
MessageCoAccept::init()
{
	if (coregister(name.c_str(), NULL) != 0)
		return (false);
	return (true);
}

int
MessageCoAccept::readMessage(MessageRef &ref)
{
	MessageBuffer *buffer;
	int error;

	if (messages.empty()) {
		trace("RCV %s: out of message buffers\n", name.c_str());
		observeReadError(NO_BUFFER, nullptr);
		return (-1);
	}

	buffer = messages.top();
	messages.pop();
	buffer->reset();
	const Message::Header *hdr = reinterpret_cast<const Message::Header *>
	    (buffer->data());

	for (;;) {
		if (pendingWrite == nullptr)
			error = coaccept(nullptr, nullptr, 0, buffer->data(),
			    buffer->capacity());
		else
			error = coaccept(nullptr, pendingWrite->data(),
			    pendingWrite->length(), buffer->data(),
			    buffer->capacity());
		if (error != 0) {
			trace("RCV %s: coaccept failed: %m\n", name.c_str());
			observeReadError(READ_ERROR, nullptr);
			goto error;
		}

		if (hdr->type == Message::RETRY) {
			buffer->setLength(hdr->length);
			logRecvMessage(buffer);
			continue;
		}
		break;
	}
	if (pendingWrite != nullptr) {
		freeMessage(pendingWrite);
		pendingWrite = nullptr;
	}

	while (hdr->length > buffer->capacity()) {
		trace("RCV %s: type %s truncated\n", name.c_str(),
		    Message::typeName(hdr->type));

		if (!buffer->grow(ROUND_SIZE(hdr->length))) {
			trace("RCV %s: failed to grow buffer to %u\n",
			    name.c_str(), hdr->length);
			observeReadError(GROW_FAIL, hdr);
			errno = ENOMEM;
			goto error;
		}
		hdr = reinterpret_cast<const Message::Header *>
		    (buffer->data());

		trace("SND %s: type %s len %d\n", name.c_str(),
		    Message::typeName(retryMessage.type), retryMessage.length);
		error = coaccept(nullptr, &retryMessage, sizeof(retryMessage),
		    buffer->data(), buffer->capacity());
		if (error != 0) {
			trace("RCV %s: coaccept failed: %m\n", name.c_str());
			observeReadError(READ_ERROR, nullptr);
			goto error;
		}
	}
	buffer->setLength(hdr->length);
	logRecvMessage(buffer);
	ref.reset(this, buffer);
	return (1);

error:
	if (pendingWrite != nullptr) {
		freeMessage(pendingWrite);
		pendingWrite = nullptr;
	}
	freeMessage(buffer);
	return (-1);
}

bool
MessageCoCall::initThread()
{
	if (cosetup(COSETUP_COCALL) != 0)
		return (false);
	return (true);
}

bool
MessageCoCall::init()
{
	/*
	 * XXX: There is no way to know if the remote thread has
	 * executed coregister(2) by the time the client invokes this.
	 * Just keep trying in a loop with a timeout.
	 */
	for (u_int i = 0;; i++) {
		if (colookup(name.c_str(), &target) == 0)
			break;

		if (i == 500)
			return (false);

		usleep(10 * 1000);
	}

	return (true);
}

int
MessageCoCall::readMessage(MessageRef &ref)
{
	int error;

	if (pendingWrite == nullptr) {
		trace("RCV %s: no pending message to write\n", name.c_str());
		observeReadError(NO_BUFFER, nullptr);
		return (-1);
	}

	if (messages.empty()) {
		trace("RCV %s: out of message buffers\n", name.c_str());
		observeReadError(NO_BUFFER, nullptr);
		return (-1);
	}

	MessageBuffer *buffer = messages.top();
	messages.pop();
	buffer->reset();
	const Message::Header *hdr = reinterpret_cast<const Message::Header *>
	    (buffer->data());

	for (;;) {
		error = cocall(target, pendingWrite->data(),
		    pendingWrite->length(), buffer->data(),
		    buffer->capacity());
		if (error != 0) {
			trace("RCV %s: cocall failed: %m\n", name.c_str());
			observeReadError(READ_ERROR, nullptr);
			goto error;
		}

		if (hdr->type == Message::RETRY) {
			buffer->setLength(hdr->length);
			logRecvMessage(buffer);
			continue;
		}
		break;
	}
	freeMessage(pendingWrite);
	pendingWrite = nullptr;

	while (hdr->length > buffer->capacity()) {
		trace("RCV %s: type %s truncated\n", name.c_str(),
		    Message::typeName(hdr->type));

		if (!buffer->grow(ROUND_SIZE(hdr->length))) {
			trace("RCV %s: failed to grow buffer to %u\n",
			    name.c_str(), hdr->length);
			observeReadError(GROW_FAIL, hdr);
			errno = ENOMEM;
			goto error;
		}
		hdr = reinterpret_cast<const Message::Header *>
		    (buffer->data());

		trace("SND %s: type %s len %d\n", name.c_str(),
		    Message::typeName(retryMessage.type), retryMessage.length);
		error = cocall(target, &retryMessage, sizeof(retryMessage),
		    buffer->data(), buffer->capacity());
		if (error != 0) {
			trace("RCV %s: coaccept failed: %m\n", name.c_str());
			observeReadError(READ_ERROR, nullptr);
			goto error;
		}
	}
	buffer->setLength(hdr->length);
	logRecvMessage(buffer);
	ref.reset(this, buffer);
	return (1);

error:
	if (pendingWrite != nullptr) {
		freeMessage(pendingWrite);
		pendingWrite = nullptr;
	}
	freeMessage(buffer);
	return (-1);
}
