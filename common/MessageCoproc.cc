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

#include "Messages.h"
#include "MessageCoproc.h"

#ifdef USE_COCALL_SLOW
#define	coaccept	coaccept_slow
#define	cocall		cocall_slow
#endif

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
		if (length + iov[i].iov_len > buffer->capacity()) {
			if (!buffer->grow(length + iov[i].iov_len)) {
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
	buffer->setLength(length);
	pendingWrite = buffer;
	messages.pop();
	return (true);
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
	bool allocatedBuffer;

	/*
	 * allocatedBuffer is a bit odd.  The pendingWrite buffer has
	 * been allocated previously by writeRawMessage, so if this
	 * function fails, after sending pendingWrite, it should
	 * release the buffer.  However, if pendingWrite is nullptr,
	 * then a new buffer is reserved, but it is not allocated
	 * until the end of the function when success is returned.
	 */
	if (pendingWrite == nullptr) {
		if (messages.empty()) {
			trace("RCV %s: out of message buffers\n",
			    name.c_str());
			observeReadError(NO_BUFFER, nullptr);
			return (-1);
		}

		buffer = messages.top();
		buffer->reset();
		allocatedBuffer = false;

		error = coaccept(nullptr, nullptr, 0, buffer->data(),
		    buffer->capacity());
	} else {
		buffer = pendingWrite;
		allocatedBuffer = true;

		error = coaccept(nullptr, pendingWrite->data(),
		    pendingWrite->length(), buffer->data(),
		    buffer->capacity());

		pendingWrite = nullptr;
	}
	if (error != 0) {
		trace("RCV %s: coaccept failed: %m\n", name.c_str());
		observeReadError(READ_ERROR, nullptr);	
		if (allocatedBuffer)
			freeMessage(buffer);
		return (-1);
	}
	buffer->setLength(sizeof(Message::Header));

	const Message::Header *hdr = buffer->hdr();
	if (hdr->length > buffer->capacity()) {
		trace("RCV %s: message truncated\n", name.c_str());
		observeReadError(TRUNCATED, nullptr);
		errno = EMSGSIZE;
		if (allocatedBuffer)
			freeMessage(buffer);
		return (-1);
	}
	buffer->setLength(hdr->length);

	if (hdr->type == Message::RESULT && buffer->result() != nullptr) {
		const Message::Result *result = buffer->result();
		trace("RCV %s: type RESULT len %d request %s error %d\n",
		    name.c_str(), result->length,
		    Message::typeName(result->request), result->error);
	} else
		trace("RCV %s: type %s len %d\n", name.c_str(),
		    Message::typeName(hdr->type), hdr->length);
	if (!allocatedBuffer)
		messages.pop();
	ref.reset(this, buffer);
	return (1);
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
	if (pendingWrite == nullptr) {
		trace("RCV %s: no pending message to write\n", name.c_str());
		observeReadError(NO_BUFFER, nullptr);
		return (-1);
	}

	MessageBuffer *buffer = pendingWrite;
	pendingWrite = nullptr;

	int error = cocall(target, buffer->data(), buffer->length(),
	    buffer->data(), buffer->capacity());
	if (error != 0) {
		trace("RCV %s: cocall failed: %m\n", name.c_str());
		observeReadError(READ_ERROR, nullptr);	
		freeMessage(buffer);
		return (-1);
	}
	buffer->setLength(sizeof(Message::Header));

	const Message::Header *hdr = buffer->hdr();
	if (hdr->length > buffer->capacity()) {
		trace("RCV %s: message truncated\n", name.c_str());
		observeReadError(TRUNCATED, nullptr);
		errno = EMSGSIZE;
		freeMessage(buffer);
		return (-1);
	}
	buffer->setLength(hdr->length);

	if (hdr->type == Message::RESULT && buffer->result() != nullptr) {
		const Message::Result *result = buffer->result();
		trace("RCV %s: type RESULT len %d request %s error %d\n",
		    name.c_str(), result->length,
		    Message::typeName(result->request), result->error);
	} else
		trace("RCV %s: type %s len %d\n", name.c_str(),
		    Message::typeName(hdr->type), hdr->length);
	ref.reset(this, buffer);
	return (1);
}
