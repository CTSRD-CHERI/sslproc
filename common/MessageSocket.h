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

#pragma once

#include <stack>

#include "Messages.h"
#include "MessageBuffer.h"

/*
 * A MessageSocket sends and receives messages over a reliable
 * datagram socket.  It provides methods to read messages and write
 * messages.
 */
class MessageRef;

class MessageSocket {
public:
	void freeMessage(MessageBuffer *);
protected:
	enum ReadError {
		NO_BUFFER,
		READ_ERROR,
		SHORT,
		TRUNCATED,
		BAD_MSG_LENGTH,
		LENGTH_MISMATCH
	};

	MessageSocket(int _fd) : fd(_fd) {};
	~MessageSocket();

	bool allocateMessages(int count, size_t size, size_t controlSize = 0);
	int readMessage(MessageRef &ref);
	bool writeMessage(enum Message::Type type,
	    const void *payload = nullptr,
	    size_t payloadLen = 0, const void *control = nullptr,
	    size_t controlLen = 0);
	bool writeMessage(enum Message::Type type, int target,
	    const void *payload = nullptr,
	    size_t payloadLen = 0);
	bool writeMessage(enum Message::Type type, int target,
	    const struct iovec *iov, int iovCnt);
	void writeErrorReply(enum Message::Type type, long ret, int errorType,
	    const void *payload = NULL, size_t payloadLen = 0);
	void writeReplyMessage(enum Message::Type type, long ret,
	    const void *payload = nullptr, size_t payloadLen = 0);
	void writeReplyMessage(enum Message::Type type, long ret,
	    const struct iovec *iov, int iovCnt);
	void writeErrnoReply(enum Message::Type type, long ret, int error);
	virtual void observeReadError(enum ReadError error,
	    const Message::Header *hdr) = 0;
	virtual void observeWriteError() = 0;
private:
	bool writeMessage(struct iovec *iov, int iovCnt,
	    const void *control, size_t controlLen);
	void writeReplyMessage(enum Message::Type type, long ret, int error,
	    const void *payload, size_t payloadLen);

	int fd;
	std::stack<MessageBuffer *> messages;
};

class MessageRef {
public:
	MessageRef() : ms(nullptr), b(nullptr)
	{}

	MessageRef(MessageRef &&ref) : ms(ref.ms), b(ref.b)
	{ ref.b = nullptr; }

	MessageRef(const MessageRef &) = delete;

	~MessageRef()
	{
		if (b != nullptr)
			ms->freeMessage(b);
	}

	void reset(MessageSocket *_ms, MessageBuffer *_b)
	{
		if (b != nullptr)
			ms->freeMessage(b);
		ms = _ms;
		b = _b;
	}

	size_t length() const
	{
		if (b == nullptr)
			return (0);
		return (b->length());
	}

	const Message::Header *hdr() const
	{
		if (b == nullptr)
			return (nullptr);
		return (b->hdr());
	}

	const Message::Result *result() const
	{
		if (b == nullptr)
			return (nullptr);
		return (b->result());
	}

	const struct cmsghdr *cmsg() const
	{
		if (b == nullptr)
			return (nullptr);
		return (b->cmsg());
	}

	explicit operator bool() const
	{ return (b != nullptr); }

private:
	MessageSocket *ms;
	MessageBuffer *b;
};
