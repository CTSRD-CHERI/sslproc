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

#include "MessageBuffer.h"

/*
 * A MessageSocket sends and receives messages over a reliable
 * datagram socket.  It provides methods to read messages and write
 * messages.
 */
class MessageSocket {
protected:
	enum ReadError {
		READ_ERROR,
		SHORT,
		TRUNCATED,
		BAD_MSG_LENGTH,
		LENGTH_MISMATCH
	};

	MessageSocket(int _fd) : fd(_fd) {};
	int readMessage(MessageBuffer &);
	bool writeMessage(int type, const void *payload = nullptr,
	    size_t payloadLen = 0, const void *control = nullptr,
	    size_t controlLen = 0);
	bool writeMessage(int type, const struct iovec *iov, int iovCnt);
	void writeErrorReply(int type, long ret, int errorType,
	    const void *payload = NULL, size_t payloadLen = 0);
	void writeReplyMessage(int type, long ret,
	    const void *payload = nullptr, size_t payloadLen = 0);
	void writeReplyMessage(int type, long ret,
	    const struct iovec *iov, int iovCnt);
	void writeErrnoReply(int type, long ret, int error);
	virtual void observeReadError(enum ReadError error,
	    const Message::Header *hdr) = 0;
	virtual void observeWriteError() = 0;
private:
	bool writeMessage(struct iovec *iov, int iovCnt,
	    const void *control, size_t controlLen);
	void writeReplyMessage(int type, long ret, int error,
	    const void *payload, size_t payloadLen);

	int fd;
};
