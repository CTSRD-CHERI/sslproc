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

#include <sys/socket.h>

#include "Messages.h"

class DataBuffer {
public:
	DataBuffer() = default;
	~DataBuffer();

	bool grow(size_t);
	void *data() { return buffer; }
	size_t capacity() { return cap; }
	size_t length() { return len; }
	void setLength(size_t);
private:
	void *buffer = nullptr;
	size_t cap = 0;
	size_t len = 0;
};

class MessageBuffer {
public:
	MessageBuffer() = default;
	~MessageBuffer() = default;

	/* Message payload. */
	bool grow(size_t amount) { return msg.grow(amount); }
	void *data() { return msg.data(); }
	size_t capacity() { return msg.capacity(); }
	size_t length() { return (msg.length()); }
	bool empty() { return (length() == 0); }
	void setLength(size_t newLength) { msg.setLength(newLength); }
	const struct sslproc_message_header *hdr()
	{
		if (length() < sizeof(struct sslproc_message_header))
			return (nullptr);
		return reinterpret_cast<const struct sslproc_message_header *>
		    (data());
	}

	/* Control message. */
	bool controlAlloc(size_t amount) { return control.grow(amount); }
	void *controlData() { return control.data(); }
	size_t controlCapacity() { return control.capacity(); }
	size_t controlLength() { return (control.length()); }
	void setControlLength(size_t newLength)
	{ control.setLength(newLength); }
	const struct cmsghdr *cmsg()
	{
		if (controlLength() < sizeof(struct cmsghdr))
			return (nullptr);
		return reinterpret_cast<const struct cmsghdr *>(controlData());
	}

	void reset()
	{
		msg.setLength(0);
		control.setLength(0);
	}
private:
	DataBuffer msg;
	DataBuffer control;
};
