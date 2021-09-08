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

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <Messages.h>
#ifdef HAVE_COCALL
#include <MessageCoproc.h>
#else
#include <MessageSocket.h>
#endif
#include "sslproc_internal.h"

namespace LibMessageChannelHelpers {
	void observeReadError(enum MessageChannel::ReadError error,
	    const Message::Header *hdr);
	void observeWriteError();
	void setMessageError(const Message::Result *msg);
};

template<class Base>
class LibMessageChannel : public Base {
public:
#ifdef HAVE_COCALL
	LibMessageChannel(const char *name) : Base(name) {}
#else
	LibMessageChannel(int fd) : Base(fd) {}
#endif
	~LibMessageChannel() = default;
	MessageRef waitForReply(enum Message::Type type, int target,
	    const struct iovec *iov, int iovCnt);
	MessageRef waitForReply(enum Message::Type type, int target,
	    const void *payload = nullptr, size_t payloadLen = 0);
	MessageRef waitForReply(enum Message::Type type,
	    const void *payload = nullptr, size_t payloadLen = 0);
	MessageRef waitForReply(enum Message::Type type,
	    const void *payload, size_t payloadLen,
	    const void *control, size_t controlLen);
private:
	MessageRef _waitForReply(enum Message::Type type);
	virtual void handleMessage(const Message::Header *hdr) = 0;
	virtual void observeReadError(enum Base::ReadError error,
	    const Message::Header *hdr);
	virtual void observeWriteError();
};

template<class Base>
void
LibMessageChannel<Base>::observeReadError(enum Base::ReadError error,
    const Message::Header *hdr)
{
	LibMessageChannelHelpers::observeReadError(error, hdr);
}

template<class Base>
void
LibMessageChannel<Base>::observeWriteError()
{
	LibMessageChannelHelpers::observeWriteError();
}

template<class Base>
MessageRef
LibMessageChannel<Base>::waitForReply(enum Message::Type type, int target,
    const struct iovec *iov, int iovCnt)
{
	if (!Base::writeMessage(type, target, iov, iovCnt))
		return {};
	return (_waitForReply(type));
}

template<class Base>
MessageRef
LibMessageChannel<Base>::waitForReply(enum Message::Type type, int target,
    const void *payload, size_t payloadLen)
{
	if (!Base::writeMessage(type, target, payload, payloadLen))
		return {};
	return (_waitForReply(type));
}

template<class Base>
MessageRef
LibMessageChannel<Base>::waitForReply(enum Message::Type type,
    const void *payload, size_t payloadLen)
{
	if (!Base::writeMessage(type, payload, payloadLen))
		return {};
	return (_waitForReply(type));
}

template<class Base>
MessageRef
LibMessageChannel<Base>::waitForReply(enum Message::Type type,
    const void *payload, size_t payloadLen, const void *control,
    size_t controlLen)
{
	if (!Base::writeMessage(type, payload, payloadLen, control, controlLen))
		return {};
	return (_waitForReply(type));
}

template<class Base>
MessageRef
LibMessageChannel<Base>::_waitForReply(enum Message::Type type)
{
	for (;;) {
		MessageRef ref;
		int rc = Base::readMessage(ref);
		if (rc == 0) {
			PROCerr(PROC_F_WAIT_FOR_REPLY, ERR_R_UNEXPECTED_EOF);
			return {};
		}
		if (rc == -1)
			return {};

		const Message::Header *hdr = ref.hdr();
		if (hdr->type == Message::RESULT) {
			char tmp[16], tmp2[16];
			const Message::Result *result = ref.result();

			if (result == nullptr) {
				PROCerr(PROC_F_WAIT_FOR_REPLY,
				    ERR_R_BAD_MESSAGE);
				ERR_add_error_data(1, "reply too short");
				return {};
			}

			if (result->error != SSL_ERROR_NONE)
				LibMessageChannelHelpers::setMessageError(
				    result);

			if (result->request == type)
				return (ref);

			PROCerr(PROC_F_WAIT_FOR_REPLY, ERR_R_MISMATCHED_REPLY);
			snprintf(tmp, sizeof(tmp), "%d", type);
			snprintf(tmp2, sizeof(tmp2), "%d", result->request);
			ERR_add_error_data(4, "expected ", tmp, " got ", tmp2);
			return {};
		}

		handleMessage(hdr);
	}
}
