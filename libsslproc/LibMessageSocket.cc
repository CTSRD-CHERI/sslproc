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

#include <errno.h>

#include <openssl/ssl.h>

#include <Messages.h>
#include "LibMessageSocket.h"
#include "sslproc_internal.h"

void
LibMessageSocket::observeReadError(enum ReadError error,
    const Message::Header *hdr)
{
	char tmp[16];

	switch (error) {
	case NO_BUFFER:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_NO_BUFFER);
		break;
	case READ_ERROR:
		PROCerr(PROC_F_RECVMSG, ERR_R_IO_ERROR);
		ERR_add_error_data(1, strerror(errno));
		break;
	case GROW_FAIL:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_MALLOC_FAILURE);
		ERR_add_error_data(1, "failed to grow message buffer");
		break;
	case SHORT:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "too short");
		break;
	case TRUNCATED:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "truncated");
		break;
	case BAD_MSG_LENGTH:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_BAD_MESSAGE);
		snprintf(tmp, sizeof(tmp), "%d", hdr->length);
		ERR_add_error_data(2, "invalid length ", tmp);
		break;
	case LENGTH_MISMATCH:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_BAD_MESSAGE);
		ERR_add_error_data(1, "length mismatch");
		break;
	}
}

void
LibMessageSocket::observeWriteError()
{
	PROCerr(PROC_F_WRITE_MESSAGE, ERR_R_IO_ERROR);
	ERR_add_error_data(1, strerror(errno));
}

MessageRef
LibMessageSocket::waitForReply(enum Message::Type type, int target,
    const struct iovec *iov, int iovCnt)
{
	if (ERR_peek_error() != 0)
		return {};
	if (!writeMessage(type, target, iov, iovCnt))
		return {};
	return (_waitForReply(type));
}

MessageRef
LibMessageSocket::waitForReply(enum Message::Type type, int target,
    const void *payload, size_t payloadLen)
{
	if (ERR_peek_error() != 0)
		return {};
	if (!writeMessage(type, target, payload, payloadLen))
		return {};
	return (_waitForReply(type));
}

MessageRef
LibMessageSocket::waitForReply(enum Message::Type type, const void *payload,
    size_t payloadLen, const void *control, size_t controlLen)
{
	if (ERR_peek_error() != 0)
		return {};
	if (!writeMessage(type, payload, payloadLen, control, controlLen))
		return {};
	return (_waitForReply(type));
}

MessageRef
LibMessageSocket::_waitForReply(enum Message::Type type)
{
	for (;;) {
		MessageRef ref;
		int rc = readMessage(ref);
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
				setMessageError(result);

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

void
LibMessageSocket::setMessageError(const Message::Result *msg)
{
	long error;
	char tmp[16], tmp2[16];

	error = *reinterpret_cast<const long *>(msg->body());
	switch (msg->error) {
	case SSL_ERROR_SSL:
		PROCerr(PROC_F_SET_MESSAGE_ERROR, ERR_R_MESSAGE_ERROR);
		if (msg->bodyLength() != 0)
			ERR_add_error_data(1, msg->body());
		break;
	case SSL_ERROR_SYSCALL:
	{
		PROCerr(PROC_F_SET_MESSAGE_ERROR, ERR_R_MESSAGE_ERROR);
		snprintf(tmp, sizeof(tmp), "%d", msg->type);
		if (msg->bodyLength() == sizeof(int)) {
			int error = *reinterpret_cast<const int *>(msg->body());
			ERR_add_error_data(4, "type=", tmp, " ", strerror(error));
		} else
			ERR_add_error_data(2, "type=", tmp);
		break;
	}
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		break;
	default:
		PROCerr(PROC_F_SET_MESSAGE_ERROR, ERR_R_MESSAGE_ERROR);
		snprintf(tmp, sizeof(tmp), "%d", msg->type);
		snprintf(tmp2, sizeof(tmp2), "%d", msg->error);
		ERR_add_error_data(4, "type=", tmp, " error=", tmp2);
		break;
	}
}
