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
#include <MessageBuffer.h>
#include "LibMessageSocket.h"
#include "sslproc_internal.h"

bool
LibMessageSocket::init()
{
	if (!replyBuffer.grow(64))
		return (false);
	return (true);
}

void
LibMessageSocket::observeReadError(enum ReadError error,
    const Message::Header *hdr)
{
	switch (error) {
	case READ_ERROR:
		PROCerr(PROC_F_RECVMSG, ERR_R_IO_ERROR);
		break;
	default:
		PROCerr(PROC_F_READ_MESSAGE, ERR_R_BAD_MESSAGE);
		break;
	}
}

void
LibMessageSocket::observeWriteError()
{
	PROCerr(PROC_F_WRITE_MESSAGE, ERR_R_IO_ERROR);
}

const Message::Result *
LibMessageSocket::waitForReply(int type)
{
	const Message::Header *hdr;
	int rc;

	for (;;) {
		if (ERR_peek_error() != 0)
			return (nullptr);

		rc = readMessage(replyBuffer);

		if (rc == 0) {
			PROCerr(PROC_F_WAIT_FOR_REPLY, ERR_R_UNEXPECTED_EOF);
			return (nullptr);
		}
		if (rc == -1)
			return (nullptr);

		hdr = replyBuffer.hdr();
		if (hdr->type == SSLPROC_RESULT) {
			const Message::Result *result =
			    reinterpret_cast<const Message::Result *>(hdr);

			if (result->request == type)
			    return (result);

			PROCerr(PROC_F_WAIT_FOR_REPLY, ERR_R_MISMATCHED_REPLY);
			return (nullptr);
		}

		if (!handleMessage(hdr))
			return (nullptr);
	}
}

void
setMessageError(const Message::Result *msg)
{
	const Message::ErrorBody *body =
	    reinterpret_cast<const Message::ErrorBody *>(msg->body);

	if (body->sslError == SSL_ERROR_SSL)
		ERR_PUT_error(ERR_GET_LIB(body->error),
		    ERR_GET_FUNC(body->error), ERR_GET_REASON(body->error),
		    "NA", 0);
}
