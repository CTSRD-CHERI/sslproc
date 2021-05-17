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

#include <Messages.h>
#include "SSLSession.h"
#include "sslproc_internal.h"

SSLSession::~SSLSession()
{
	close(fd);
}

bool
SSLSession::handleMessage(const Message::Header *hdr)
{
	char tmp[16];
	long ret;

	switch (hdr->type) {
	case SSLPROC_BIO_READ:
	{
		if (hdr->length != sizeof(Message::Read)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(2, "SSLPROC_BIO_READ bad length=",
			    tmp);
			return (false);
		}

		const Message::Read *msg =
		    reinterpret_cast<const Message::Read *>(hdr);
		if (msg->resid > 0) {
			/*
			 * XXX: We could perhaps just perform a
			 * short read with whatever capacity we
			 * have if it is not zero.
			 */
			if (!readBuffer.grow(msg->resid)) {
				PROCerr(PROC_F_SSL_HANDLE_MESSAGE,
				    ERR_R_MALLOC_FAILURE);
				ERR_add_error_data(1,
				    "failed to grow read buffer");
				return (false);
			}
		}

		ret = BIO_read(ssl->rbio, readBuffer.data(), msg->resid);
		if (ret > 0)
			writeReplyMessage(hdr->type, ret, readBuffer.data(),
			    ret);
		else {
			int flags = BIO_get_flags(ssl->rbio);
			writeReplyMessage(hdr->type, ret, &flags,
			    sizeof(flags));
		}
		break;
	}
	case SSLPROC_BIO_WRITE:
	{
		ret = BIO_write(ssl->wbio, hdr->body(), hdr->bodyLength());
		int flags = BIO_get_flags(ssl->wbio);
		writeReplyMessage(hdr->type, ret, &flags, sizeof(flags));
		break;
	}
	case SSLPROC_BIO_CTRL_READ:
	case SSLPROC_BIO_CTRL_WRITE:
	{
		if (hdr->length != sizeof(Message::Ctrl)) {
			writeErrnoReply(hdr->type, -1, EMSGSIZE);
			PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", hdr->length);
			ERR_add_error_data(3,
			    hdr->type == SSLPROC_BIO_CTRL_READ ?
			    "SSLPROC_BIO_CTRL_READ" : "SSLPROC_BIO_CTRL_WRITE",
			    " bad length=", tmp);
			return (false);
		}

		const Message::Ctrl *msg =
		    reinterpret_cast<const Message::Ctrl *>(hdr);
		long ret;
		BIO *bio;

		if (hdr->type == SSLPROC_BIO_CTRL_READ)
			bio = ssl->rbio;
		else
			bio = ssl->wbio;

		switch (msg->cmd) {
		case BIO_CTRL_GET_CLOSE:
		case BIO_CTRL_SET_CLOSE:
		case BIO_CTRL_FLUSH:
			ret = BIO_ctrl(bio, msg->cmd, msg->larg, nullptr);
			writeReplyMessage(hdr->type, ret);
			break;
		default:
			writeErrnoReply(hdr->type, -1, EOPNOTSUPP);
			PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
			snprintf(tmp, sizeof(tmp), "%d", msg->cmd);
			ERR_add_error_data(3,
			    hdr->type == SSLPROC_BIO_CTRL_READ ?
			    "SSLPROC_BIO_CTRL_READ" : "SSLPROC_BIO_CTRL_WRITE",
			    " unsupported cmd=", tmp);
			return (false);
		}
		break;
	}
	default:
		PROCerr(PROC_F_SSL_HANDLE_MESSAGE, ERR_R_BAD_MESSAGE);
		snprintf(tmp, sizeof(tmp), "%d", hdr->type);
		ERR_add_error_data(2, "unknown message type=", tmp);
		return (false);
	}

	return (true);
}
