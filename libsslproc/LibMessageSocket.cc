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

#include <Messages.h>
#include <MessageBuffer.h>
#include "LibMessageSocket.h"

bool
LibMessageSocket::init()
{
	if (!replyBuffer.grow(64))
		return (false);
	return (true);
}

const Message::Result *
LibMessageSocket::waitForReply(int type)
{
	const Message::Header *hdr;
	int rc;

	for (;;) {
		/*
		 * TODO: do we perhaps stuff a suitable error into our own
		 * per-thread error queue?
		 */
		if (hasWriteError()) {
			errno = EIO;
			return (nullptr);
		}

		rc = readMessage(replyBuffer);

		if (rc == 0) {
			errno = ENOENT;
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

			/* XXX: Should probably kill the entire connection. */
			return (nullptr);
		}

		if (!handleMessage(hdr))
			/* XXX: Error handling? */
			return (nullptr);
	}
}
