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

#include <assert.h>
#include <errno.h>
#include <syslog.h>

#include <sslproc_msg.h>

#include "KEvent.h"
#include "MessageBuffer.h"
#include "MessageSocket.h"
#include "ControlSocket.h"
#include "SSLSession.h"

SSL_CTX *sslCtx;

bool
ControlSocket::init()
{
	if (!inputBuffer.grow(64) ||
	    !inputBuffer.controlAlloc(CMSG_SPACE(sizeof(int))))
		return (false);
	if (!readEvent.init())
		return (false);
	return (true);
}

void
ControlSocket::handleMessage(const struct sslproc_message_header *hdr,
    const struct cmsghdr *cmsg)
{
	int *fds;
	int error;

	switch (hdr->type) {
	case SSLPROC_CREATE_SESSION:
	{
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len != CMSG_SPACE(sizeof(int))) {
			syslog(LOG_WARNING,
			    "invalid control message for SSLPROC_CREATE_SESSION");
			error = EBADMSG;
			writeReplyMessage(hdr->type, -1, &error, sizeof(error));
			break;
		}

		fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
		SSLSession *ss = new SSLSession(kq, fds[0]);
		if (!ss->init()) {
			syslog(LOG_WARNING, "failed to init SSL sesssion");
			delete ss;
			error = ENXIO;
			writeReplyMessage(hdr->type, -1, &error, sizeof(error));
			break;
		}
		writeReplyMessage(hdr->type, 0);
		break;
	}
	default:
		syslog(LOG_WARNING, "unknown control request %d", hdr->type);
	}
}

void
ControlSocket::onEvent(const struct kevent *kevent)
{
	int rc, resid;

	if (kevent->flags & EV_EOF)
		exit(0);

	resid = kevent->data;
	while (resid > 0) {
		rc = readMessage(inputBuffer);
		if (rc == 0)
			exit(0);
		if (rc == -1)
			exit(1);

		assert(inputBuffer.length() <= resid);
		resid -= inputBuffer.length();

		handleMessage(inputBuffer.hdr(), inputBuffer.cmsg());
		if (hasWriteError())
			exit(1);
	}
}
