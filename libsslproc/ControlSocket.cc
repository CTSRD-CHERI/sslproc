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

#include <stdlib.h>
#include <unistd.h>

#include <Messages.h>
#include "ControlSocket.h"
#include "sslproc_internal.h"

ControlSocket::~ControlSocket()
{
	close(fd);
}

bool
ControlSocket::createContext(const PSSL_METHOD *method)
{
	const Message::Result *reply = waitForReply(Message::CREATE_CONTEXT,
	    &method->method, sizeof(method->method));
	if (reply == nullptr)
		return (false);
	if (reply->ret != 0)
		return (false);
	return (true);
}

bool
ControlSocket::createSession(int sessionFd)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	int *fds;

	cmsg = &cmsgbuf.hdr;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
	fds[0] = sessionFd;
	const Message::Result *reply = waitForReply(Message::CREATE_SESSION,
	    nullptr, 0, &cmsgbuf, sizeof(cmsgbuf));
	if (reply == nullptr)
		return (false);
	return (reply->ret == 0);
}

bool
ControlSocket::handleMessage(const Message::Header *hdr)
{
	return (false);
}
