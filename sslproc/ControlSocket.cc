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

#include <sys/event.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sslproc.h>

#include "local.h"
#include "ControlSocket.h"
#include "SSLSession.h"

SSL_CTX *sslCtx;

bool
ControlSocket::init()
{
	if (!setFdNonBlocking(fd, "control socket"))
		return (false);
	if (!inputBuffer.grow(64) || !outputBuffer.grow(64))
		return (false);
	if (!controlRead.init())
		return (false);
	if (!controlWrite.initDisabled())
		return (false);
	return (true);
}

void
ControlSocket::drainOutput()
{
	if (outputBuffer.empty())
		return;

	ssize_t rc = write(fd, outputBuffer.data(), outputBuffer.length());
	if (rc == -1) {
		if (errno == EAGAIN) {
			controlRead.disable();
			controlWrite.enable();
			return;
		}
		syslog(LOG_WARNING, "failed to write control data");
		exit(1);
	}

	if (rc == 0) {
		syslog(LOG_WARNING, "control data fd is closed");
		exit(1);
	}

	outputBuffer.advance(rc);
	if (outputBuffer.empty()) {
		controlRead.enable();
		controlWrite.disable();
	} else {
		controlRead.disable();
		controlWrite.enable();
	}
}

void
ControlSocket::handleMessage(const struct sslproc_message_header *hdr,
    const struct cmsghdr *cmsg, size_t cmsgLen)
{
	struct sslproc_message_result resultMsg;
	int *fds;
	int error;

	assert(outputBuffer.empty());

	resultMsg.type = SSLPROC_RESULT;
	resultMsg.request = hdr->type;

	switch (hdr->type) {
	case SSLPROC_CREATE_SESSION:
	{
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len != CMSG_SPACE(sizeof(int) * 2)) {
			syslog(LOG_WARNING,
			    "invalid control message for SSLPROC_CREATE_SESSION");
			break;
		}

		fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
		SSLSession *ss = new SSLSession(fds[0], fds[1]);
		if (!ss->init()) {
			syslog(LOG_WARNING, "failed to init SSL sesssion");
			delete ss;
		}
		break;
	}
	default:
		syslog(LOG_WARNING, "unknown control request %d", hdr->type);
	}

	drainOutput();
}

void
ControlSocket::onEvent(const struct kevent *kevent)
{
	const struct sslproc_message_header *hdr;
	struct msghdr msg;
	struct iovec iov[1];
	char cbuf[CMSG_SPACE(sizeof(int) * 2)];
	const struct cmsghdr *cmsg;
	ssize_t nread;

	if (kevent->flags & EV_EOF)
		exit(0);

	if (kevent->filter == EVFILT_WRITE) {
		drainOutput();
		return;
	}

	for (;;) {
		inputBuffer.reset();
		iov[0].iov_base = inputBuffer.end();
		iov[0].iov_len = inputBuffer.space();
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		msg.msg_flags = 0;
		nread = recvmsg(kevent->ident, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (nread == -1) {
			syslog(LOG_ERR,
			    "failed to read from control socket: %m");
			exit(1);
		}
		if (nread == 0)
			break;
		if (msg.msg_flags & MSG_TRUNC) {
			hdr = reinterpret_cast<const struct sslproc_message_header *>
			    (inputBuffer.data());
			if (hdr->length >= sizeof(*hdr))
				inputBuffer.grow(hdr->length);
		}

		inputBuffer.reset();
		iov[0].iov_base = inputBuffer.end();
		iov[0].iov_len = inputBuffer.space();
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		msg.msg_flags = 0;
		nread = recvmsg(kevent->ident, &msg, MSG_DONTWAIT);
		assert(nread > 0);
		if (nread < sizeof(*hdr)) {
			syslog(LOG_WARNING, "control socket message too short");
			continue;
		}
		if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
			syslog(LOG_WARNING, "control socket message truncated");
			continue;
		}
		hdr = reinterpret_cast<const struct sslproc_message_header *>
		    (inputBuffer.data());
		if (hdr->length < sizeof(*hdr)) {
			syslog(LOG_WARNING,
			    "invalid message on control socket");
			continue;
		}		
		if (nread != hdr->length) {
			syslog(LOG_WARNING,
			    "control socket message length mismatch");
			continue;
		}

		if (msg.msg_controllen != sizeof(cbuf)) {
			syslog(LOG_WARNING,
			    "invalid message on control socket");
			continue;
		}

		if (msg.msg_controllen == 0)
			cmsg = NULL;
		else
			cmsg = reinterpret_cast<const struct cmsghdr *>(cbuf);
		handleMessage(hdr, cmsg, msg.msg_controllen);
		if (!outputBuffer.empty())
			return;
	}
}
