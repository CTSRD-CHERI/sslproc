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

/*
 * Each SSL session is managed messages passed over a UNIX domain
 * datagram socket.  Each request is answered by a result message,
 * but the helper library is permitted to submit async requests to
 * client while servicing a request.  Only one async request is
 * permitted at a time, and the client should respond to each
 * async request with a result message.
 *
 * Sessions are created via control messages passed over a UNIX domain
 * datagram socket.  The invoking process is required to pass a file
 * descriptor to this global socket as fd 3.
 *
 * In addition to creating sessions, other control messages are passed
 * via the global control socket for configuring global state such as
 * the shared SSL_CTX used for all sessions.
 *
 * The messages used by both the global and per-connection control
 * sockets are defined in sslproc.h.
 */

#include <syslog.h>

#include "local.h"
#include "KEvent.h"
#include "ControlSocket.h"

int
main(int ac, char **av)
{
	openlog("sslproc", LOG_PID, LOG_DAEMON);

	KQueue kq;
	if (!kq.init())
		return (1);

	if (!initOpenSSL()) {
		syslog(LOG_ERR, "failed to initialize OpenSSL");
		return (1);
	}

	ControlSocket controlSocket(&kq, 3);

	if (!controlSocket.init())
		return (1);

	kq.run();
	return (0);
}
