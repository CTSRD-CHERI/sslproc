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
 * Each SSL session is managed by messages passed over a UNIX domain
 * stream socket.  Each request is answered by a result message,
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
 * sockets are defined in Messages.h.
 */

#include <capsicum_helpers.h>
#include <syslog.h>

#include "local.h"
#include "ControlChannel.h"

int
main(int ac, char **av)
{
	openlog("sslproc", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	if (!initOpenSSL()) {
		syslog(LOG_ERR, "failed to initialize OpenSSL");
		return (1);
	}

	if (caph_limit_stdio() < 0) {
		syslog(LOG_ERR, "failed to restrict stdio: %m");
		return (1);
	}

	cap_rights_t rights;
#ifndef HAVE_COCALL
	cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(3, &rights) < 0) {
		syslog(LOG_ERR, "failed to restrict control socket: %m");
		return (false);
	}
#endif

	const char *tracerPath = getenv("SSLPROC_TRACE_PATH");
	if (tracerPath != nullptr) {
		int fd = open(tracerPath, O_WRONLY | O_CREAT | O_APPEND,
		    0644);
		if (fd != -1) {
			cap_rights_init(&rights, CAP_WRITE);
			if (caph_rights_limit(fd, &rights) == 0)
				MessageChannel::enableTracing(fd);
			else
				close(fd);
		}
	}

#ifndef HAVE_COCALL
	/*
	 * XXX: Can't use co* in capability mode.
	 *
	 * cocall/coaccept/cosetup are no brainers to permit, but we
	 * also need coregister and it's not clear that would be safe.
	 */
	if (caph_enter() < 0) {
		syslog(LOG_ERR, "failed to enter capability mode: %m");
		return (1);
	}
#endif

#ifdef HAVE_COCALL
	if (ac != 2) {
		syslog(LOG_ERR, "control channel name not provided");
		return (1);
	}

	ControlChannel controlChannel(av[1]);
#else
	ControlChannel controlChannel(3);
#endif

	if (!controlChannel.init())
		return (1);

	controlChannel.run();
	return (0);
}
