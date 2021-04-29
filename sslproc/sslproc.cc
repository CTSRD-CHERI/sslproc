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
 * Each connection contains two directions, one for reading data via
 * SSL_read, and one for writing data via SSL_write.  Each direction
 * contains an input fd and an output fd.
 *
 * For SSL_read, sslproc reads raw (encrypted) data from the input fd
 * and writes application data to the output fd.  For SSL_write,
 * sslproc reads application data from the input fd and writes
 * encrypted data to the output fd.
 *
 * Sessions are managed via control messages passed over a UNIX domain
 * socket.  The per-connection messages are defined in sslproc.h.
 *
 * New sessions are created by passing a file descriptor of the
 * per-session UNIX domain socket over a global UNIX domain socket.
 * The invoking process is required to pass a file descriptor to the
 * global UNIX domain socket as fd 3.
 */

#include <sys/event.h>
#include <fcntl.h>
#include <syslog.h>

#include "local.h"
#include "ControlSocket.h"

static int kqfd;

bool
setFdNonBlocking(int fd, const char *descr)
{
	int rc;

	rc = fcntl(fd, F_GETFL);
	if (rc == -1) {
		syslog(LOG_ERR, "fcntl(F_GETFL) of %s failed: %m", descr);
		return (false);
	}

	if (rc & O_NONBLOCK)
		return (true);

	rc = fcntl(fd, F_SETFL, rc | O_NONBLOCK);
	if (rc == -1) {
		syslog(LOG_ERR, "fcntl(F_SETFL) of %s failed: %m", descr);
		return (false);
	}
	return (true);
}

bool
Kevent::init()
{
	struct kevent kevent;
	int flags, rc;

	flags = EV_ADD;
	if (!enabled)
		flags |= EV_DISABLE;
	EV_SET(&kevent, fd, filter, flags, 0, 0, listener);

	rc = ::kevent(kqfd, &kevent, 1, NULL, 0, NULL);
	if (rc == -1) {
		syslog(LOG_ERR, "kevent register failed: %m");
		return (false);
	}
	return (true);
}

bool
Kevent::initDisabled()
{
	enabled = false;
	return init();
}

void
Kevent::disable()
{
	struct kevent kevent;
	int rc;

	if (!enabled)
		return;
	enabled = false;

#ifdef EV_KEEPUDATA
	EV_SET(&kevent, fd, filter, EV_DISABLE | EV_KEEPUDATA, 0, 0, NULL);
#else
	EV_SET(&kevent, fd, filter, EV_DISABLE, 0, 0, listener);
#endif

	rc = ::kevent(kqfd, &kevent, 1, NULL, 0, NULL);
	if (rc == -1) {
		syslog(LOG_ERR, "kevent enable failed: %m");
		exit(1);
	}
}

void
Kevent::enable()
{
	struct kevent kevent;
	int rc;

	if (enabled)
		return;
	enabled = true;

#ifdef EV_KEEPUDATA
	EV_SET(&kevent, fd, filter, EV_ENABLE | EV_KEEPUDATA, 0, 0, NULL);
#else
	EV_SET(&kevent, fd, filter, EV_ENABLE, 0, 0, listener);
#endif

	rc = ::kevent(kqfd, &kevent, 1, NULL, 0, NULL);
	if (rc == -1) {
		syslog(LOG_ERR, "kevent enable failed: %m");
		exit(1);
	}
}

static void
keventLoop(void)
{
	struct kevent kevent;
	int rc;

	for (;;) {
		rc = ::kevent(kqfd, NULL, 0, &kevent, 1, NULL);
		if (rc == -1) {
			syslog(LOG_ERR, "kevent failed: %m");
			exit(1);
		}
		if (rc == 0) {
			syslog(LOG_ERR, "kevent found no events");
			exit(1);
		}
		
		KeventListener *listener =
		    reinterpret_cast<KeventListener *>(kevent.udata);

		listener->onEvent(&kevent);
	}
}

int
main(int ac, char **av)
{

	openlog("sslproc", LOG_PID, LOG_DAEMON);

	kqfd = kqueue();
	if (kqfd == -1) {
		syslog(LOG_ERR, "failed to create kqueue: %m");
		return (1);
	}

	if (!initOpenSSL()) {
		syslog(LOG_ERR, "failed to initialize OpenSSL");
		return (1);
	}

	ControlSocket controlSocket(3);

	if (!controlSocket.init())
		return (1);

	keventLoop();
	return (0);
}
