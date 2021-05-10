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
#include <capsicum_helpers.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "KEvent.h"

KQueue::~KQueue()
{
	close(fd);
}

bool
KQueue::init()
{
	fd = kqueue();
	if (fd == -1) {
		syslog(LOG_ERR, "failed to create kqueue: %m");
		return (false);
	}

	cap_rights_t rights;
	cap_rights_init(&rights, CAP_KQUEUE);
	if (caph_rights_limit(fd, &rights) < 0) {
		syslog(LOG_ERR, "failed to restrict kqueue: %m");
		return (false);
	}

	return (true);
}

void
KQueue::run()
{
	struct kevent kevent;
	int rc;

	for (;;) {
		rc = ::kevent(fd, nullptr, 0, &kevent, 1, nullptr);
		if (rc == -1) {
			syslog(LOG_ERR, "kevent failed: %m");
			exit(1);
		}
		if (rc == 0) {
			syslog(LOG_ERR, "kevent found no events");
			exit(1);
		}

		KEventListener *listener =
		    reinterpret_cast<KEventListener *>(kevent.udata);

		listener->onEvent(&kevent);
	}
}

bool
KQueue::registerEvent(const struct kevent *kevent)
{
	int rc;

	rc = ::kevent(fd, kevent, 1, nullptr, 0, nullptr);
	return (rc != -1);
}

bool
KEvent::init()
{
	struct kevent kevent;

	EV_SET(&kevent, fd, filter, EV_ADD, 0, 0, listener);

	if (!kq->registerEvent(&kevent)) {
		syslog(LOG_ERR, "kevent register failed: %m");
		return (false);
	}
	return (true);
}
