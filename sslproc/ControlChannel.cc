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
#include <capsicum_helpers.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <list>

#include <openssl/ssl.h>

#include "local.h"
#include "Messages.h"
#include "MessageSocket.h"
#include "ControlChannel.h"
#include "CommandChannel.h"

static std::list<CommandChannel *> commandChannels;
static pthread_mutex_t commandChannelsLock = { PTHREAD_MUTEX_INITIALIZER };

bool
ControlChannel::init()
{
	/* Control socket messages don't recurse. */
	if (!allocateMessages(1, 64, CMSG_SPACE(sizeof(int))))
		return (false);
	return (true);
}

void
ControlChannel::deleteCommandChannel(CommandChannel *cs)
{
	pthread_mutex_lock(&commandChannelsLock);
	commandChannels.remove(cs);
	pthread_mutex_unlock(&commandChannelsLock);
}

void
ControlChannel::handleMessage(const Message::Header *hdr,
    const struct cmsghdr *cmsg)
{
	int *fds;

	switch (hdr->type) {
	case Message::NOP:
		writeReplyMessage(hdr->type, 0);
		break;
	case Message::CREATE_COMMAND_CHANNEL:
	{
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
			syslog(LOG_WARNING,
	    "invalid control message for Message::CREATE_COMMAND_SOCKET");
			writeErrnoReply(hdr->type, -1, EBADMSG);
			break;
		}

		fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));

		cap_rights_t rights;
		cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
		if (caph_rights_limit(fds[0], &rights) < 0) {
			int error = errno;
			close(fds[0]);
			syslog(LOG_WARNING,
			    "failed to restrict session socket: %m");
			writeErrnoReply(hdr->type, -1, error);
			break;
		}

		CommandChannel *cs = new CommandChannel(fds[0]);
		if (!cs->init()) {
			syslog(LOG_WARNING, "failed to init command socket");
			delete cs;
			writeErrnoReply(hdr->type, -1, ENXIO);
			break;
		}
		pthread_mutex_lock(&commandChannelsLock);
		commandChannels.push_back(cs);
		pthread_mutex_unlock(&commandChannelsLock);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	case Message::FORK:
	{
		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
			syslog(LOG_WARNING,
			    "invalid control message for Message::FORK");
			writeErrnoReply(hdr->type, -1, EBADMSG);
			break;
		}

		fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));

		cap_rights_t rights;
		cap_rights_init(&rights, CAP_EVENT, CAP_READ, CAP_WRITE);
		if (caph_rights_limit(fds[0], &rights) < 0) {
			int error = errno;
			close(fds[0]);
			syslog(LOG_WARNING,
			    "failed to restrict new control socket: %m");
			writeErrnoReply(hdr->type, -1, error);
			break;
		}

		pid_t pid = fork();
		if (pid == -1) {
			int error = errno;
			close(fds[0]);
			syslog(LOG_WARNING, "failed to fork: %m");
			writeErrnoReply(hdr->type, -1, error);
			break;
		}

		if (pid == 0) {
			/*
			 * Teardown any command sockets inherited from
			 * the parent process.  No locking is needed
			 * here since the child process is
			 * single-threaded at this point.
			 */
			while (!commandChannels.empty()) {
				CommandChannel *cs = commandChannels.front();
				delete cs;
				commandChannels.pop_front();
			}

			/* Switch fd of child control socket. */
			updateFd(fds[0]);

			/*
			 * Return to await the first message on the
			 * new socket.
			 */
			break;
		}

		close(fds[0]);
		writeReplyMessage(hdr->type, 0);
		break;
	}
	default:
		syslog(LOG_WARNING, "unknown control request %d", hdr->type);
	}
}

void
ControlChannel::run()
{
	for (;;) {
		MessageRef ref;

		int rc = readMessage(ref);
		if (rc == 0)
			exit(0);
		if (rc == -1)
			exit(1);

		handleMessage(ref.hdr(), ref.cmsg());
	}
}

void
ControlChannel::observeReadError(enum ReadError error,
    const Message::Header *hdr)
{
	switch (error) {
	case NO_BUFFER:
		syslog(LOG_WARNING, "out of message buffers on control socket");
		break;
	case READ_ERROR:
		syslog(LOG_WARNING, "failed to read from control socket: %m");
		break;
	case GROW_FAIL:
		syslog(LOG_WARNING,
		    "failed to grow control socket message buffer");
		break;
	case SHORT:
		syslog(LOG_WARNING, "control message too short");
		break;
	case TRUNCATED:
		syslog(LOG_WARNING, "control message truncated");
		break;
	case BAD_MSG_LENGTH:
		syslog(LOG_WARNING, "invalid control message length %d",
		    hdr->length);
		break;
	case LENGTH_MISMATCH:
		syslog(LOG_WARNING, "control message length mismatch");
		break;
	}
}

void
ControlChannel::observeWriteError()
{
	syslog(LOG_WARNING, "failed to write message on control socket: %m");
	exit(1);
}
