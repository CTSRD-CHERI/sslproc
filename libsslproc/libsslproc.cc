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
#include <atomic>
#include <memory>

#include "sslproc_internal.h"
#include "ControlSocket.h"
#include "CommandSocket.h"
#include "TargetStore.h"

static std::unique_ptr<ControlSocket> controlSocket;
static thread_local std::unique_ptr<CommandSocket> commandSocket;
TargetStore targets;

static void
ControlSocket_init(void)
{
	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds) == -1) {
		PROCerr(PROC_F_CONTROLSOCKET_INIT, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "socketpair: ", strerror(errno));
		return;
	}

	/*
	 * This doesn't use posix_spawn due to a lack of
	 * posix_spawn_file_actions_addclosefrom().
	 */
	pid_t pid = vfork();
	if (pid == -1) {
		close(fds[0]);
		close(fds[1]);
		return;
	}

	if (pid == 0) {
		/* child */
		if (dup2(fds[1], 3) == -1)
			exit(127);
		closefrom(4);
		execlp("sslproc", "sslproc", NULL);
		exit(127);
	}

	close(fds[1]);

	ControlSocket *cs = new ControlSocket(fds[0]);
	if (!cs->init()) {
		delete cs;

		/* TODO: wait for child, maybe kill it if necessary? */
		return;
	}

	controlSocket.reset(cs);
}

static CommandSocket *
createCommandSocket()
{
	ControlSocket *ctrl = controlSocket.get();
	if (ctrl == nullptr)
		return (nullptr);

	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fds) == -1) {
		PROCerr(PROC_F_CONTROLSOCKET_INIT, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "socketpair: ", strerror(errno));
		return (nullptr);
	}

	if (!ctrl->createCommandSocket(fds[1])) {
		close(fds[0]);
		close(fds[1]);
		return (nullptr);
	}

	close(fds[1]);

	CommandSocket *cs = new CommandSocket(fds[0]);
	if (!cs->init()) {
		delete cs;
		return (nullptr);
	}

	return (cs);
}

CommandSocket *
currentCommandSocket()
{
	CommandSocket *cs = commandSocket.get();
	if (cs == nullptr) {
		cs = createCommandSocket();
		commandSocket.reset(cs);
	}
	return (cs);
}

int
POPENSSL_init_ssl(void)
{
	static std::atomic_int initted;

	if (initted > 0)
		return (0);

	for (;;) {
		int value;

		value = initted.load();
		if (value > 0)
			return (0);
		if (value == 0 && initted.compare_exchange_weak(value, -1))
			break;
	}

	PERR_init();
	ControlSocket_init();
	SSL_init();
	initted.store(1);
	return (0);
}

