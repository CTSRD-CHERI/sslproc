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

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <atomic>
#include <list>
#include <memory>

#include "sslproc_internal.h"
#include "ControlSocket.h"
#include "CommandSocket.h"
#include "TargetStore.h"

static std::list<CommandSocket *> commandSockets;
static pthread_mutex_t commandSocketsLock = { PTHREAD_MUTEX_INITIALIZER };
static std::unique_ptr<ControlSocket> controlSocket;
static thread_local std::unique_ptr<CommandSocket> commandSocket;
static thread_local std::unique_ptr<ControlSocket> childControlSocket;
TargetStore targets;

static void
MessageTracing_init(void)
{
	const char *tracerPath = getenv("LIBSSLPROC_TRACE_PATH");
	if (tracerPath == nullptr)
		return;

	int fd = open(tracerPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1)
		return;

	MessageSocket::enableTracing(fd);
}

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

	pthread_mutex_lock(&commandSocketsLock);
	commandSockets.push_back(cs);
	pthread_mutex_unlock(&commandSocketsLock);
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

/*
 * For an application fork(), the helper needs to also fork preserving
 * COW semantics for any state established in the helper by the
 * application process.  Waiting to fork the helper in the atchild
 * hook is racey as the parent might perform operations affecting the
 * state in the helper after fork() returns but before the atchild
 * hook runs in the parent.  To avoid this, the 'prepare' hook
 * executed in the parent prior to the system call forks the helper
 * and establishes a new ControlSocket.  The 'parent' hook deletes
 * this socket in the parent after the fork.  The 'child' hook uses
 * this socket as the ControlSocket in the child after the fork.
 */
void
POPENSSL_atfork_prepare(void)
{
	if (childControlSocket)
		return;

	ControlSocket *ctrl = controlSocket.get();
	if (ctrl == nullptr)
		return;

	/*
	 * Request a fork of the helper.  Create a new socketpair to
	 * use as the control socket in the child helper.
	 */
	int fds[2];
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds) == -1) {
		PROCerr(PROC_F_POPENSSL_ATFORK_PREPARE, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(2, "socketpair: ", strerror(errno));
		return;
	}

	if (!ctrl->requestFork(fds[1])) {
		close(fds[0]);
		close(fds[1]);
		return;
	}

	close(fds[1]);

	ControlSocket *newCtrl = new ControlSocket(fds[0]);
	if (!newCtrl->init()) {
		delete newCtrl;
		newCtrl = nullptr;
	}

	childControlSocket.reset(newCtrl);
}

void
POPENSSL_atfork_parent(void)
{
	childControlSocket.reset(nullptr);
}

void
POPENSSL_atfork_child(void)
{
	if (!childControlSocket)
		return;

	/*
	 * Teardown any command sockets inherited from the parent
	 * process.  No locking is needed here since the child process
	 * is single-threaded at this point.
	 */
	while (!commandSockets.empty()) {
		CommandSocket *cs = commandSockets.front();
		delete cs;
		commandSockets.pop_front();
	}

	/*
	 * Clear the TLS variable so that the first method will
	 * allocate a new command socket.
	 */
	commandSocket.release();

	/*
	 * Switch to the new ControlSocket allocated in the prepare
	 * hook.
	 */
	controlSocket = std::move(childControlSocket);
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
	MessageTracing_init();
	ControlSocket_init();
	pthread_atfork(POPENSSL_atfork_prepare, POPENSSL_atfork_parent,
	    POPENSSL_atfork_child);
	SSL_init();
	initted.store(1);
	return (0);
}

