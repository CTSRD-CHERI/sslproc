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

#pragma once

/*
 * Messages sent and received over the various sockets.
 */
namespace Message {

	struct Header {
		int	type;
		int	length;
	};

/* Global messages from client -> sslproc over the 'control' socket. */

#define	SSLPROC_NOP			1
#define	SSLPROC_CREATE_CONTEXT		2

	struct CreateContext : public Header {
		int	method;		/* SSLPROC_METHOD_* */
	};

#define	SSLPROC_METHOD_TLS		0	/* TLS_method() */
#define	SSLPROC_METHOD_TLS_CLIENT	1	/* TLS_server_method() */
#define	SSLPROC_METHOD_TLS_SERVER	2	/* TLS_client_method() */

/* These three return 'long options' on success. */
#define	SSLPROC_CTX_SET_OPTIONS		3
#define	SSLPROC_CTX_CLEAR_OPTIONS	4

	struct Options : public Header {
		long	options;
	};

#define	SSLPROC_CTX_GET_OPTIONS		5

#define	SSLPROC_CTX_CTRL		6

	struct CtrlBody {
		int	cmd;
		long	larg;
		/* TODO: Nothing that supports parg yet. */
	};

	struct Ctrl : public Header, CtrlBody {};

/* Includes session fd in an SCM_RIGHTS control message. */
#define	SSLPROC_CREATE_SESSION	0x10

/* Per-session messages from client -> sslproc over the 'app' fd. */

/*
 * The result of these messages return the return value of the
 * associated SSL_* function in 'ret'.  If 'ret' indicates failure,
 * the return value of SSL_get_error() is appended as an int.
 */
#define	SSLPROC_CONNECT		0x40
#define	SSLPROC_ACCEPT		0x42
#define	SSLPROC_SHUTDOWN	0x43

#define	SSLPROC_READ		0x44

	struct Read : public Header {
		int	resid;		/* Max amount of data requested. */
	};

#define	SSLPROC_WRITE		0x45

/* Per-session messages from sslproc -> client over the 'raw' fd. */

/*
 * The result of these messages return the number of bytes
 * transferred in 'ret'.  If an error occurs, 'ret' is set to -1, and
 * the 'errno' value is returned as 'data' as an int.
 */
#define	SSLPROC_READ_RAW	0x80
#define	SSLPROC_WRITE_RAW	0x81

/*
 * The receiver always returns a Result message to the sender at the
 * completion of each operation.
 */
#define	SSLPROC_RESULT		0x100

	struct Result : public Header {
		int	request;	/* SSLPROC_* */
		int	error;		/* SSL_ERROR_* */
		long	ret;
		char	body[];

		size_t bodyLength() const
		{
			return (length - sizeof(Result));
		}
	};
}
