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

		size_t bodyLength() const
		{
			return (length - sizeof(Header));
		}

		const void *body() const
		{
			return (reinterpret_cast<const void *>(this + 1));
		}
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
	};

	struct Ctrl : public Header, CtrlBody {

		size_t bodyLength() const
		{
			return (length - sizeof(Ctrl));
		}

		const void *body() const
		{
			return (reinterpret_cast<const void *>(this + 1));
		}
	};

/* Message body is a ASN1-serialized X509 object. */
#define	SSLPROC_CTX_USE_CERTIFICATE_ASN1	7

#define	SSLPROC_CTX_USE_PRIVATEKEY_ASN1	8

	struct PKey : public Header {
		int	pktype;

		size_t keyLength() const
		{
			return (length - sizeof(PKey));
		}

		const void *key() const
		{
			return (reinterpret_cast<const void *>(this + 1));
		}
	};

#define	SSLPROC_CTX_CHECK_PRIVATE_KEY	9
#define	SSLPROC_CTX_ENABLE_SERVERNAME_CB	10
#define	SSLPROC_CTX_DISABLE_SERVERNAME_CB	11

/* Includes session fd in an SCM_RIGHTS control message. */
#define	SSLPROC_CREATE_SESSION	0x10

/* Per-session messages from client -> sslproc over the 'session' fd. */

/*
 * The result of these messages return the return value of the
 * associated SSL_* function in 'ret'.
 */
#define	SSLPROC_CONNECT		0x40
#define	SSLPROC_DO_HANDSHAKE	0x41
#define	SSLPROC_ACCEPT		0x42
#define	SSLPROC_SHUTDOWN	0x43

#define	SSLPROC_READ		0x44

	struct Read : public Header {
		int	resid;		/* Max amount of data requested. */
	};

/*
 * The payload of this message is the data to write.  The length is
 * implicit from the length of the payload.
 */
#define	SSLPROC_WRITE		0x45

#define	SSLPROC_ENABLE_MSG_CB	0x46
#define	SSLPROC_DISABLE_MSG_CB	0x47

#define	SSLPROC_SET_ACCEPT_STATE	0x48
#define	SSLPROC_SET_CONNECT_STATE	0x49
#define	SSLPROC_IS_SERVER	0x4a
#define	SSLPROC_IN_INIT		0x4b
#define	SSLPROC_IN_BEFORE	0x4c
#define	SSLPROC_IS_INIT_FINISHED	0x4d
#define	SSLPROC_GET_SERVERNAME	0x4e
#define	SSLPROC_GET_SERVERNAME_TYPE	0x4f
#define	SSLPROC_CTRL		0x50
#define	SSLPROC_SET_SHUTDOWN	0x51
#define	SSLPROC_GET_SHUTDOWN	0x52
#define	SSLPROC_GET_PEER_CERTIFICATE	0x53
#define	SSLPROC_GET_VERIFY_RESULT	0x54
#define	SSLPROC_SET_VERIFY_RESULT	0x55

/* Per-session messages from sslproc -> client over the 'session' fd. */

#define	SSLPROC_BIO_READ	0x80
#define	SSLPROC_BIO_WRITE	0x81
#define	SSLPROC_BIO_CTRL_READ	0x82
#define	SSLPROC_BIO_CTRL_WRITE	0x83

/* The message buffer is stored in the body. */
#define	SSLPROC_MSG_CB		0x84

	struct MsgCb : public Header {
		int	write_p;
		int	version;
		int	content_type;

		size_t bodyLength() const
		{
			return (length - sizeof(MsgCb));
		}

		const void *body() const
		{
			return (reinterpret_cast<const void *>(this + 1));
		}
	};

/*
 * While this callback is registered in the context, it is invoked on
 * a session.  The message body contains the '*al' alert value.  The
 * message reply can contain an updated value of '*al' in its body.
 */
#define	SSLPROC_SERVERNAME_CB	0x85

/*
 * The receiver always returns a Result message to the sender at the
 * completion of each operation.  'error' is set to SSL_ERROR_NONE on
 * success, or another value for an error.  If 'error' is
 * SSL_ERROR_SYSCALL, the body contains an errno value as an int.  If
 * 'error' is SSL_ERROR_SSL, the body contains an error string of the
 * OpenSSL error queue generated by ERR_print_errors().
 */
#define	SSLPROC_RESULT		0x100

	struct Result : public Header {
		int	request;	/* SSLPROC_* */
		int	error;		/* SSL_ERROR_* */
		long	ret;

		size_t bodyLength() const
		{
			return (length - sizeof(Result));
		}

		const void *body() const
		{
			return (reinterpret_cast<const void *>(this + 1));
		}
	};
}
