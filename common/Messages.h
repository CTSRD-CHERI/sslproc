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
 * Messages sent and received over the IPC channels.
 */
namespace Message {
	enum Type {
		/* Messages without a target. */
		NOP = 0x0001,
		RESULT,

		/*
		 * Special message sent only on the control socket to
		 * allocate a command socket.  Each client thread or
		 * process needs its own command socket.
		 */
		CREATE_COMMAND_SOCKET,

		/* Returns a target for the created context. */
		CREATE_CONTEXT,

		/* Returns a target for the created context. */
		CREATE_CONF_CONTEXT,

		/* Operations on an SSL_CTX. */
		FREE_CONTEXT = 0x100,

		/* These three return 'long options' on success. */
		CTX_SET_OPTIONS,
		CTX_CLEAR_OPTIONS,
		CTX_GET_OPTIONS,

		CTX_CTRL,

		/* Message body is a ASN1-serialized X509 object. */
		CTX_USE_CERTIFICATE_ASN1,

		CTX_USE_PRIVATEKEY_ASN1,

		CTX_CHECK_PRIVATE_KEY,
		CTX_ENABLE_SERVERNAME_CB,
		CTX_DISABLE_SERVERNAME_CB,
		CTX_ENABLE_CLIENT_HELLO_CB,
		CTX_DISABLE_CLIENT_HELLO_CB,
		CTX_ENABLE_SRP_USERNAME_CB,
		CTX_DISABLE_SRP_USERNAME_CB,
		CTX_ENABLE_SESS_CBS,
		CTX_DISABLE_SESS_CBS,
		CTX_ENABLE_TMP_DH_CB,
		CTX_DISABLE_TMP_DH_CB,
		CTX_ENABLE_INFO_CB,
		CTX_DISABLE_INFO_CB,
		CTX_ENABLE_ALPN_SELECT_CB,
		CTX_DISABLE_ALPN_SELECT_CB,
		CTX_SET_CIPHER_LIST,
		CTX_SET_CIPHERSUITES,
		CTX_SET_TIMEOUT,
		CTX_GET0_CERTIFICATE,
		CTX_ENABLE_CLIENT_CERT_CB,
		CTX_DISABLE_CLIENT_CERT_CB,
		CTX_SET_VERIFY,
		CTX_LOAD_VERIFY_LOCATIONS,
		CTX_SET_CLIENT_CA_LIST,
		CTX_GET_CLIENT_CA_LIST,
		CTX_SET_POST_HANDSHAKE_AUTH,

		/* Returns a target for the created session. */
		CREATE_SESSION,

		/* Operations on an SSL. */
		FREE_SESSION = 0x200,

		/*
		 * The result of these messages return the return
		 * value of the associated SSL_* function in 'ret'.
		 */
		CONNECT,
		DO_HANDSHAKE,
		ACCEPT,
		SHUTDOWN,
		READ,
		PEEK,

		/*
		 * The payload of this message is the data to write.
		 * The length is implicit from the length of the
		 * payload.
		 */
		WRITE,

		ENABLE_MSG_CB,
		DISABLE_MSG_CB,

		SET_ACCEPT_STATE,
		SET_CONNECT_STATE,
		IS_SERVER,
		IN_INIT,
		IN_BEFORE,
		IS_INIT_FINISHED,
		GET_SERVERNAME,
		GET_SERVERNAME_TYPE,
		CTRL,

		/* Message body is a ASN1-serialized X509 object. */
		USE_CERTIFICATE_ASN1,

		SET_SHUTDOWN,
		GET_SHUTDOWN,
		GET_PEER_CERTIFICATE,
		GET_VERIFY_RESULT,
		SET_VERIFY_RESULT,
		GET_VERIFY_MODE,
		GET_VERIFY_DEPTH,
		SET_VERIFY,
		VERIFY_CLIENT_POST_HANDSHAKE,
		SET_ALPN_PROTOS,
		SET_CIPHER_LIST,
		SET_CIPHERSUITES,
		GET_SRP_USERNAME,
		GET_SRP_USERINFO,
		GET_CURRENT_CIPHER,
		GET_PENDING_CIPHER,
		SET_SESSION_ID_CONTEXT,
		CLIENT_VERSION,
		VERSION,
		SET_SSL_CTX,

		/* These three return 'long options' on success. */
		SET_OPTIONS,
		CLEAR_OPTIONS,
		GET_OPTIONS,

		/*
		 * Requests to operate on the BIOs belonging to an
		 * SSL.  The target identifies the SSL.
		 */
		BIO_READ = 0x300,
		BIO_WRITE,
		BIO_CTRL_READ,
		BIO_CTRL_WRITE,

		/*
		 * Callbacks on SSL objects.  The target identifies
		 * the SSL.
		 */
		MSG_CB = 0x400,

		/*
		 * The message body contains the '*al' or '*ad' value.
		 * The message reply can contain an updated value of
		 * '*al'/'*ad' in its body.
		 */
		SERVERNAME_CB,
		CLIENT_HELLO_CB,
		SRP_USERNAME_CB,

		SESS_NEW_CB,
		SESS_REMOVE_CB,
		SESS_GET_CB,
		TMP_DH_CB,
		INFO_CB,
		ALPN_SELECT_CB,
		CLIENT_CERT_CB,
		VERIFY_CB,
		DEFAULT_PASSWD_CB,

		/*
		 * This callback is invoked on an SSL_CTX instead of
		 * an SSL.
		 */
		CTX_DEFAULT_PASSWD_CB,

		/* Operations on an SSL_CONF_CTX. */
		FREE_CONF_CONTEXT = 0x500,
		CONF_CTX_FINISH,
		CONF_CTX_SET_FLAGS,
		CONF_CMD,
		CONF_CMD_VALUE_TYPE,
		CONF_CTX_SET_SSL_CTX,
	};

	struct Header {
		enum Type type;
		int	length;

		size_t bodyLength() const
		{
			return (length - sizeof(Header));
		}

		const void *body() const
		{
			return (this + 1);
		}
	};

	enum ContextMethod {
		METHOD_TLS = 0,		/* TLS_method() */
		METHOD_TLS_CLIENT,	/* TLS_server_method() */
		METHOD_TLS_SERVER	/* TLS_client_method() */
	};

	/* Body for CREATE_CONTEXT */
	struct CreateContext : public Header {
		enum ContextMethod method;
	};

	/* Body for messages targeted at an object. */
	struct Targeted : public Header {
		int target;
#if __SIZEOF_LONG__ == 8
		/*
		 * This ensures message bodies containing longs or
		 * pointers are aligned when the body is written in a
		 * separate iovec from the the header.  Note that
		 * using "alignas(void *)" doesn't work as subclasses
		 * of this feel free to move their members into the
		 * padding without an explicit pad0 field.
		 */
		int pad0;
#endif

		size_t bodyLength() const
		{
			return (length - sizeof(Targeted));
		}

		const void *body() const
		{
			return (this + 1);
		}
	};

	/*
	 * Body for CTX_SET_OPTIONS, CTX_CLEAR_OPTIONS, SET_OPTIONS,
	 * and CLEAR_OPTIONS.
	 */
	struct Options : public Targeted {
		long	options;
	};

	/*
	 * Body for CTX_CTRL and CTRL.  Additional
	 * data for the 'parg' may also be included.
	 */
	struct CtrlBody {
		int	cmd;
		long	larg;
	};

	struct Ctrl : public Targeted, CtrlBody {
		size_t bodyLength() const
		{
			return (length - sizeof(Ctrl));
		}

		const void *body() const
		{
			return (this + 1);
		}
	};

	/* Body for CTX_USE_PRIVATEKEY_ASN1 */
	struct PKey : public Targeted {
		int	pktype;

		size_t keyLength() const
		{
			return (length - sizeof(PKey));
		}

		const void *key() const
		{
			return (this + 1);
		}
	};

	/* Body for CTX_SET_VERIFY */
	struct SetVerify : public Targeted {
		int	mode;
		int	cb_set;
	};

	/*
	 * Body for READ and BIO_READ.
	 */
	struct Read : public Targeted {
		int	resid;		/* Max amount of data requested. */
	};

	/*
	 * Body for MSG_CB.  The message buffer is stored in
	 * the body.
	 */
	struct MsgCb : public Targeted {
		int	write_p;
		int	version;
		int	content_type;

		size_t bodyLength() const
		{
			return (length - sizeof(MsgCb));
		}

		const void *body() const
		{
			return (this + 1);
		}
	};

	/* Body for SESS_NEW_CB. */
	struct SessNewCb : public Targeted {
		long	time;
		int	compress_id;
		unsigned int id_len;
		long	internal_length;

		const void *id() const
		{
			return (this + 1);
		}

		const void *internal() const
		{
			return (reinterpret_cast<const char *>(id()) + id_len);
		}
	};

	/* Body for TMP_DH_CB. */
	struct TmpDhCb : public Targeted {
		int	is_export;
		int	keylength;
	};


	/* Body for INFO_CB. */
	struct InfoCb : public Targeted {
		int	where;
		int	ret;
	};

	/* Body for VERIFY_CB. */
	struct VerifyCb: public Targeted {
		int	preverify_ok;
		int	x509_error;
		int	x509_error_depth;

		size_t certLength() const
		{
			return (length - sizeof(VerifyCb));
		}

		const void *cert() const
		{
			return (this + 1);
		}
	};

	/* Body for DEFAULT_PASSWD_CB and CTX_DEFAULT_PASSWD_CB. */
	struct DefaultPasswdCb: public Targeted {
		int	rwflag;

		size_t bufLength() const
		{
			return (length - sizeof(DefaultPasswdCb));
		}

		const void *buf() const
		{
			return (this + 1);
		}
	};

	/*
	 * The receiver always returns a Result message to the sender
	 * at the completion of each operation.  'error' is set to
	 * SSL_ERROR_NONE on success, or another value for an error.
	 * If 'error' is SSL_ERROR_SYSCALL, the body contains an errno
	 * value as an int.  If 'error' is SSL_ERROR_SSL, the body
	 * contains an error string of the OpenSSL error queue
	 * generated by ERR_print_errors().
	 */
	struct Result : public Header {
		enum Type request;
		int	error;		/* SSL_ERROR_* */
		long	ret;

		size_t bodyLength() const
		{
			return (length - sizeof(Result));
		}

		const void *body() const
		{
			return (this + 1);
		}
	};

	/* Returned by GET_*_CIPHER. */
	struct CipherResultBody {
		int	bits;
		int	alg_bits;
	};

	struct CipherResult : public Result, CipherResultBody {
		size_t nameLength() const
		{
			return (length - sizeof(CipherResult));
		}

		const char *name() const
		{
			return (reinterpret_cast<const char *>(this + 1));
		}
	};

	/* Response from CLIENT_CERT_CB */
	struct ClientCertCbResultBody {
		int	cert_len;
		int	pk_len;
		int	pktype;
	};

	struct ClientCertCbResult : public Result, ClientCertCbResultBody {
		const void *cert() const
		{
			return (this + 1);
		}

		const void *pkey() const
		{
			return (reinterpret_cast<const char *>(cert()) +
			    cert_len);
		}
	};

	/* Response from VERIFY_CB */
	struct VerifyCbResult : public Result {
		int	x509_error;
	};
}
