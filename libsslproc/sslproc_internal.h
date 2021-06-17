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

#include <sys/cdefs.h>
#include <atomic>
#include <unordered_map>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <Messages.h>

__BEGIN_DECLS

/* OPENSSL_init */

int	POPENSSL_init_ssl(void);

/* ERR */

extern int PROC_lib;
void	PERR_init(void);

void	SSL_init(void);

class CommandSocket;

CommandSocket *currentCommandSocket();

class TargetStore;

extern TargetStore targets;

__END_DECLS

#define	PROCerr(f,r)	ERR_PUT_error(PROC_lib, (f), (r), __FILE__, __LINE__)

#define	PROC_F_SSL_CTX_NEW		1
#define	PROC_F_READ_MESSAGE		2
#define	PROC_F_WRITE_MESSAGE		3
#define	PROC_F_RECVMSG			4
#define	PROC_F_WAIT_FOR_REPLY		5
#define	PROC_F_SET_MESSAGE_ERROR	6
#define	PROC_F_SSL_NEW			7
#define	PROC_F_SSL_CTX_USE_CERTIFICATE	8
#define	PROC_F_SSL_CTX_USE_CERTIFICATE_ASN1	9
#define	PROC_F_SSL_CTX_USE_CERTIFICATE_FILE	10
#define	PROC_F_SSL_CTX_USE_PRIVATEKEY	11
#define	PROC_F_SSL_CTX_USE_PRIVATEKEY_ASN1	12
#define	PROC_F_SSL_CTX_USE_PRIVATEKEY_FILE	13
#define	PROC_F_CMDSOCK_HANDLE_MESSAGE	14
#define	PROC_F_SSL_READ			15
#define	PROC_F_D2I_SSL_SESSION		16
#define	PROC_F_SSL_CTX_SET_CIPHER_LIST	17
#define	PROC_F_SSL_CTX_SET_CIPHERSUITES	18
#define	PROC_F_CONTROLSOCKET_INIT	19
#define	PROC_F_CREATECOMMANDSOCKET	20
#define	PROC_F_SSL_CTX_CTRL		21
#define	PROC_F_SSL_CTX_CHECK_PRIVATE_KEY	22
#define	PROC_F_SSL_CTX_SET_SRP_USERNAME_CALLBACK	23
#define	PROC_F_SSL_CTX_GET0_CERTIFICATE	24
#define	PROC_F_SSL_CTRL			25
#define	PROC_F_SSL_GET_PEER_CERTIFICATE	26
#define	PROC_F_SSL_GET_VERIFY_RESULT	27
#define	PROC_F_SSL_GET_SRP_USERNAME	28
#define	PROC_F_SSL_GET_SRP_USERINFO	29
#define	PROC_F_SSL_FETCH_CIPHER		30
#define	PROC_F_SSL_SET_SESSION_ID_CONTEXT	31
#define	PROC_F_SSL_DO_HANDSHAKE		32
#define	PROC_F_SSL_ACCEPT		33
#define	PROC_F_SSL_CONNECT		34
#define	PROC_F_SSL_GET_SERVERNAME	35
#define	PROC_F_SSL_WRITE		36
#define	PROC_F_SSL_SHUTDOWN		37
#define	PROC_F_SSL_SET_SSL_CTX		38
#define	PROC_F_SSL_CONF_CTX_NEW		39
#define	PROC_F_SSL_CONF_CTX_FINISH	40
#define	PROC_F_SSL_CONF_CMD		41
#define	PROC_F_SSL_CTX_LOAD_VERIFY_LOCATIONS	42
#define	PROC_F_USE_CERTIFICATE_CHAIN_FILE	43
#define	PROC_F_SSL_USE_CERTIFICATE	44
#define	PROC_F_SSL_USE_CERTIFICATE_ASN1	45
#define	PROC_F_SSL_USE_CERTIFICATE_FILE	46
#define	PROC_F_SSL_SET_CIPHER_LIST	47
#define	PROC_F_SSL_SET_CIPHERSUITES	48

#define	ERR_R_IO_ERROR		(128|ERR_R_FATAL)
#define	ERR_R_BAD_MESSAGE	(129|ERR_R_FATAL)
#define	ERR_R_UNEXPECTED_EOF	(130|ERR_R_FATAL)
#define	ERR_R_MISMATCHED_REPLY	(131|ERR_R_FATAL)
#define	ERR_R_MESSAGE_ERROR	(132)
#define	ERR_R_BAD_VERSION	(133|ERR_R_FATAL)
#define	ERR_R_NO_BUFFER		(134|ERR_R_FATAL)
#define	ERR_R_MISSING_TARGET	(135|ERR_R_FATAL)
#define	ERR_R_NO_COMMAND_SOCKET	(136|ERR_R_FATAL)

/* SSL_CONF_CTX */

struct _PSSL_CTX;

struct _PSSL_CONF_CTX {
	int target;
};

/* SSL_METHOD */

struct _PSSL_METHOD {
	enum Message::ContextMethod method;
};

/* SSL_CIPHER */

struct _PSSL_CIPHER {
	char *name;
	int alg_bits;
	int bits;
};

/* SSL_SESSION */

struct _PSSL_SESSION {
	long time;
	int compress_id;
	unsigned char *id;
	unsigned int id_len;
	unsigned char *internal_repr;
	long internal_length;
	std::atomic_int refs;
};

/* SSL_CTX */

struct _PSSL;

struct session_map_key {
	session_map_key(const unsigned char *_id, unsigned int _len) :
	    id(_id), id_len(_len)
	{}

	const unsigned char *id;
	unsigned int id_len;
};

inline bool operator==(const session_map_key &l, const session_map_key &r)
{
	if (l.id_len != r.id_len)
		return (false);
	return (memcmp(l.id, r.id, l.id_len) == 0);
}

namespace std {
	template<> struct hash<session_map_key> {
		inline size_t operator()(const session_map_key &k) const noexcept
		{
			size_t value;

			if (k.id_len >= sizeof(value))
				value = *reinterpret_cast<const size_t *>(k.id);
			else if (k.id_len == 0)
				value = 0;
			else
				value = *k.id;
			return (value);
		}
	};
}

struct _PSSL_CTX {
	int target;
	CRYPTO_EX_DATA ex_data;
	X509 *get0_cert;
	STACK_OF(X509_NAME) *client_CA_list;
	int (*servername_cb)(struct _PSSL *, int *, void *);
	void *servername_cb_arg;
	int (*client_hello_cb)(struct _PSSL *, int *, void *);
	void *client_hello_cb_arg;
	int (*srp_username_cb)(struct _PSSL *, int *, void *);
	void *srp_cb_arg;
	int (*sess_new_cb)(struct _PSSL *, struct _PSSL_SESSION *);
	void (*sess_remove_cb)(struct _PSSL_CTX *, struct _PSSL_SESSION *);
	struct _PSSL_SESSION *(*sess_get_cb)(struct _PSSL *,
	    const unsigned char *, int, int *);
	DH *(*tmp_dh_cb)(struct _PSSL *, int, int);
	void (*info_cb)(const struct _PSSL *, int, int);
	int (*alpn_select_cb)(struct _PSSL *, const unsigned char **,
	    unsigned char *, const unsigned char *, unsigned int, void *);
	void *alpn_select_cb_arg;
	int (*client_cert_cb)(struct _PSSL *, X509 **, EVP_PKEY **);
	int (*verify_cb)(int, X509_STORE_CTX *);
	pem_password_cb *default_passwd_cb;
	void *default_passwd_cb_userdata;
	bool sess_cbs_enabled;
	std::unordered_map<session_map_key, struct _PSSL_SESSION *> sessions;
	std::atomic_int refs;
};

/* SSL */

struct _PSSL {
	int target;
	struct _PSSL_CTX *ctx;
	CRYPTO_EX_DATA ex_data;
	BIO *rbio;
	BIO *wbio;
	char *servername;
	char *srp_username;
	char *srp_userinfo;
	struct _PSSL_CIPHER current_cipher;
	struct _PSSL_CIPHER pending_cipher;
	void (*msg_cb)(int, int, int, const void *, size_t, struct _PSSL *, void *);
	void *msg_cb_arg;
	int (*verify_cb)(int, X509_STORE_CTX *);
	pem_password_cb *default_passwd_cb;
	void *default_passwd_cb_userdata;
	std::atomic_int refs;
	int last_error;
};
