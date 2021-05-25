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

__BEGIN_DECLS

/* OPENSSL_init */

int	POPENSSL_init_ssl(void);

/* ERR */

extern int PROC_lib;
void	PERR_init(void);

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
#define	PROC_F_SSL_HANDLE_MESSAGE	14
#define	PROC_F_SSL_READ			15
#define	PROC_F_D2I_SSL_SESSION		16

#define	ERR_R_IO_ERROR		(128|ERR_R_FATAL)
#define	ERR_R_BAD_MESSAGE	(129|ERR_R_FATAL)
#define	ERR_R_UNEXPECTED_EOF	(130|ERR_R_FATAL)
#define	ERR_R_MISMATCHED_REPLY	(131|ERR_R_FATAL)
#define	ERR_R_MESSAGE_ERROR	(132)
#define	ERR_R_BAD_VERSION	(133|ERR_R_FATAL)

/* SSL_METHOD */

struct _PSSL_METHOD {
	int method;	/* SSL_METHOD_* */
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

class ControlSocket;
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
	ControlSocket *cs;
	CRYPTO_EX_DATA ex_data;
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
	bool sess_cbs_enabled;
	std::unordered_map<session_map_key, struct _PSSL_SESSION *> sessions;
	std::atomic_int refs;
};

/* SSL */

class SSLSession;

struct _PSSL {
	struct _PSSL_CTX *ctx;
	CRYPTO_EX_DATA ex_data;
	BIO *rbio;
	BIO *wbio;
	SSLSession *ss;
	char *servername;
	char *srp_username;
	char *srp_userinfo;
	struct _PSSL_CIPHER current_cipher;
	struct _PSSL_CIPHER pending_cipher;
	void (*msg_cb)(int, int, int, const void *, size_t, struct _PSSL *, void *);
	void *msg_cb_arg;
	std::atomic_int refs;
	int last_error;
};
