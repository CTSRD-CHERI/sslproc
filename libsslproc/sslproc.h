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

#include <openssl/pem.h>
#include <openssl/x509.h>

__BEGIN_DECLS

/* Types */

struct _PSSL_CONF_CTX;
typedef struct _PSSL_CONF_CTX PSSL_CONF_CTX;

struct _PSSL_METHOD;
typedef struct _PSSL_METHOD PSSL_METHOD;

struct _PSSL_CIPHER;
typedef struct _PSSL_CIPHER PSSL_CIPHER;

struct _PSSL_SESSION;
typedef struct _PSSL_SESSION PSSL_SESSION;

struct _PSSL_CTX;
typedef struct _PSSL_CTX PSSL_CTX;

struct _PSSL;
typedef struct _PSSL PSSL;

/* OPENSSL_init? */

/* SSL_CONF_CTX */

PSSL_CONF_CTX *PSSL_CONF_CTX_new(void);
int PSSL_CONF_CTX_finish(PSSL_CONF_CTX *cctx);
void PSSL_CONF_CTX_free(PSSL_CONF_CTX *cctx);
unsigned int PSSL_CONF_CTX_set_flags(PSSL_CONF_CTX *cctx, unsigned int flags);
int PSSL_CONF_cmd(PSSL_CONF_CTX *cctx, const char *cmd, const char *value);
int PSSL_CONF_cmd_value_type(PSSL_CONF_CTX *cctx, const char *cmd);
void PSSL_CONF_CTX_set_ssl_ctx(PSSL_CONF_CTX *cctx, PSSL_CTX *ctx);

/* SSL_METHOD */

const PSSL_METHOD *PTLS_method(void);
const PSSL_METHOD *PTLS_server_method(void);
const PSSL_METHOD *PTLS_client_method(void);

/* SSL_CIPHER */

const char *PSSL_CIPHER_get_name(const PSSL_CIPHER *c);
int PSSL_CIPHER_get_bits(const PSSL_CIPHER *c, int *alg_bits);
DEFINE_STACK_OF_CONST(PSSL_CIPHER)

/* SSL_SESSION */

PSSL_SESSION *PSSL_SESSION_new(void);
int PSSL_SESSION_up_ref(PSSL_SESSION *s);
void PSSL_SESSION_free(PSSL_SESSION *s);
const unsigned char *PSSL_SESSION_get_id(const PSSL_SESSION *s,
    unsigned int *len);
unsigned int PSSL_SESSION_get_compress_id(const PSSL_SESSION *s);
long PSSL_SESSION_get_time(const PSSL_SESSION *s);
PSSL_SESSION *d2i_PSSL_SESSION(PSSL_SESSION **a, const unsigned char **pp,
    long length);
int i2d_PSSL_SESSION(PSSL_SESSION *in, unsigned char **pp);

/* SSL_CTX */

PSSL_CTX *PSSL_CTX_new(const PSSL_METHOD *method);
int PSSL_CTX_up_ref(PSSL_CTX *ctx);
void PSSL_CTX_free(PSSL_CTX *ctx);
long PSSL_CTX_set_options(PSSL_CTX *ctx, long options);
long PSSL_CTX_clear_options(PSSL_CTX *ctx, long options);
long PSSL_CTX_get_options(PSSL_CTX *ctx);
long PSSL_CTX_ctrl(PSSL_CTX *ctx, int cmd, long larg, void *parg);
long PSSL_CTX_callback_ctrl(PSSL_CTX *ctx, int cmd, void (*cb)(void));
int PSSL_CTX_set_ex_data(PSSL_CTX *ctx, int idx, void *data);
void *PSSL_CTX_get_ex_data(const PSSL_CTX *ctx, int idx);
int PSSL_CTX_use_certificate(PSSL_CTX *ctx, X509 *x);
int PSSL_CTX_use_certificate_ASN1(PSSL_CTX *ctx, int len, unsigned char *d);
int PSSL_CTX_use_certificate_file(PSSL_CTX *ctx, const char *file, int type);
int PSSL_CTX_use_PrivateKey(PSSL_CTX *ctx, EVP_PKEY *pkey);
int PSSL_CTX_use_PrivateKey_ASN1(int type, PSSL_CTX *ctx,
    const unsigned char *d, int len);
int PSSL_CTX_use_PrivateKey_file(PSSL_CTX *ctx, const char *file, int type);
int PSSL_CTX_check_private_key(PSSL_CTX *ctx);
typedef int (*PSSL_client_hello_cb_fn)(PSSL *s, int *al, void *arg);
void PSSL_CTX_set_client_hello_cb(PSSL_CTX *ctx, PSSL_client_hello_cb_fn cb,
    void *arg);
int PSSL_CTX_set_srp_username_callback(PSSL_CTX *ctx,
    int (*cb)(PSSL *, int *, void *));
int PSSL_CTX_set_srp_cb_arg(PSSL_CTX *ctx, void *arg);
void PSSL_CTX_sess_set_new_cb(PSSL_CTX *ctx, int (*cb)(PSSL *, PSSL_SESSION *));
void PSSL_CTX_sess_set_remove_cb(PSSL_CTX *ctx,
    void (*cb)(PSSL_CTX *, PSSL_SESSION *));
void PSSL_CTX_sess_set_get_cb(PSSL_CTX *ctx,
    PSSL_SESSION * (*cb)(PSSL *, const unsigned char *, int, int *));
void PSSL_CTX_set_tmp_dh_callback(PSSL_CTX *ctx, DH *(*cb)(PSSL *, int, int));
void PSSL_CTX_set_info_callback(PSSL_CTX *ctx,
    void (*cb)(const PSSL *, int, int));
typedef int (*PSSL_CTX_alpn_select_cb_func)(PSSL *ssl,
    const unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg);
void PSSL_CTX_set_alpn_select_cb(PSSL_CTX *ctx, PSSL_CTX_alpn_select_cb_func cb,
    void *arg);
int PSSL_CTX_set_cipher_list(PSSL_CTX *ctx, const char *s);
int PSSL_CTX_set_ciphersuites(PSSL_CTX *ctx, const char *s);
long PSSL_CTX_set_timeout(PSSL_CTX *ctx, long time);
X509 *PSSL_CTX_get0_certificate(const PSSL_CTX *ctx);
void PSSL_CTX_set_client_cert_cb(PSSL_CTX *ctx,
    int (*cb)(PSSL *, X509 **, EVP_PKEY **));
typedef int (*PSSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);
void PSSL_CTX_set_verify(PSSL_CTX *ctx, int mode, PSSL_verify_cb cb);
PSSL_verify_cb PSSL_CTX_get_verify_callback(const PSSL_CTX *ctx);
int PSSL_CTX_get_verify_mode(const PSSL_CTX *ctx);
int PSSL_CTX_load_verify_locations(PSSL_CTX *ctx, const char *CAfile,
    const char *CApath);
X509_STORE *PSSL_CTX_get_cert_store(const PSSL_CTX *ctx);
void PSSL_CTX_set_client_CA_list(PSSL_CTX *ctx, STACK_OF(X509_NAME) *list);
STACK_OF(X509_NAME) *PSSL_CTX_get_client_CA_list(const PSSL_CTX *ctx);
void PSSL_CTX_set_default_passwd_cb(PSSL_CTX *ctx, pem_password_cb *cb);
void PSSL_CTX_set_default_passwd_cb_userdata(PSSL_CTX *ctx, void *data);
int PSSL_CTX_use_certificate_chain_file(PSSL_CTX *ctx, const char *file);
void PSSL_CTX_set_post_handshake_auth(PSSL_CTX *ctx, int val);

#define	PSSL_CTX_set0_chain(ctx, sk)					\
	PSSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, (char *)(sk))
#define	PSSL_CTX_set1_chain(ctx, sk)					\
	PSSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 1, (char *)(sk))
#define	PSSL_CTX_add0_chain_cert(ctx, x509)				\
	PSSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, (char *)(x509))
#define	PSSL_CTX_add1_chain_cert(ctx, x509)				\
	PSSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, (char *)(x509))
#define	PSSL_CTX_clear_chain_certs(ctx)					\
	PSSL_CTX_set0_chain(ctx, NULL)

/* SSL */

PSSL *PSSL_new(PSSL_CTX *ctx);
int PSSL_up_ref(PSSL *ssl);
void PSSL_free(PSSL *ssl);
long PSSL_set_options(PSSL *ssl, long options);
long PSSL_clear_options(PSSL *ssl, long options);
long PSSL_get_options(PSSL *ssl);
long PSSL_ctrl(PSSL *ssl, int cmd, long larg, void *parg);
int PSSL_set_ex_data(PSSL *ssl, int idx, void *data);
void *PSSL_get_ex_data(const PSSL *ssl, int idx);
int PSSL_use_certificate(PSSL *ssl, X509 *x);
int PSSL_use_certificate_ASN1(PSSL *ssl, const unsigned char *d, int len);
int PSSL_use_certificate_file(PSSL *ssl, const char *file, int type);
PSSL_CTX *PSSL_get_SSL_CTX(const PSSL *ssl);
PSSL_CTX *PSSL_set_SSL_CTX(PSSL *ssl, PSSL_CTX *ctx);
X509 *PSSL_get_peer_certificate(const PSSL *ssl);
long PSSL_get_verify_result(const PSSL *ssl);
void PSSL_set_verify_result(PSSL *ssl, long result);
int PSSL_get_verify_mode(const PSSL *ssl);
int PSSL_get_verify_depth(const PSSL *ssl);
void PSSL_set_verify(PSSL *ssl, int mode, PSSL_verify_cb cb);
int PSSL_verify_client_post_handshake(PSSL *ssl);
int PSSL_set_alpn_protos(PSSL *ssl, const unsigned char *protos,
    unsigned int len);
int PSSL_set_cipher_list(PSSL *ssl, const char *s);
int PSSL_set_ciphersuites(PSSL *ssl, const char *s);
char *PSSL_get_srp_username(PSSL *ssl);
char *PSSL_get_srp_userinfo(PSSL *ssl);
const PSSL_CIPHER *PSSL_get_current_cipher(const PSSL *ssl);
const PSSL_CIPHER *PSSL_get_pending_cipher(const PSSL *ssl);
int PSSL_set_session_id_context(PSSL *ssl, const unsigned char *ctx,
    unsigned int len);
void PSSL_set_msg_callback(PSSL *ssl, void (*cb)(int, int, int, const void *,
    size_t, PSSL *, void *));
BIO *PSSL_get_rbio(PSSL *ssl);
BIO *PSSL_get_wbio(PSSL *ssl);
void PSSL_set_bio(PSSL *ssl, BIO *rbio, BIO *wbio);
void PSSL_set0_rbio(PSSL *ssl, BIO *rbio);
void PSSL_set0_wbio(PSSL *ssl, BIO *wbio);
int PSSL_get_error(const PSSL *ssl, int i);
void PSSL_set_connect_state(PSSL *ssl);
void PSSL_set_accept_state(PSSL *ssl);
int PSSL_is_server(PSSL *ssl);
int PSSL_do_handshake(PSSL *ssl);
int PSSL_accept(PSSL *ssl);
int PSSL_connect(PSSL *ssl);
int PSSL_in_init(const PSSL *ssl);
int PSSL_in_before(const PSSL *ssl);
int PSSL_is_init_finished(const PSSL *ssl);
int PSSL_client_version(const PSSL *ssl);
const char *PSSL_get_version(const PSSL *ssl);
int PSSL_version(const PSSL *ssl);
const char *PSSL_get_servername(const PSSL *ssl, const int type);
int PSSL_get_servername_type(const PSSL *ssl);
int PSSL_read(PSSL *ssl, void *buf, int len);
int PSSL_peek(PSSL *ssl, void *buf, int len);
int PSSL_write(PSSL *ssl, const void *buf, int len);
void PSSL_set_shutdown(PSSL *ssl, int mode);
int PSSL_get_shutdown(const PSSL *ssl);
int PSSL_shutdown(PSSL *ssl);
int PSSL_get_ex_data_X509_STORE_CTX_idx(void);
void PSSL_set_default_passwd_cb(PSSL *ssl, pem_password_cb *cb);
void PSSL_set_default_passwd_cb_userdata(PSSL *ssl, void *data);
int PSSL_use_certificate_chain_file(PSSL *ssl, const char *file);
STACK_OF(PSSL_CIPHER) *PSSL_get_ciphers(PSSL *ssl);
STACK_OF(X509) *PSSL_get_peer_cert_chain(PSSL *ssl);
int PSSL_renegotiate(PSSL *ssl);
EVP_PKEY *PSSL_get_privatekey(PSSL *ssl);
STACK_OF(X509_NAME) *PSSL_get_client_CA_list(const PSSL *ssl);
const char *PSSL_state_string_long(const PSSL *ssl);

#define	PSSL_set0_chain(ssl, sk)					\
	PSSL_ctrl(ssl, SSL_CTRL_CHAIN, 0, (char *)(sk))
#define	PSSL_set1_chain(ssl, sk)					\
	PSSL_ctrl(ssl, SSL_CTRL_CHAIN, 1, (char *)(sk))
#define	PSSL_add0_chain_cert(ssl, x509)					\
	PSSL_ctrl(ssl, SSL_CTRL_CHAIN_CERT, 0, (char *)(x509))
#define	PSSL_add1_chain_cert(ssl, x509)					\
	PSSL_ctrl(ssl, SSL_CTRL_CHAIN_CERT, 1, (char *)(x509))
#define	PSSL_clear_chain_certs(ssl)					\
	PSSL_set0_chain(ssl, NULL)

__END_DECLS
