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

#include <openssl/x509.h>

__BEGIN_DECLS

/* OPENSSL_init? */

/* SSL_METHOD */

struct _PSSL_METHOD;
typedef struct _PSSL_METHOD PSSL_METHOD;

const PSSL_METHOD *PTLS_method(void);
const PSSL_METHOD *PTLS_server_method(void);
const PSSL_METHOD *PTLS_client_method(void);

/* SSL_CTX */

struct _PSSL_CTX;
typedef struct _PSSL_CTX PSSL_CTX;

PSSL_CTX *PSSL_CTX_new(const PSSL_METHOD *method);
int PSSL_CTX_up_ref(PSSL_CTX *ctx);
void PSSL_CTX_free(PSSL_CTX *ctx);
long PSSL_CTX_set_options(PSSL_CTX *ctx, long options);
long PSSL_CTX_clear_options(PSSL_CTX *ctx, long options);
long PSSL_CTX_get_options(PSSL_CTX *ctx);
long PSSL_CTX_ctrl(PSSL_CTX *ctx, int cmd, long larg, void *parg);
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

/* SSL */

struct _PSSL;
typedef struct _PSSL PSSL;

PSSL *PSSL_new(PSSL_CTX *ctx);
int PSSL_up_ref(PSSL *ssl);
void PSSL_free(PSSL *ssl);
long PSSL_ctrl(PSSL *ssl, int cmd, long larg, void *parg);
int PSSL_set_ex_data(PSSL *ssl, int idx, void *data);
void *PSSL_get_ex_data(const PSSL *ssl, int idx);
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
int PSSL_read(PSSL *ssl, void *buf, int len);
int PSSL_write(PSSL *ssl, const void *buf, int len);

__END_DECLS
