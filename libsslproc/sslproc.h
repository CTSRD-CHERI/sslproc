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

__BEGIN_DECLS

/* OPENSSL_init? */

/* ERR */

unsigned long PERR_get_error(void);
unsigned long PERR_peek_error(void);
unsigned long PERR_peek_last_error(void);
unsigned long PERR_get_error_line(const char **file, int *line);
unsigned long PERR_peek_error_line(const char **file, int *line);
unsigned long PERR_peek_last_error_line(const char **file, int *line);
unsigned long PERR_get_error_line_data(const char **file, int *line,
    const char **data, int *flags);
unsigned long PERR_peek_error_line_data(const char **file, int *line,
    const char **data, int *flags);
unsigned long PERR_peek_last_error_line_data(const char **file, int *line,
    const char **data, int *flags);
void PERR_clear_error(void);

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

/* SSL */

__END_DECLS
