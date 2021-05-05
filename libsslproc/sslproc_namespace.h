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

/* SSL_METHOD */

#define	SSL_METHOD		PSSL_METHOD
#define	TLS_method		PTLS_method
#define	TLS_server_method	PTLS_server_method
#define	TLS_client_method	PTLS_client_method

/* SSL_CTX */

#define	SSL_CTX			PSSL_CTX
#define	SSL_CTX_new		PSSL_CTX_new
#define	SSL_CTX_up_ref		PSSL_CTX_up_ref
#define	SSL_CTX_free		PSSL_CTX_free
#define	SSL_CTX_set_options	PSSL_CTX_set_options
#define	SSL_CTX_clear_options	PSSL_CTX_clear_options
#define	SSL_CTX_get_options	PSSL_CTX_get_options
#define	SSL_CTX_ctrl		PSSL_CTX_ctrl
#define	SSL_CTX_set_ex_data	PSSL_CTX_set_ex_data
#define	SSL_CTX_get_ex_data	PSSL_CTX_get_ex_data

/* SSL */
