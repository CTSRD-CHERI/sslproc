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

#undef SSL_METHOD
#undef TLS_method
#undef TLS_server_method
#undef TLS_client_method

/* SSL_CTX */

#undef SSL_CTX
#undef SSL_CTX_new
#undef SSL_CTX_up_ref
#undef SSL_CTX_free
#undef SSL_CTX_set_options
#undef SSL_CTX_clear_options
#undef SSL_CTX_get_options
#undef SSL_CTX_ctrl
#undef SSL_CTX_set_ex_data
#undef SSL_CTX_get_ex_data
#undef SSL_CTX_use_certificate
#undef SSL_CTX_use_certificate_ASN1
#undef SSL_CTX_use_certificate_file
#undef SSL_CTX_use_PrivateKey
#undef SSL_CTX_use_PrivateKey_ASN1
#undef SSL_CTX_use_PrivateKey_file
#undef SSL_CTX_check_private_key

/* SSL */

#undef SSL
#undef SSL_new
#undef SSL_up_ref
#undef SSL_free
#undef SSL_ctrl
#undef SSL_set_msg_callback
#undef SSL_get_rbio
#undef SSL_get_wbio
#undef SSL_set_bio
#undef SSL_set0_rbio
#undef SSL_set0_wbio
#undef SSL_get_error
#undef SSL_accept
#undef SSL_connect
#undef SSL_read
#undef SSL_write
