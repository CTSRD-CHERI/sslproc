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

#include <openssl/err.h>

#include "sslproc.h"
#include "sslproc_internal.h"

int PROC_lib;

static ERR_STRING_DATA PROC_strings[] = {
	{0, "sslproc"},
	{ERR_PACK(0, PROC_F_SSL_CTX_NEW, 0), "PSSL_CTX_new"},
	{ERR_PACK(0, PROC_F_READ_MESSAGE, 0), "MessageSocket::readMessage"},
	{ERR_PACK(0, PROC_F_WRITE_MESSAGE, 0), "MessageSocket::writeMessage"},
	{ERR_PACK(0, PROC_F_RECVMSG, 0), "recvmsg"},
	{ERR_PACK(0, PROC_F_SET_MESSAGE_ERROR, 0), "setMessageError"},
	{ERR_PACK(0, 0, ERR_R_IO_ERROR), "I/O error"},
	{ERR_PACK(0, 0, ERR_R_BAD_MESSAGE), "invalid message"},
	{ERR_PACK(0, 0, ERR_R_UNEXPECTED_EOF), "unexpected EOF"},
	{ERR_PACK(0, 0, ERR_R_MISMATCHED_REPLY), "mismatched reply"},
	{ERR_PACK(0, 0, ERR_R_MESSAGE_ERROR), "message error"},
	{0, nullptr},
};

void
PERR_init(void)
{
	PROC_lib = ERR_get_next_error_library();

	/* We have to patch the library-wide entry by hand. */
	PROC_strings[0].error = ERR_PACK(PROC_lib, 0, 0);
	ERR_load_strings(PROC_lib, PROC_strings);
}
