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

#include <string.h>

#include "sslproc.h"
#include "sslproc_internal.h"
#include "CommandChannel.h"
#include "TargetStore.h"

const char *
PSSL_CIPHER_get_name(const PSSL_CIPHER *c)
{
	if (c == nullptr)
		return ("(NONE)");
	return (c->name);
}

int
PSSL_CIPHER_get_bits(const PSSL_CIPHER *c, int *alg_bits)
{
	if (c == nullptr)
		return (0);

	if (alg_bits != nullptr)
		*alg_bits = c->alg_bits;
	return (c->bits);
}

const PSSL_CIPHER *
PSSL_CIPHER_find(CommandChannel *cs, int target)
{
	PSSL_CIPHER *cipher = targets.lookup<PSSL_CIPHER>(target);
	if (cipher != nullptr)
		return (cipher);

	cipher = new PSSL_CIPHER();
	cipher->target = target;
	MessageRef ref = cs->waitForReply(Message::CIPHER_FETCH_INFO, target);
	if (!ref || ref.result()->error) {
		PROCerr(PROC_F_CIPHER_FIND, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to fetch cipher details");
		delete cipher;
		return (nullptr);
	}
	const Message::Result *msg = ref.result();
	if (msg->length < sizeof(Message::CipherResult)) {
		PROCerr(PROC_F_CIPHER_FIND, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "reply too short");
		delete cipher;
		return (nullptr);
	}
	const Message::CipherResult *cipherMsg =
	    reinterpret_cast<const Message::CipherResult *>(msg);
	cipher->bits = cipherMsg->bits;
	cipher->alg_bits = cipherMsg->alg_bits;
	if (cipherMsg->nameLength() == 0)
		cipher->name = nullptr;
	else
		cipher->name = strndup(cipherMsg->name(),
		    cipherMsg->nameLength());
	if (!targets.insert(target, cipher)) {
		PROCerr(PROC_F_CIPHER_FIND, ERR_R_INTERNAL_ERROR);
		ERR_add_error_data(1, "failed to add cipher to TargetStore");
		free(cipher->name);
		delete cipher;
		return (nullptr);
	}
	return (cipher);
}
