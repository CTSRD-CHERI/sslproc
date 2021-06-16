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

/* Helper routines for parsing chunks of data in message bodies. */

#include <sys/uio.h>
#include <vector>

#include <openssl/x509.h>

/*
 * Return a vector of pointers to nul-terminated C strings in a
 * buffer.  If the buffer is not nul-terminated, an empty vector is
 * returned.
 */
std::vector<const char *> parseStrings(const void *buf, size_t len);

/*
 * Free a dynamically allocated vector of iovecs.  Assumes each buffer
 * in the iovec is allocated by OPENSSL_malloc().
 */
void freeIOVector(std::vector<struct iovec> &vector);

/*
 * Routines to serialize and then de-serialize (parse) an OpenSSL
 * stack of objects (STACK_OF(T)).
 */
#define	SERIALIZE_STACK_DECLARE(T)					\
std::vector<struct iovec> sk_##T##_serialize(STACK_OF(T) *);		\
STACK_OF(T) *sk_##T##_parse(const void *buf, size_t len)

SERIALIZE_STACK_DECLARE(X509);
SERIALIZE_STACK_DECLARE(X509_NAME);
