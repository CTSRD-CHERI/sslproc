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

#include "MessageHelpers.h"

std::vector<const char *>
parseStrings(const void *buf, size_t len)
{
	const char *cp = reinterpret_cast<const char *>(buf);
	const char *end = cp + len - 1;

	if (*end != '\0')
		return {};

	std::vector<const char *> strings;
	while (cp < end) {
		strings.push_back(cp);
		cp += strlen(cp) + 1;
	}
	return (strings);
}

void
freeIOVector(std::vector<struct iovec> &vector)
{
	for (const struct iovec &vec : vector)
		OPENSSL_free(vec.iov_base);
}

#define SERIALIZE_STACK_DEFINE(T)					\
std::vector<struct iovec>						\
sk_##T##_serialize(STACK_OF(T) *sk)					\
{									\
	int count = sk_##T##_num(sk);					\
	if (count <= 0)							\
		return {};						\
									\
	std::vector <struct iovec> vectors;				\
	struct iovec iov;						\
									\
	/* First, a count of items. */					\
	int *p = reinterpret_cast<int *>(OPENSSL_malloc(sizeof(int)));	\
	*p = count;							\
	iov.iov_base = p;						\
	iov.iov_len = sizeof(int);					\
	vectors.emplace_back(iov);					\
									\
	for (int i = 0; i < count; i++) {				\
		unsigned char *pp = nullptr;				\
		int len = i2d_##T(sk_##T##_value(sk, i), &pp);		\
		if (len < 0) {						\
			freeIOVector(vectors);				\
			return {};					\
		}							\
									\
		/* Each object is preceded by its length. */		\
		p = reinterpret_cast<int *>(OPENSSL_malloc(sizeof(int))); \
		*p = len;						\
		iov.iov_base = p;					\
		iov.iov_len = sizeof(int);				\
		vectors.emplace_back(iov);				\
									\
		iov.iov_base = pp;					\
		iov.iov_len = len;					\
		vectors.emplace_back(iov);				\
									\
		if (len % 4 == 0 || i == count - 1)			\
			continue;					\
									\
		/* Pad serialization to a 4 byte boundary. */		\
		iov.iov_len = 4 - (len % 4);				\
		iov.iov_base = OPENSSL_zalloc(iov.iov_len);		\
		vectors.emplace_back(iov);				\
	}								\
	return vectors;							\
}									\
									\
STACK_OF(T) *								\
sk_##T##_parse(const void *buf, size_t len)				\
{									\
	if (len < sizeof(int))						\
		return nullptr;						\
									\
	int count = *reinterpret_cast<const int *>(buf);		\
	if (count < 0)							\
		return nullptr;						\
									\
	STACK_OF(T) *sk;						\
									\
	sk = sk_##T##_new_reserve(nullptr, count);			\
									\
	const unsigned char *cp = 					\
	    reinterpret_cast<const unsigned char *>(buf);		\
	cp += sizeof(int);						\
	len -= sizeof(int);						\
									\
	for (int i = 0; i < count; i++) {				\
		if (len < sizeof(int))					\
			goto error;					\
									\
		int objLen = *reinterpret_cast<const int *>(cp);	\
		cp += sizeof(int);					\
		len -= sizeof(int);					\
									\
		if (len < objLen)					\
			goto error;					\
									\
		const unsigned char *pp = cp;				\
		T *item = d2i_##T(nullptr, &pp, objLen);		\
		if (item == nullptr)					\
			goto error;					\
		if (pp != cp + objLen) {				\
			T##_free(item);					\
			goto error;					\
		}							\
		sk_##T##_push(sk, item);				\
									\
		/* Round up to cover padding. */			\
		objLen += 4 - (objLen % 4);				\
		cp += objLen;						\
		if (len < objLen)					\
			len = 0;					\
		else							\
			len -= objLen;					\
	}								\
	return (sk);							\
									\
error:									\
	sk_##T##_pop_free(sk, T##_free);				\
	return nullptr;							\
}

SERIALIZE_STACK_DEFINE(X509);
SERIALIZE_STACK_DEFINE(X509_NAME);
