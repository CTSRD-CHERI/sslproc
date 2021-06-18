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

#include <typeinfo>
#include <unordered_map>

/*
 * Some requests can accept a NULL target (e.g. SSL_CTX_ctrl).
 * NULL_TARGET is reserved as a marker for these cases.
 */
#define	NULL_TARGET	0

class TargetStore {
public:
	TargetStore()
	{}

	/* Allocate a new handle associated with an object. */
	template <class T>
	int allocate(T *obj)
	{ return (allocate(TargetValue(typeid(T *), obj))); }

	/* Insert a new mapping for an existing handle. */
	template <class T>
	bool insert(int target, T *obj)
	{ return (insert(target, TargetValue(typeid(T *), obj))); }

	/* Lookup objects by handle. */
	template <class T>
	T *lookup(int target)
	{ return (reinterpret_cast<T *>(lookup(target, typeid(T *)))); }

	void remove(int target);
private:
	struct TargetValue {
		TargetValue(const std::type_info &t, void *p)
		    : type(t), pointer(p)
		{}

		TargetValue(const std::type_info &t, const void *p)
		    : type(t), pointer(const_cast<void *>(p))
		{}

		const std::type_info &type;
		void *pointer;
	};

	int allocate(TargetValue &&value);
	bool insert(int target, TargetValue &&value);
	void *lookup(int target, const std::type_info &type);

	std::unordered_map<int, TargetValue> targets;
	int lastTarget;
};
