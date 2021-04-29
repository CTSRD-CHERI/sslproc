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

#include <malloc_np.h>
#include <stdlib.h>
#include <string.h>

#include "IOBuffer.h"

IOBuffer::~IOBuffer()
{
	free(buffer_);
}

bool
IOBuffer::advance(size_t amount)
{

	if (amount > length_ - offset_)
		return (false);

	offset_ += amount;
	if (offset_ == length_)
		reset();
	return (true);
}

bool
IOBuffer::advanceEnd(size_t amount)
{

	if (amount > capacity_ - length_)
		return (false);

	length_ += amount;
	return (true);
}

void
IOBuffer::reset()
{
	offset_ = 0;
	length_ = 0;
}

/* Ensure there is sufficient room to append 'amount' bytes to the buffer.  */
bool
IOBuffer::grow(size_t amount)
{
	size_t newCapacity = length_ + amount;
	if (newCapacity <= capacity_)
		return (true);

	char *newBuffer = reinterpret_cast<char *>(realloc(buffer_,
	    newCapacity));
	if (newBuffer == NULL)
		return (false);

	free(buffer_);
	buffer_ = newBuffer;
	capacity_ = malloc_usable_size(newBuffer);
	return (true);
}

bool
IOBuffer::appendData(void *p, size_t len)
{
	if (!grow(len))
		return (false);

	memcpy(buffer_ + offset_, p, len);
	length_ += len;
	return (true);
}
