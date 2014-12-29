/*
 * Copyright (C) 2014 Andrew Ayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization.
 */

#pragma once

#include <stddef.h>
#include <cstring>
#include <stdexcept>
#include "util.hpp"

namespace crypto {
	template<class State> class Block_hash {
	public:
		enum {
			LENGTH = State::LENGTH,
			BLOCK_LENGTH = State::BLOCK_LENGTH
		};

	private:
		State			state;
		unsigned long long	count;
		unsigned char		buffer[BLOCK_LENGTH];

	public:
		Block_hash () : count(0) { }
		~Block_hash ()
		{
			explicit_memzero(&count, sizeof(count));
			explicit_memzero(buffer, sizeof(buffer));
		}

		unsigned long long	get_count () const { return count; }

		void			update (const void* data, size_t len)
		{
			const unsigned char*	p = reinterpret_cast<const unsigned char*>(data);
			size_t			pending_len = count % BLOCK_LENGTH;
			const size_t		remaining_len = BLOCK_LENGTH - pending_len;

			if (count + len < count) {
				throw std::overflow_error("crypto::Block_hash::update");
			}
			count += len;

			if (len >= remaining_len) {
				// Make buffer a complete block
				std::memcpy(buffer + pending_len, p, remaining_len);
				p += remaining_len;
				len -= remaining_len;
				state.transform(buffer);
				pending_len = 0;

				// Now process remaining blocks
				while (len >= BLOCK_LENGTH) {
					state.transform(p);
					p += BLOCK_LENGTH;
					len -= BLOCK_LENGTH;
				}
			}
			std::memcpy(buffer + pending_len, p, len);
		}

		void			finish (unsigned char* out, size_t out_len =LENGTH)
		{
			State::pad(*this);
			state.write(out, out_len);
		}

		static void		compute (unsigned char* out, size_t out_len, const void* data, size_t data_len)
		{
			Block_hash	hash;
			hash.update(data, data_len);
			hash.finish(out, out_len);
		}

		static void		compute (unsigned char* out, const void* data, size_t data_len)
		{
			compute(out, LENGTH, data, data_len);
		}
	};
}
