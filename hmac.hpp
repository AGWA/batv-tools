/*
 * Copyright (C) 2013 Andrew Ayer
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

#include <cstring>
#include <stddef.h>
#include "util.hpp"

namespace crypto {
	template<class Hash> class Hmac {
		Hash		hash;
		unsigned char	key[Hash::BLOCK_LENGTH];
		size_t		key_len;
	public:
		enum {
			LENGTH = Hash::LENGTH,
			KEY_LENGTH = Hash::BLOCK_LENGTH
		};

		Hmac (const unsigned char* arg_key, size_t arg_key_len =KEY_LENGTH)
		{
			if (arg_key_len > Hash::BLOCK_LENGTH) {
				Hash::compute(key, Hash::BLOCK_LENGTH, arg_key, arg_key_len);
				key_len = Hash::LENGTH;
			} else {
				std::memcpy(key, arg_key, arg_key_len);
				key_len = arg_key_len;
			}

			unsigned char	k_ipad[Hash::BLOCK_LENGTH];
			std::memset(k_ipad, 0, Hash::BLOCK_LENGTH);
			std::memcpy(k_ipad, key, key_len);
			for (size_t i = 0; i < Hash::BLOCK_LENGTH; ++i) {
				k_ipad[i] ^= 0x36;
			}

			hash.update(k_ipad, Hash::BLOCK_LENGTH);
			explicit_memzero(k_ipad, Hash::BLOCK_LENGTH);
		}
		~Hmac ()
		{
			explicit_memzero(key, Hash::BLOCK_LENGTH);
		}

		inline void	update (const void* data, size_t len)
		{
			hash.update(data, len);
		}

		void		finish (unsigned char* out, size_t out_len =LENGTH)
		{
			unsigned char	digest[Hash::LENGTH];
			hash.finish(digest);

			unsigned char	k_opad[Hash::BLOCK_LENGTH];
			std::memset(k_opad, 0, Hash::BLOCK_LENGTH);
			std::memcpy(k_opad, key, key_len);
			for (size_t i = 0; i < Hash::BLOCK_LENGTH; ++i) {
				k_opad[i] ^= 0x5c;
			}

			Hash		final_hash;
			final_hash.update(k_opad, Hash::BLOCK_LENGTH);
			final_hash.update(digest, Hash::LENGTH);
			final_hash.finish(out, out_len);

			explicit_memzero(k_opad, Hash::BLOCK_LENGTH);
		}

		static void compute (unsigned char* out, size_t out_len, const unsigned char* key, size_t key_len, const void* data, size_t data_len)
		{
			Hmac		hmac(key, key_len);
			hmac.update(data, data_len);
			hmac.finish(out, out_len);
		}
	};
}
