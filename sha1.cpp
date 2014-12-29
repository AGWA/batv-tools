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

#include "sha1.hpp"
#include "util.hpp"
#include <cstring>
#include <stdint.h>

using namespace crypto;
using std::memset;
using std::memcpy;

Sha1_state::Sha1_state ()
{
	state[0] = 0x67452301;
	state[1] = 0xEFCDAB89;
	state[2] = 0x98BADCFE;
	state[3] = 0x10325476;
	state[4] = 0xC3D2E1F0;
}

Sha1_state::~Sha1_state ()
{
	explicit_memzero(state, sizeof(state));
}

/* Loosely based on "100% Public Domain" SHA-1 C implementation by Steve Reid <steve@edmweb.com> */

#define LOAD_BE32(p) ((((const unsigned char *)(p))[0] << 24) | \
		      (((const unsigned char *)(p))[1] << 16) | \
		      (((const unsigned char *)(p))[2] <<  8) | \
		      (((const unsigned char *)(p))[3] <<  0) )

#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define BLK(i) (blocks[(i)&15])
#define SRC_BUFFER(i) (LOAD_BE32(buffer + (i)*4))
#define SRC_BLOCKS(i) (ROL(BLK((i)+13) ^ BLK((i)+8) ^ BLK((i)+2) ^ BLK(i), 1))

#define DO_ROUND(v, w, x, y, z, i, source, constant, function) \
	do { \
		BLK(i) = source(i); \
		z += (function) + BLK(i) + constant + ROL(v, 5); \
		w = ROL(w, 30); \
	} while (0)

#define R1A(v, w, x, y, z, i) DO_ROUND(v, w, x, y, z, i, SRC_BUFFER, 0x5A827999, ((w&(x^y))^y))
#define R1B(v, w, x, y, z, i) DO_ROUND(v, w, x, y, z, i, SRC_BLOCKS, 0x5A827999, ((w&(x^y))^y))
#define R2(v, w, x, y, z, i)  DO_ROUND(v, w, x, y, z, i, SRC_BLOCKS, 0x6ED9EBA1, (w^x^y))
#define R3(v, w, x, y, z, i)  DO_ROUND(v, w, x, y, z, i, SRC_BLOCKS, 0x8F1BBCDC, (((w|x)&y)|(w&x)))
#define R4(v, w, x, y, z, i)  DO_ROUND(v, w, x, y, z, i, SRC_BLOCKS, 0xCA62C1D6, (w^x^y))

void Sha1_state::transform (const unsigned char* buffer)
{
	uint32_t a, b, c, d, e;
	uint32_t blocks[16];

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* Round 1 */
	R1A(a,b,c,d,e, 0); R1A(e,a,b,c,d, 1); R1A(d,e,a,b,c, 2); R1A(c,d,e,a,b, 3);
	R1A(b,c,d,e,a, 4); R1A(a,b,c,d,e, 5); R1A(e,a,b,c,d, 6); R1A(d,e,a,b,c, 7);
	R1A(c,d,e,a,b, 8); R1A(b,c,d,e,a, 9); R1A(a,b,c,d,e,10); R1A(e,a,b,c,d,11);
	R1A(d,e,a,b,c,12); R1A(c,d,e,a,b,13); R1A(b,c,d,e,a,14); R1A(a,b,c,d,e,15);
	R1B(e,a,b,c,d,16); R1B(d,e,a,b,c,17); R1B(c,d,e,a,b,18); R1B(b,c,d,e,a,19);

	/* Round 2 */
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);

	/* Round 3 */
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);

	/* Round 4 */
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	explicit_memzero(&a, sizeof(a));
	explicit_memzero(&b, sizeof(b));
	explicit_memzero(&c, sizeof(c));
	explicit_memzero(&d, sizeof(d));
	explicit_memzero(&e, sizeof(e));
	explicit_memzero(blocks, sizeof(blocks));
}

void Sha1_state::write (unsigned char* out, size_t out_len)
{
	if (out) {
		for (unsigned int i = 0; i < out_len && i < LENGTH; ++i) {
			out[i] = (state[i / 4] >> ((3 - (i % 4)) * 8)) & 0xFF;
		}
	}
}
