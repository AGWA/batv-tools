/*
 * Copyright 2014 Andrew Ayer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "util.hpp"

void explicit_memzero (void* s, size_t n)
{
	volatile unsigned char* p = reinterpret_cast<unsigned char*>(s);

	while (n--) {
		*p++ = 0;
	}
}

void store_be64 (unsigned char* p, uint64_t i)
{
	p[7] = i; i >>= 8;
	p[6] = i; i >>= 8;
	p[5] = i; i >>= 8;
	p[4] = i; i >>= 8;
	p[3] = i; i >>= 8;
	p[2] = i; i >>= 8;
	p[1] = i; i >>= 8;
	p[0] = i;
}
