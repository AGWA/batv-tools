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

#ifndef BATV_UTIL_HPP
#define BATV_UTIL_HPP

#include <stddef.h>
#include <stdint.h>
#include <string>

void	explicit_memzero (void* s, size_t n); // zero memory that won't be optimized away
void	store_be64 (unsigned char* p, uint64_t i);

inline void chomp (std::string& str) { str.erase(str.find_last_not_of(" \t\r\n") + 1); } // NB: std::string::npos+1==0

#endif
