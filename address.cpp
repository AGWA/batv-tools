/*
 * Copyright 2013 Andrew Ayer
 *
 * This file is part of batv-tools.
 *
 * batv-tools is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * batv-tools is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with batv-tools.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "address.hpp"
#include <cctype>
#include <cstring>

using namespace batv;

bool Batv_address::parse (const Email_address& address, char sub_address_delimiter)
{
	const char*		p = address.local_part.c_str();

	if (sub_address_delimiter) {
		// non-standard format, using sub-addressing

		// eat the loc-core (up to last delimiter character)
		const char*	loc_core_start = p;
		p = std::strrchr(p, sub_address_delimiter);
		if (!p) {
			return false;
		}
		orig_mailfrom.local_part.assign(loc_core_start, p);
		++p;
		
		// eat the tag-type (up to '=')
		const char*	tag_type_start = p;
		while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
			++p;
		}
		if (*p != '=') {
			return false;
		}
		tag_type.assign(tag_type_start, p);
		++p;

		// eat the tag-val (rest of local part)
		const char*	tag_val_start = p;
		while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
			++p;
		}
		if (*p != '\0') {
			return false;
		}
		tag_val.assign(tag_val_start, p);
	} else {
		// standard BATV format

		// eat the tag-type
		const char*	tag_type_start = p;
		while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
			++p;
		}
		if (*p != '=') {
			return false;
		}
		tag_type.assign(tag_type_start, p);
		++p;

		// eat the tag-val
		const char*	tag_val_start = p;
		while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
			++p;
		}
		if (*p != '=') {
			return false;
		}
		tag_val.assign(tag_val_start, p);
		++p;

		// eat the loc-core (rest of local part)
		orig_mailfrom.local_part = p;
	}

	orig_mailfrom.domain = address.domain;
	return true;
}

std::string	Batv_address::make_string (char sub_address_delimiter) const
{
	std::string		address_str;

	if (sub_address_delimiter) {
		// non-standard format, using sub-addressing
		address_str.assign(orig_mailfrom.local_part);
		address_str.push_back(sub_address_delimiter);
		address_str.append(tag_type);
		address_str.push_back('=');
		address_str.append(tag_val);
		address_str.push_back('@');
		address_str.append(orig_mailfrom.domain);
	} else {
		// standard BATV format
		address_str.assign(tag_type);
		address_str.push_back('=');
		address_str.append(tag_val);
		address_str.push_back('=');
		address_str.append(orig_mailfrom.local_part);
		address_str.push_back('@');
		address_str.append(orig_mailfrom.domain);
	}
	
	return address_str;
}


std::string batv::canon_address (const char* addr)
{
	// Strip pairs of leading and trailing angle brackets from the address
	const char*	start = addr;
	const char*	end = addr + std::strlen(addr);
	while (*start == '<' && *(end - 1) == '>') {
		++start;
		--end;
	}
	return std::string(start, end);
}

void	Email_address::parse (const char* str)
{
	if (const char* at_sign_p = std::strchr(str, '@')) {
		local_part.assign(str, at_sign_p);
		domain.assign(at_sign_p + 1);
	} else {
		local_part = str;
		domain.clear();
	}
}

std::string	Email_address::make_string () const
{
	return domain.empty() ? local_part : local_part + "@" + domain;
}

