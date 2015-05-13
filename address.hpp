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
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#ifndef BATV_ADDRESS_HPP
#define BATV_ADDRESS_HPP

#include <string>

namespace batv {
	struct Email_address {
		std::string	local_part;
		std::string	domain;

		void		parse (const char*);
		std::string	make_string () const;
		void		clear () { local_part.clear(); domain.clear (); }
	};

	struct Batv_address {
		std::string	tag_type;
		std::string	tag_val;
		Email_address	orig_mailfrom;

		bool		parse (const Email_address&, char sub_address_delimiter);
		std::string	make_string (char sub_address_delimiter) const;
	};

	inline bool	is_batv_address (const Email_address& addr, char delim) { return Batv_address().parse(addr, delim); }
	std::string	canon_address (const char*);
}

#endif
