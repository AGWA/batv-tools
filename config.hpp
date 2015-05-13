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

#ifndef BATV_CONFIG_HPP
#define BATV_CONFIG_HPP

#include "key.hpp"
#include <vector>
#include <string>

namespace batv {
	struct Common_config {
		Key_map			keys;			// map from sender address/domain to their HMAC key
		Key			default_key;		// key to use if address/domain not in key map
		unsigned int		address_lifetime;	// in days, how long BATV address is valid
		char			sub_address_delimiter;	// e.g. "+"

		Common_config ()
		{
			address_lifetime = 7;
			sub_address_delimiter = 0;
		}

		const Key*		get_key (const std::string& sender_address) const;	// Get HMAC key for the given sender
												// (NULL if sender doesn't use BATV)
	};
}

#endif
