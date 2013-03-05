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

#pragma once

#include <map>
#include <vector>
#include <string>
#include <iosfwd>

namespace batv {
	typedef std::vector<unsigned char> Key;
	typedef std::map<std::string, Key> Key_map;

	void		load_key (Key& key, std::istream& key_file_in);
	void		load_key_map (Key_map& key_map, std::istream& key_map_file_in);

	// Get HMAC key for given sender from the key map:
	//  returns default_key (which is NULL by default) if sender is not in map.
	//  returns NULL if sender is in map with an empty key
	const Key*	get_key (const Key_map&, const std::string& sender_address, const Key* default_key =NULL);
}

