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

#include "key.hpp"
#include "common.hpp"
#include "util.hpp"
#include <fstream>
#include <limits>

using namespace batv;

void	batv::load_key (Key& key, const std::string& key_file_path)
{
	std::ifstream		key_file_in(key_file_path.c_str());
	if (!key_file_in) {
		throw Config_error("Unable to open key file " + key_file_path);
	}

	key.clear();
	while (key_file_in.good() && key_file_in.peek() != -1) {
		char	ch;
		key_file_in.get(ch);
		key.push_back(ch);
	}
	if (key.empty()) {
		throw Config_error("Key file " + key_file_path + " is empty");
	}
}

void	batv::load_key_map (Key_map& key_map, std::istream& in)
{
	while (in.good() && in.peek() != -1) {
		// Skip comments (lines starting with #) and blank lines
		if (in.peek() == '#' || in.peek() == '\n') {
			in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			continue;
		}

		// read address/domain
		std::string		address;
		in >> address;

		// skip whitespace
		in >> std::ws;

		// read key file path
		std::string		key_file_path;
		std::getline(in, key_file_path);
		chomp(key_file_path);

		// Load the keyfile 
		load_key(key_map[address], key_file_path);
	}
}

const Key* batv::get_key (const Key_map& keys, const std::string& sender_address, const Key* default_key)
{
	Key_map::const_iterator		it;

	// Look up the address itself
	it = keys.find(sender_address);
	if (it != keys.end()) {
		return !it->second.empty() ? &it->second : NULL;
	}

	// Try looking up only the domain
	std::string::size_type	at_sign_pos = sender_address.find('@');
	if (at_sign_pos != std::string::npos) {
		it = keys.find(sender_address.substr(at_sign_pos));
		if (it != keys.end()) {
			return !it->second.empty() ? &it->second : NULL;
		}
	}

	return default_key;
}

