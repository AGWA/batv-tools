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

#include "prvs.hpp"
#include "key.hpp"
#include "common.hpp"
#include "address.hpp"
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string.h>

using namespace batv;

namespace {
	void print_usage (const char* argv0)
	{
		std::clog << "Usage: " << argv0 << " [OPTIONS...] FROM_ADDRESS" << std::endl;
		std::clog << "Options:" << std::endl;
		std::clog << " -k KEY_FILE        -- path to key file (default: ~/.batv-key)" << std::endl;
		std::clog << " -K KEY_MAP_FILE    -- path to key map file (default: ~/.batv-keys)" << std::endl;
		std::clog << " -l LIFETIME        -- lifetime, in days, of BATV address (default: 7)" << std::endl;
		std::clog << " -d SUB_ADDR_DELIM  -- sub address delimiter (default: +)" << std::endl;
	}
}

int main (int argc, char** argv)
try {
	char		sub_address_delimiter = '+';
	unsigned int	address_lifetime = 7;
	Key		key;
	std::string	key_file;
	Key_map		key_map;
	std::string	key_map_file;

	int		flag;
	while ((flag = getopt(argc, argv, "k:K:l:d:")) != -1) {
		switch (flag) {
		case 'k':
			key_file = optarg;
			break;
		case 'K':
			key_map_file = optarg;
			break;
		case 'l':
			address_lifetime = std::atoi(optarg);
			break;
		case 'd':
			if (std::strlen(optarg) != 1) {
				std::clog << argv[0] << ": sub address delimiter (as specified by -d) must be exactly one character" << std::endl;
				return 1;
			}
			sub_address_delimiter = optarg[0];
			break;
		default:
			print_usage(argv[0]);
			return 2;
		}
	}

	if (argc - optind != 1) {
		print_usage(argv[0]);
		return 2;
	}

	if (address_lifetime < 1 || address_lifetime > 999) {
		std::clog << argv[0] << ": address lifetime (as specified by -l) must be between 1 and 999, inclusive" << std::endl;
		return 1;
	}

	// Load the key
	check_personal_key_path(key_file, ".batv-key");
	check_personal_key_path(key_map_file, ".batv-keys");

	if (key_file.empty() && key_map_file.empty()) {
		std::clog << argv[0] << ": Neither ~/.batv-key nor ~/.batv-keys exist." << std::endl;
		std::clog << "Please create one and/or the other or specify alternative paths using -k or -K" << std::endl;
		return 1;
	}

	// Load the key and key map
	if (!key_file.empty()) {
		load_key(key, key_file);
	}
	if (!key_map_file.empty()) {
		std::ifstream	key_map_in(key_map_file.c_str());
		load_key_map(key_map, key_map_in);
	}
	
	// Determine what key to use to sign this message
	const Key*		use_key = get_key(key_map, argv[optind], !key.empty() ? &key : NULL);
	if (!use_key) {
		std::clog << argv[0] << ": " << argv[optind] << ": No key available for this sender" << std::endl;
		return 1;
	}

	// Generate the BATV address
	Email_address		from_address;
	from_address.parse(argv[optind]);
	if (from_address.domain.empty()) {
		std::clog << argv[0] << ": " << argv[optind] << ": Address is missing domain name" << std::endl;
		return 1;
	}

	std::cout << prvs_generate(from_address, address_lifetime, *use_key).make_string(sub_address_delimiter) << std::endl;
	return 0;

} catch (const Initialization_error& e) {
	std::clog << argv[0] << ": " << e.message << std::endl;
	return 1;
}

