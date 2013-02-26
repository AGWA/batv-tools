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
		std::clog << " -l LIFETIME        -- lifetime, in days, of BATV address (default: 7)" << std::endl;
		std::clog << " -d SUB_ADDR_DELIM  -- sub address delimiter (default: +)" << std::endl;
	}
}

int main (int argc, char** argv)
{
	char		sub_address_delimiter = '+';
	unsigned int	address_lifetime = 7;
	Key		key;
	std::string	key_file;

	int		flag;
	while ((flag = getopt(argc, argv, "k:l:d:")) != -1) {
		switch (flag) {
		case 'k':
			key_file = optarg;
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
	if (key_file.empty()) {
		if (const char* home_dir = std::getenv("HOME")) {
			key_file = home_dir;
		}
		key_file += "/.batv-key";
	}
	if (access(key_file.c_str(), R_OK) == -1) {
		std::clog << argv[0] << ": " << key_file << ": " << strerror(errno) << std::endl;
		return 1;
	}

	try {
		std::ifstream	key_in(key_file.c_str());
		load_key(key, key_in);
	} catch (const Config_error& e) {
		std::clog << argv[0] << ": " << e.message << std::endl;
		return 1;
	}

	// Generate the BATV address
	Email_address		from_address;
	from_address.parse(argv[optind]);
	if (from_address.domain.empty()) {
		std::clog << argv[0] << ": " << argv[optind] << ": Address is missing domain name" << std::endl;
		return 1;
	}

	std::cout << prvs_generate(from_address, address_lifetime, key).make_string(sub_address_delimiter) << std::endl;
	return 0;
}

