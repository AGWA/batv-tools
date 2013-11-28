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

#include "config.hpp"
#include "common.hpp"
#include <arpa/inet.h>
#include <stdint.h>
#include <cstring>
#include <cstdlib>
#include <istream>
#include <fstream>
#include <limits>

using namespace batv;

namespace {
	struct in6_addr		make_ipv4_mapped_address (const struct in_addr& ipv4_addr)
	{
		// Make an IPv4-mapped IPv6 address
		struct in6_addr	ipv6_addr;
		std::memset(ipv6_addr.s6_addr, '\0', 10);
		ipv6_addr.s6_addr[10] = 0xFF;
		ipv6_addr.s6_addr[11] = 0xFF;
		std::memcpy(ipv6_addr.s6_addr + 12, &ipv4_addr.s_addr, 4);
		return ipv6_addr;
	}

	Config::Ipv6_cidr	parse_cidr_string (const char* str)
	{
		struct in6_addr		address;
		int			prefix_len = -1;
		std::string		address_str;
		if (const char* slash = std::strchr(str, '/')) {
			address_str.assign(str, slash);
			prefix_len = std::atoi(slash + 1);
		} else {
			address_str = str;
		}

		if (address_str.find(':') != std::string::npos) {
			// IPv6 address
			if (inet_pton(AF_INET6, address_str.c_str(), &address) != 1) {
				throw Config_error("Invalid IPv6 address: " + address_str);
			}

			if (prefix_len == -1) {
				prefix_len = 128;
			}
		} else {
			// IPv4 address
			struct in_addr	ipv4_address;
			if (inet_pton(AF_INET, address_str.c_str(), &ipv4_address) != 1) {
				throw Config_error("Invalid IPv4 address: " + address_str);
			}

			address = make_ipv4_mapped_address(ipv4_address);

			if (prefix_len == -1) {
				prefix_len = 128;
			} else {
				prefix_len = 96 + prefix_len;
			}
		}

		if (prefix_len < 0 || prefix_len > 128) {
			throw Config_error("Invalid prefix length in CIDR string: " + std::string(str));
		}

		return Config::Ipv6_cidr(address, prefix_len);
	}
}


const Key* Config::get_key (const std::string& sender_address) const
{
	return batv::get_key(keys, sender_address);
}

bool Config::is_internal_host (const struct in_addr& addr) const
{
	return is_internal_host(make_ipv4_mapped_address(addr));
}

bool Config::is_internal_host (const struct in6_addr& addr) const
{
	std::vector<Ipv6_cidr>::const_iterator it(internal_hosts.begin());
	while (it != internal_hosts.end()) {
		unsigned int	prefix_bytes = it->second / 8;
		uint8_t		last_byte_mask = 255 << (8 - it->second % 8);

		if (std::memcmp(addr.s6_addr, it->first.s6_addr, prefix_bytes) == 0 &&
			(prefix_bytes >= 16 ||
			 ((addr.s6_addr[prefix_bytes] ^ it->first.s6_addr[prefix_bytes]) & last_byte_mask) == 0)) {
			return true;
		}

		++it;
	}
	return false;
}

void	Config::set (const std::string& directive, const std::string& value)
{
	if (directive == "daemon") {
		if (value == "yes" || value == "true" || value == "on" || value == "1") {
			daemon = true;
		} else if (value == "no" || value == "false" || value == "off" || value == "0") {
			daemon = false;
		} else {
			throw Config_error("Invalid boolean value " + value);
		}
	} else if (directive == "debug") {
		debug = std::atoi(value.c_str());
	} else if (directive == "pid-file") {
		pid_file = value;
	} else if (directive == "user") {
		user_name = value;
	} else if (directive == "group") {
		group_name = value;
	} else if (directive == "config") {
		// Include another config file
		std::ifstream	config_in(value.c_str());
		if (!config_in) {
			throw Config_error("Unable to open config file " + value);
		}
		load(config_in);
	} else if (directive == "socket") {
		socket_spec = value;
	} else if (directive == "socket-mode") {
		if (value.size() != 3 ||
				value[0] < '0' || value[0] > '7' ||
				value[1] < '0' || value[1] > '7' ||
				value[2] < '0' || value[2] > '7') {
			throw Config_error("Invalid socket mode (not a 3 digit octal number): " + value);
		}
		socket_mode = ((value[0] - '0') << 6) | ((value[1] - '0') << 3) | (value[2] - '0');
	} else if (directive == "mode") {
		if (value == "sign") {
			do_sign = true;
			do_verify = false;
		} else if (value == "verify") {
			do_verify = true;
			do_sign = false;
		} else if (value == "both") {
			do_verify = true;
			do_sign = true;
		} else {
			throw Config_error("Invalid mode " + value);
		}
	} else if (directive == "lifetime") {
		address_lifetime = std::atoi(value.c_str());
		if (address_lifetime < 1 || address_lifetime > 999) {
			throw Config_error("Invalid address lifetime " + value + " (must be between 1 and 999, inclusive)");
		}
	} else if (directive == "internal-host") {
		internal_hosts.push_back(parse_cidr_string(value.c_str()));
	} else if (directive == "sub-address-delimiter") {
		if (value.size() != 1) {
			throw Config_error("Sub address delimiter must be exactly one character");
		}
		sub_address_delimiter = value[0];
	} else if (directive == "key-map") {
		std::ifstream	key_map_in(value.c_str());
		if (!key_map_in) {
			throw Config_error("Unable to open key map " + value);
		}
		load_key_map(keys, key_map_in);
	} else if (directive == "on-internal-error") {
		if (value == "tempfail") {
			on_internal_error = FAILURE_TEMPFAIL;
		} else if (value == "accept") {
			on_internal_error = FAILURE_ACCEPT;
		} else if (value == "reject") {
			on_internal_error = FAILURE_REJECT;
		} else {
			throw Config_error("Invalid value for 'on-internal-error' directive (should be 'tempfail', 'accept', or 'reject'): " + value);
		}
	} else if (directive == "reject-unless-verified") {
		if (value == "yes" || value == "true" || value == "on" || value == "1") {
			reject_unless_verified = true;
		} else if (value == "no" || value == "false" || value == "off" || value == "0") {
			reject_unless_verified = false;
		} else {
			throw Config_error("Invalid value for 'reject-unless-verified' directive (should be 'true' or 'false')");
		}
	} else {
		throw Config_error("Invalid config directive " + directive);
	}
}

void	Config::load (std::istream& in)
{
	while (in.good() && in.peek() != -1) {
		// Skip comments (lines starting with #) and blank lines
		if (in.peek() == '#' || in.peek() == '\n') {
			in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			continue;
		}

		// read directive name
		std::string		directive;
		in >> directive;

		// skip whitespace
		in >> std::ws;

		// read directive value
		std::string		value;
		std::getline(in, value);

		set(directive, value);
	}
}

void	Config::validate () const
{
	if (socket_spec.empty()) {
		throw Config_error("Milter socket not specified");
	}
}

