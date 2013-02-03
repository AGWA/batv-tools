#include "config.hpp"
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
				throw Config::Error("Invalid IPv6 address: " + address_str);
			}

			if (prefix_len == -1) {
				prefix_len = 128;
			}
		} else {
			// IPv4 address
			struct in_addr	ipv4_address;
			if (inet_pton(AF_INET, address_str.c_str(), &ipv4_address) != 1) {
				throw Config::Error("Invalid IPv4 address: " + address_str);
			}

			address = make_ipv4_mapped_address(ipv4_address);

			if (prefix_len == -1) {
				prefix_len = 128;
			} else {
				prefix_len = 96 + prefix_len;
			}
		}

		if (prefix_len < 0 || prefix_len > 128) {
			throw Config::Error("Invalid prefix length in CIDR string: " + std::string(str));
		}

		return Config::Ipv6_cidr(address, prefix_len);
	}

	void	load_key (Config::Key& key, std::istream& key_file_in)
	{
		key.clear();
		while (key_file_in.good() && key_file_in.peek() != -1) {
			char	ch;
			key_file_in.get(ch);
			key.push_back(ch);
		}
	}

	void	load_key_map (Config::Key_map& key_map, std::istream& in)
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

			// Load the keyfile 
			std::ifstream		key_file_in(key_file_path.c_str());
			if (!key_file_in) {
				throw Config::Error("Unable to open key file " + key_file_path);
			}
			load_key(key_map[address], key_file_in);
		}
	}
}


const Config::Key* Config::get_key (const std::string& sender_address) const
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

	return NULL;
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
			throw Error("Invalid boolean value " + value);
		}
	} else if (directive == "debug") {
		debug = std::atoi(value.c_str());
	} else if (directive == "pid-file") {
		pid_file = value;
	} else if (directive == "config") {
		// Include another config file
		std::ifstream	config_in(value.c_str());
		if (!config_in) {
			throw Error("Unable to open config file " + value);
		}
		load(config_in);
	} else if (directive == "socket") {
		socket_spec = value;
	} else if (directive == "socket-mode") {
		if (value.size() != 3 ||
				value[0] < '0' || value[0] > '7' ||
				value[1] < '0' || value[1] > '7' ||
				value[2] < '0' || value[2] > '7') {
			throw Error("Invalid socket mode (not a 3 digit octal number): " + value);
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
			throw Error("Invalid mode " + value);
		}
	} else if (directive == "lifetime") {
		address_lifetime = std::atoi(value.c_str());
		if (address_lifetime < 1 || address_lifetime > 999) {
			throw Error("Invalid address lifetime " + value + " (must be between 1 and 999, inclusive)");
		}
	} else if (directive == "internal-host") {
		internal_hosts.push_back(parse_cidr_string(value.c_str()));
	} else if (directive == "sub-address-delimiter") {
		if (value.size() != 1) {
			throw Error("Sub address delimiter must be exactly one character");
		}
		sub_address_delimiter = value[0];
	} else if (directive == "key-map") {
		std::ifstream	key_map_in(value.c_str());
		if (!key_map_in) {
			throw Error("Unable to open key map " + value);
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
			throw Error("Invalid value for 'on-internal-error' directive (should be 'tempfail', 'accept', or 'reject'): " + value);
		}
	} else {
		throw Error("Invalid config directive " + directive);
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
		throw Error("Milter socket not specified");
	}
	if (keys.empty()) {
		throw Error("No keys specified");
	}
}

