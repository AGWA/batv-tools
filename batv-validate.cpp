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
#include "config.hpp"
#include "verify.hpp"
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <utility>
#include <limits>
#include <sstream>
#include <set>
#include <string>
#include <string.h>

using namespace batv;

namespace {
	void print_usage (const char* argv0)
	{
		std::clog << "Usage:" << std::endl;
		std::clog << " " << argv0 << " [OPTIONS...] BATV-ADDRESS" << std::endl;
		std::clog << " " << argv0 << " -m [OPTIONS...]" << std::endl;
		std::clog << " " << argv0 << " -f [OPTIONS...]" << std::endl;
		std::clog << "Options:" << std::endl;
		std::clog << " -m                 -- read message from stdin, validate the recipient address" << std::endl;
		std::clog << " -f                 -- filter message on stdin, add X-Batv-Status header" << std::endl;
		std::clog << " -k KEY_FILE        -- path to key file (default: ~/.batv-key)" << std::endl;
		std::clog << " -K KEY_MAP_FILE    -- path to key map file (default: ~/.batv-keys)" << std::endl;
		std::clog << " -l LIFETIME        -- lifetime, in days, of BATV addresses (default: 7)" << std::endl;
		std::clog << " -d SUB_ADDR_DELIM  -- sub address delimiter (default: +)" << std::endl;
		std::clog << " -h RCPT_HEADER     -- envelope recipient header (for -f and -m mode)" << std::endl;
		std::clog << "                       (default: Delivered-To)" << std::endl;
	}

	struct Validate_config : Common_config {
		std::string		rcpt_header;		// e.g. "Delivered-To"

		Validate_config ()
		{
			sub_address_delimiter = '+';
			rcpt_header = "Delivered-To";
		}
	};

	struct Input_error {
		std::string		message;
		explicit Input_error (const std::string& m) : message(m) { }
	};

	void parse_header (const std::string& first_line, std::istream& in, std::string& name, std::string& value)
	{
		if (first_line[0] == ' ' || first_line[0] == '\t') {
			throw Input_error("Malformed message headers: unexpected continuation header");
		}

		// Parse first line of header
		std::string::size_type	colon_pos = first_line.find(':');
		if (colon_pos == std::string::npos) {
			throw Input_error("No colon in message header line");
		}
		name = first_line.substr(0, colon_pos);
		value = first_line.substr(colon_pos + 1);

		// Read in continuation lines, if any
		while (in.peek() == ' ' || in.peek() == '\t') {
			std::string	line;
			std::getline(in, line);
			value.append("\n").append(line);
		}
	}

	const char* after_ws (const char* p)
	{
		while (*p == ' ') ++p;
		return p;
	}

	// Read and parse the message, returning all the Delivered-To (or equivalent) headers.
	std::vector<Email_address> parse_mail (const Validate_config& config, std::istream& in)
	{
		std::vector<Email_address>	rcpt_tos;
		bool				first = true;	// becomes false after the first line of input
		while (in.peek() != -1 && in.peek() != '\n') {
			// Read first line of header
			std::string		first_line;
			std::getline(in, first_line);

			if (first && std::strncmp(first_line.c_str(), "From ", 5) == 0) {
				// The input must be in mbox format.  Skip the "From " line.
				first = false;
				continue;
			}

			// Parse the header, possibly reading in continuation lines
			std::string	name;
			std::string	value;
			parse_header(first_line, in, name, value);

			// Process the header
			if (strcasecmp(name.c_str(), config.rcpt_header.c_str()) == 0) {
				rcpt_tos.push_back(Email_address());
				rcpt_tos.back().parse(canon_address(after_ws(value.c_str())).c_str());
			}
			first = false;
		}

		// Ignore the rest of the input
		in.ignore(std::numeric_limits<std::streamsize>::max());

		return rcpt_tos;
	}

	void filter (const Validate_config& config, std::istream& in, std::ostream& out)
	{
		Verify_result	result = VERIFY_NONE;
		bool		first = true;	// becomes false after the first line of input
		while (in.peek() != -1 && in.peek() != '\n') {
			// Read first line of header
			std::string		first_line;
			std::getline(in, first_line);

			if (first && std::strncmp(first_line.c_str(), "From ", 5) == 0) {
				// The input must be in mbox format.  Pass through the "From " line.
				out << first_line << '\n';
				first = false;
				continue;
			}

			// Parse the header, possibly reading in continuation lines
			std::string	name;
			std::string	value;
			parse_header(first_line, in, name, value);

			// Process the header
			if (strcasecmp(name.c_str(), "X-Batv-Status") == 0) {
				// Remove this header to prevent malicious senders from faking us out

			} else if (result != VERIFY_SUCCESS && strcasecmp(name.c_str(), config.rcpt_header.c_str()) == 0) {
				Email_address		rcpt_to;
				rcpt_to.parse(canon_address(after_ws(value.c_str())).c_str());

				std::string		true_rcpt;
				Verify_result		this_result = verify(rcpt_to, &true_rcpt, config);

				if (this_result != VERIFY_NONE) {
					result = this_result;
				}

				if (this_result == VERIFY_SUCCESS) {
					// Restore original envelope recipient
					out << name << ": " << true_rcpt << '\n';

					out << "X-Batv-Status: valid\n";

					// Leave the original BATV envelope recipient in a different header
					out << "X-Batv-Delivered-To:" << value << '\n';

				} else {
					// Copy through the header unmodified
					out << name << ':' << value << '\n';
				}

			} else {
				// Copy through this header unmodified
				out << name << ':' << value << '\n';
			}

			first = false;
		}

		if (result == VERIFY_MISSING) {
			out << "X-Batv-Status: invalid, missing\n";
		} else if (result == VERIFY_BAD_SIGNATURE) {
			out << "X-Batv-Status: invalid, bad-signature\n";
		}

		// Copy through the message body
		out << in.rdbuf();
	}
}

int main (int argc, char** argv)
try {
	bool		is_filter = false;
	bool		is_mail_input = false;
	Validate_config	config;
	std::string	key_file;
	std::string	key_map_file;

	int		flag;
	while ((flag = getopt(argc, argv, "fmk:K:l:d:h:")) != -1) {
		switch (flag) {
		case 'f':
			is_filter = true;
			break;
		case 'm':
			is_mail_input = true;
			break;
		case 'k':
			key_file = optarg;
			break;
		case 'K':
			key_map_file = optarg;
			break;
		case 'l':
			config.address_lifetime = std::atoi(optarg);
			break;
		case 'd':
			if (std::strlen(optarg) != 1) {
				std::clog << argv[0] << ": sub address delimiter (as specified by -d) must be exactly one character" << std::endl;
				return 1;
			}
			config.sub_address_delimiter = optarg[0];
			break;
		case 'h':
			config.rcpt_header = optarg;
			break;
		default:
			print_usage(argv[0]);
			return 2;
		}
	}

	// Validate arguments
	if (is_filter && is_mail_input) {
		std::clog << argv[0] << ": can't specify both -f and -m" << std::endl;
		print_usage(argv[0]);
		return 2;
	}

	if (!is_filter && !is_mail_input && argc - optind != 1) {
		print_usage(argv[0]);
		return 2;
	} else if ((is_filter || is_mail_input) && argc - optind != 0) {
		print_usage(argv[0]);
		return 2;
	}

	if (config.address_lifetime < 1 || config.address_lifetime > 999) {
		std::clog << argv[0] << ": address lifetime (as specified by -l) must be between 1 and 999, inclusive" << std::endl;
		return 1;
	}

	// Load the default key and key map
	check_personal_key_path(key_file, ".batv-key");
	check_personal_key_path(key_map_file, ".batv-keys");

	if (key_file.empty() && key_map_file.empty()) {
		std::clog << argv[0] << ": Neither ~/.batv-key nor ~/.batv-keys exist." << std::endl;
		std::clog << "Please create one and/or the other or specify alternative paths using -k or -K" << std::endl;
		return 1;
	}

	if (!key_file.empty()) {
		load_key(config.default_key, key_file);
	}
	if (!key_map_file.empty()) {
		std::ifstream	key_map_in(key_map_file.c_str());
		load_key_map(config.keys, key_map_in);
	}

	// Do the validation/filtering
	if (is_filter) {
		std::ios_base::sync_with_stdio(false);
		std::cin.tie(NULL);
		filter(config, std::cin, std::cout);

	} else {
		std::vector<Email_address>	rcpt_tos;
		if (is_mail_input) {
			// Get the possible envelope recipients from the message on stdin
			std::ios_base::sync_with_stdio(false);
			std::cin.tie(NULL);
			rcpt_tos = parse_mail(config, std::cin);
			if (rcpt_tos.empty()) {
				// no envelope recipient header found
				std::clog << argv[0] << ": No envelope recipient header (" << config.rcpt_header << ") found in message (use -h to specify a different header)" << std::endl;
				return 13;
			}
		} else {
			// Get the one and only envelope recipient from the command line argument
			rcpt_tos.push_back(Email_address());
			rcpt_tos.back().parse(argv[optind]);
		}

		// The message may have multiple Delivered-To (or equivalent) headers if it passed
		// through several mail servers.  We check each one until one validates successfully.
		// Buffer errors in an ostringstream and only write it to stderr if all the addresses
		// fail to validate.  The exit code will reflect the status of the last address.
		std::ostringstream	errors;
		int			status = 0;
		for (size_t i = 0; i < rcpt_tos.size(); ++i) {
			std::string	true_rcpt;
			Verify_result	result = verify(rcpt_tos[i], &true_rcpt, config);
			if (result == VERIFY_NONE) {
				errors << argv[0] << ": " << true_rcpt << ": No key available for this sender" << std::endl;
				continue;
			} else if (result == VERIFY_MISSING) {
				errors << argv[0] << ": " << rcpt_tos[i].make_string() << ": Missing BATV signature" << std::endl;
				status = 11;
				continue;
			} else if (result == VERIFY_BAD_SIGNATURE) {
				errors << argv[0] << ": " << rcpt_tos[i].make_string() << ": Invalid signature" << std::endl;
				status = 10;
				continue;
			} else if (result == VERIFY_SUCCESS) {
				// Output original envelope recipient
				std::cout << true_rcpt << std::endl;
				status = 0;
				break;
			}
		}

		if (status != 0) {
			std::clog << errors.str();
			return status;
		}
	}

	return 0;

} catch (const Config_error& e) {
	std::clog << argv[0] << ": " << e.message << std::endl;
	return 1;
} catch (const Input_error& e) {
	std::clog << argv[0] << ": " << e.message << std::endl;
	return 1;
}

