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
#include <vector>
#include <utility>
#include <set>
#include <string>
#include <string.h>

using namespace batv;

namespace {
	struct Filter_config {
		Key_map			keys;			// map from sender address/domain to their HMAC key
		unsigned int		address_lifetime;	// in days, how long BATV address is valid
		char			sub_address_delimiter;	// e.g. "+"
		std::string		rcpt_header;		// e.g. "Delivered-To"
		bool			is_mbox;		// input is in mbox format i.e. starts with "From " line

		Filter_config ()
		{
			address_lifetime = 7;
			sub_address_delimiter = '+';
			rcpt_header = "Delivered-To";
			is_mbox = true;
		}
	};

	struct Input_error {
		std::string		message;
		explicit Input_error (const std::string& m) : message(m) { }
	};

	bool read_header (std::istream& in, std::string& name, std::string& value)
	{
		if (in.peek() == -1) {
			throw Input_error("Premature end of message headers");
		}
		if (in.peek() == '\n') {
			return false;
		}

		// Read first line of header
		std::string		line;
		std::getline(in, line);
		if (line[0] == ' ' || line[0] == '\t') {
			throw Input_error("Malformed message headers: unexpected continuation header");
		}

		// Parse first line of header
		std::string::size_type	colon_pos = line.find(':');
		if (colon_pos == std::string::npos) {
			throw Input_error("No colon in message header line");
		}
		name = line.substr(0, colon_pos);
		value = line.substr(colon_pos + 1);

		// Read in continuation lines, if any
		while (in.peek() == ' ' || in.peek() == '\t') {
			std::string	line;
			std::getline(in, line);
			value.append("\n").append(line);
		}

		return true;
	}

	const char* after_ws (const char* p)
	{
		while (*p == ' ') ++p;
		return p;
	}

	void filter (const Filter_config& config, std::istream& in, std::ostream& out)
	{
		if (config.is_mbox) {
			// Pass through the "From " line
			std::string	from_line;
			std::getline(in, from_line);
			if (std::strncmp(from_line.c_str(), "From ", 5) != 0) {
				throw Input_error("Message does not start with mbox From line.  Use -r option if input is not in mbox format.");
			}
			out << from_line << '\n';
		}

		// Process headers
		std::string	name;
		std::string	value;
		bool		done = false;
		while (read_header(in, name, value)) {
			if (strcasecmp(name.c_str(), "X-Batv-Status") == 0) {
				// Remove this header to prevent malicious senders from faking us out

			} else if (!done && strcasecmp(name.c_str(), config.rcpt_header.c_str()) == 0) {
				Email_address		rcpt_to;
				rcpt_to.parse(canon_address(after_ws(value.c_str())).c_str());

				// Make sure that the BATV address is syntactically valid AND it's using a known tag type:
				Batv_address		batv_rcpt;
				if (batv_rcpt.parse(rcpt_to, config.sub_address_delimiter) && batv_rcpt.tag_type == "prvs") {
					// Get the key for this sender:
					const Key*	batv_rcpt_key = get_key(config.keys, batv_rcpt.orig_mailfrom.make_string());
					if (batv_rcpt_key != NULL) {
						// A non-NULL key means this is a BATV sender.

						// Restore original envelope recipient
						out << name << ": " << batv_rcpt.orig_mailfrom.make_string() << '\n';

						// But also leave the original BATV envelope recipient in a different header
						out << "X-Batv-Delivered-To:" << value << '\n';

						// Validate the address and put the status in the X-Batv-Status header
						if (prvs_validate(batv_rcpt, config.address_lifetime, *batv_rcpt_key)) {
							out << "X-Batv-Status: valid\n";
						} else {
							out << "X-Batv-Status: invalid\n";
						}

						// Set a flag so we don't do this again.
						done = true;
					}
				}
				if (!done) {
					// Copy through the header unmodified
					out << name << ':' << value << '\n';
				}

			} else {
				// Copy through this header unmodified
				out << name << ':' << value << '\n';
			}
		}

		// Copy through the message body
		out << in.rdbuf();
	}
}

int main (int argc, char** argv)
{
	Filter_config	config;
	std::string	key_map_file;

	int		flag;
	while ((flag = getopt(argc, argv, "k:l:d:h:r")) != -1) {
		switch (flag) {
		case 'k':
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
		case 'r':
			config.is_mbox = false;
			break;
		default:
			std::clog << "Usage: " << argv[0] << " [OPTIONS...]" << std::endl;
			std::clog << "Options:" << std::endl;
			std::clog << " -k KEY_MAP_FILE    -- path to key map file (default: ~/.batv-keys)" << std::endl;
			std::clog << " -l LIFETIME        -- lifetime, in days, of BATV addresses (default: 7)" << std::endl;
			std::clog << " -d SUB_ADDR_DELIM  -- sub address delimiter (default: +)" << std::endl;
			std::clog << " -h RCPT_HEADER     -- envelope recipient header (default: Delivered-To)" << std::endl;
			std::clog << " -r                 -- input is a raw (non-mbox) message (default: no)" << std::endl;
			return 2;
		}
	}

	if (config.address_lifetime < 1 || config.address_lifetime > 999) {
		std::clog << argv[0] << ": address lifetime (as specified by -l) must be between 1 and 999, inclusive" << std::endl;
		return 1;
	}

	if (key_map_file.empty()) {
		if (const char* home_dir = std::getenv("HOME")) {
			key_map_file = home_dir;
		}
		key_map_file += "/.batv-keys";
	}
	if (access(key_map_file.c_str(), R_OK) == -1) {
		std::clog << argv[0] << ": " << key_map_file << ": " << strerror(errno) << std::endl;
		return 1;
	}

	try {
		std::ifstream	key_map_in(key_map_file.c_str());
		load_key_map(config.keys, key_map_in);
	} catch (const Config_error& e) {
		std::clog << argv[0] << ": " << e.message << std::endl;
		return 1;
	}

	try {
		filter(config, std::cin, std::cout);
	} catch (const Input_error& e) {
		std::clog << argv[0] << ": " << e.message << std::endl;
		return 1;
	}

	return 0;
}

