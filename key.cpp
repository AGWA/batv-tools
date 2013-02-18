#include "key.hpp"
#include "common.hpp"
#include <fstream>
#include <limits>

using namespace batv;

void	batv::load_key (Key& key, std::istream& key_file_in)
{
	key.clear();
	while (key_file_in.good() && key_file_in.peek() != -1) {
		char	ch;
		key_file_in.get(ch);
		key.push_back(ch);
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

		// Load the keyfile 
		std::ifstream		key_file_in(key_file_path.c_str());
		if (!key_file_in) {
			throw Config_error("Unable to open key file " + key_file_path);
		}
		load_key(key_map[address], key_file_in);
	}
}

const Key* batv::get_key (const Key_map& keys, const std::string& sender_address)
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

