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

	// Get HMAC key for given sender from the key map (return NULL if not in key map):
	const Key*	get_key (const Key_map&, const std::string& sender_address);
}

