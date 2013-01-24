#pragma once

#include <string>

namespace batv_milter {
	struct Email_address {
		std::string	local_part;
		std::string	domain;
	};

	struct Batv_address {
		std::string	tag_type;
		std::string	tag_val;
		std::string	loc_core;
		std::string	domain;

		bool		parse (const char*);
	};

	inline bool	is_batv_address (const char* addr) { return Batv_address().parse(addr); }
	std::string	canon_address (const char*);
	Email_address	split_address (const char*);
}

