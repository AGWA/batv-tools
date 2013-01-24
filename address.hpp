#pragma once

#include <string>

namespace batv_milter {
	struct Batv_address {
		std::string	tag_type;
		std::string	tag_val;
		std::string	orig_mailfrom;	// includes both loc-core and domain

		bool		parse (const char*);
	};

	inline bool	is_batv_address (const char* addr) { return Batv_address().parse(addr); }
	std::string	canon_address (const char*);
}

