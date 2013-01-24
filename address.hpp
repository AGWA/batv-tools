#pragma once 
#include <string>

namespace batv_milter {
	struct Email_address {
		std::string	local_part;
		std::string	domain;

		void		parse (const char*);
		std::string	make_string () const;
		void		clear () { local_part.clear(); domain.clear (); }
	};

	struct Batv_address {
		std::string	tag_type;
		std::string	tag_val;
		Email_address	orig_mailfrom;

		bool		parse (const Email_address&, char sub_address_delimiter);
		std::string	make_string (char sub_address_delimiter) const;
	};

	inline bool	is_batv_address (const Email_address& addr, char delim) { return Batv_address().parse(addr, delim); }
	std::string	canon_address (const char*);
}

