#include "address.hpp"
#include <cctype>
#include <cstring>

using namespace batv_milter;

bool Batv_address::parse (const char* p)
{
	// eat the loc-core (up to '+')
	const char*	loc_core_start = p;
	while (*p != '+' && *p != '@' && *p != '\0') {
		++p;
	}
	if (*p != '+') {
		return false;
	}
	loc_core.assign(loc_core_start, p);
	++p;

	// eat the tag-type (up to '=')
	const char*	tag_type_start = p;
	while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
		++p;
	}
	if (*p != '=') {
		return false;
	}
	tag_type.assign(tag_type_start, p);
	++p;

	// eat the tag-val (up to '@')
	const char*	tag_val_start = p;
	while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
		++p;
	}
	if (*p != '@') {
		return false;
	}
	tag_val.assign(tag_val_start, p);
	++p;

	// eat the domain
	domain = p;

	return true;
}


std::string batv_milter::canon_address (const char* addr)
{
	// Strip pairs of leading and trailing angle brackets from the address
	const char*	start = addr;
	const char*	end = addr + std::strlen(addr);
	while (*start == '<' && *(end - 1) == '>') {
		++start;
		--end;
	}
	return std::string(start, end);
}

Email_address	batv_milter::split_address (const char* str)
{
	Email_address	addr;
	if (const char* at_sign_p = std::strchr(str, '@')) {
		addr.local_part.assign(str, at_sign_p);
		addr.domain.assign(at_sign_p + 1);
	} else {
		addr.local_part = str;
	}
	return addr;
}

