#include "address.hpp"
#include <cctype>
#include <cstring>

using namespace batv_milter;

bool Batv_address::parse (const char* p)
{
	// eat the tag-type
	const char*	tag_type_start = p;
	while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
		++p;
	}
	if (*p != '=') {
		return false;
	}
	tag_type.assign(tag_type_start, p);
	++p;

	// eat the tag-val
	const char*	tag_val_start = p;
	while (std::isdigit(*p) || std::isalpha(*p) || *p == '-') {
		++p;
	}
	if (*p != '=') {
		return false;
	}
	tag_val.assign(tag_val_start, p);
	++p;

	// eat the orig-mailfrom
	orig_mailfrom = p;

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
