#pragma once

#include "address.hpp"
#include <vector>
#include <string>

namespace batv_milter {
	bool		prvs_validate (const Batv_address&, unsigned int lifetime, const std::vector<unsigned char>& key);
	Batv_address	prvs_generate (const Email_address& orig_mailfrom, unsigned int lifetime, const std::vector<unsigned char>& key);
}
