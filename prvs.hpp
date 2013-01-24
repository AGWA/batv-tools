#pragma once

#include <vector>
#include <string>

namespace batv_milter {
	bool		prvs_validate (const std::string& val, const std::string& loc_core, const std::string& domain, unsigned int lifetime, const std::vector<unsigned char>& key);
	std::string	prvs_generate (const std::string& loc_core, const std::string& domain, unsigned int lifetime, const std::vector<unsigned char>& key);
}
