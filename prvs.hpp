/*
 * Copyright 2013 Andrew Ayer
 *
 * This file is part of batv-tools.
 *
 * batv-tools is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * batv-tools is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with batv-tools.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "address.hpp"
#include <vector>
#include <string>

namespace batv {
	bool		prvs_validate (const Batv_address&, unsigned int lifetime, const std::vector<unsigned char>& key);
	Batv_address	prvs_generate (const Email_address& orig_mailfrom, unsigned int lifetime, const std::vector<unsigned char>& key);
}
