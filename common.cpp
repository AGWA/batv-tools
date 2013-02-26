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

#include "common.hpp"
#include <unistd.h>
#include <cstdlib>
#include <errno.h>
#include <string.h>

using namespace batv;

void batv::check_personal_key_path (std::string& path, const char* filename)
{
	if (path.empty()) {
		if (const char* home_dir = std::getenv("HOME")) {
			path = home_dir;
		}
		path.append("/").append(filename);
		if (access(path.c_str(), R_OK) == -1) {
			if (errno != ENOENT) {
				throw Config_error(path + ": " + strerror(errno));
			}
			path.clear();
		}
	} else if (access(path.c_str(), R_OK) == -1) {
		throw Config_error(path + ": " + strerror(errno));
	}
}
