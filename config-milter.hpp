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
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#pragma once

#include "key.hpp"
#include "config.hpp"
#include <utility>
#include <netinet/in.h>
#include <map>
#include <vector>
#include <string>
#include <iosfwd>

namespace batv {
	struct Config : Common_config { // TODO: rename this class to Milter_config as it's specific to the milter
		typedef std::pair<struct in6_addr, unsigned int> Ipv6_cidr;	// an IPv6 address and prefix length

		enum Failure_mode {
			FAILURE_TEMPFAIL,
			FAILURE_ACCEPT,
			FAILURE_REJECT
		};

		bool			daemon;
		int			debug;
		std::string		pid_file;
		std::string		user_name;
		std::string		group_name;
		std::string		socket_spec;
		int			socket_mode;		// or -1 to use the umask
		bool			do_sign;
		bool			do_verify;
		std::vector<Ipv6_cidr>	internal_hosts;		// we generate BATV addresses only for mail from these hosts
		Failure_mode		on_internal_error;	// what to do when an internal error happens

		bool			is_internal_host (const struct in6_addr&) const;	// Is given IPv6 address internal?
		bool			is_internal_host (const struct in_addr&) const;		// Is given IPv4 addres internal?

		void			set (const std::string& directive, const std::string& value);
		void			load (std::istream&);
		void			validate () const;

		Config ()
		{
			daemon = false;
			debug = 0;
			socket_mode = -1;
			do_sign = true;
			do_verify = true;
			on_internal_error = FAILURE_TEMPFAIL;
		}

	};
}

