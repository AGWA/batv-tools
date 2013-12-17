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

#include <string>

namespace batv {
	struct Common_config;
	struct Email_address;

	enum Verify_result {
		VERIFY_NONE,		// Message does not need to be validated
		VERIFY_SUCCESS,		// Message successfully validated
		VERIFY_MISSING,		// Message is missing BATV signature
		VERIFY_BAD_SIGNATURE,	// Message has bad BATV signature
		VERIFY_MULTIPLE_RCPT,	// Message has multiple recipients
		VERIFY_ERROR		// There was an error during verification
	};

	Verify_result verify (const Email_address& env_rcpt, std::string* true_rcpt, const Common_config&);
}
