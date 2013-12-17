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

#include "verify.hpp"
#include "prvs.hpp"
#include "address.hpp"
#include "key.hpp"
#include "config.hpp"

using namespace batv;

Verify_result batv::verify (const Email_address& env_rcpt, std::string* true_rcpt, const Common_config& config)
{
	bool		has_batv_rcpt;
	Batv_address	batv_rcpt;
	const Key*	rcpt_key;

	if (batv_rcpt.parse(env_rcpt, config.sub_address_delimiter) && batv_rcpt.tag_type == "prvs") {
		has_batv_rcpt = true;
		*true_rcpt = batv_rcpt.orig_mailfrom.make_string();
	} else {
		has_batv_rcpt = false;
		*true_rcpt = env_rcpt.make_string();
	}

	rcpt_key = config.get_key(*true_rcpt);

	if (!rcpt_key) {
		// The recipient of this message is not a BATV user b/c he doesn't have a key
		return VERIFY_NONE;
	}

	if (!has_batv_rcpt) {
		// This message was not signed with BATV...
		return VERIFY_MISSING;
	}

	if (!prvs_validate(batv_rcpt, config.address_lifetime, *rcpt_key)) {
		// Message has invalid BATV signature...
		return VERIFY_BAD_SIGNATURE;
	}

	return VERIFY_SUCCESS;
}

