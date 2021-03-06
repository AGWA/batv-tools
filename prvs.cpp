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

#include "prvs.hpp"
#include <vector>
#include <algorithm>
#include <stdint.h>
#include <cstdio>
#include <stdio.h>
#include <cstdlib>
#include <ctime>
#include "hmac.hpp"
#include "sha1.hpp"

using namespace batv;

static unsigned int today ()
{
	return (std::time(NULL) / 86400) % 1000;
}

static void make_prvs_hash (unsigned char* hash_out, const char* tag_val, const Email_address& orig_mailfrom, const std::vector<unsigned char>& key)
{
	// hash-source = K DDD <orig-mailfrom>
	crypto::Hmac<crypto::Sha1>	hmac(key.data(), key.size());
	hmac.update(tag_val, 4);
	hmac.update(orig_mailfrom.local_part.data(), orig_mailfrom.local_part.size());
	hmac.update("@", 1);
	hmac.update(orig_mailfrom.domain.data(), orig_mailfrom.domain.size());
	hmac.finish(hash_out);
}

bool	batv::prvs_validate (const Batv_address& address, unsigned int lifetime, const std::vector<unsigned char>& key)
{
	if (address.tag_val.size() != 10) {
		return false;
	}

	// tag-val        =  K DDD SSSSSS

	unsigned int			key_num;
	unsigned int			expiration_day;
	unsigned int			claimed_hmac[3];

	std::sscanf(address.tag_val.c_str(), "%1u%3u%2x%2x%2x", &key_num, &expiration_day, &claimed_hmac[0], &claimed_hmac[1], &claimed_hmac[2]);

	// check the key-num
	if (key_num != 0) {
		return false;
	}

	// check the expiration
	if (static_cast<unsigned int>((static_cast<int>(expiration_day) - static_cast<int>(today())) + 1000) % 1000 > lifetime) {
		return false;
	}

	// validate the HMAC
	unsigned char			correct_hmac[20];
	make_prvs_hash(correct_hmac, &address.tag_val[0], address.orig_mailfrom, key);

	return ((claimed_hmac[0] ^ correct_hmac[0]) |
		(claimed_hmac[1] ^ correct_hmac[1]) |
		(claimed_hmac[2] ^ correct_hmac[2])) == 0;
}

Batv_address	batv::prvs_generate (const Email_address& orig_mailfrom, unsigned int lifetime, const std::vector<unsigned char>& key)
{
	// tag-val        =  K DDD SSSSSS
	char				val[11];
	
	// key-num
	val[0] = '0';

	// expiration
	snprintf(val + 1, 4, "%03u", (today() + lifetime) % 1000);

	// HMAC
	unsigned char			hmac[20];
	make_prvs_hash(hmac, val, orig_mailfrom, key);

	snprintf(val + 4, 7, "%02x%02x%02x", static_cast<unsigned int>(hmac[0]),
						static_cast<unsigned int>(hmac[1]),
						static_cast<unsigned int>(hmac[2]));

	Batv_address	address;
	address.tag_type = "prvs";
	address.tag_val.assign(val, val + 10);
	address.orig_mailfrom = orig_mailfrom;
	return address;
}

