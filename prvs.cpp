#include "prvs.hpp"
#include <vector>
#include <algorithm>
#include <stdint.h>
#include <cstdio>
#include <stdio.h>
#include <cstdlib>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

using namespace batv_milter;

static unsigned int today ()
{
	return (std::time(NULL) / 86400) % 1000;
}

bool	batv_milter::prvs_validate (const std::string& val, const std::string& orig_mailfrom, unsigned int lifetime, const std::vector<unsigned char>& key)
{
	if (val.size() != 10) {
		return false;
	}

	// tag-val        =  K DDD SSSSSS

	unsigned int			key_num;
	unsigned int			expiration_day;
	unsigned int			claimed_hmac[3];

	std::sscanf(val.c_str(), "%1u%3u%2x%2x%2x", &key_num, &expiration_day, &claimed_hmac[0], &claimed_hmac[1], &claimed_hmac[2]);

	// check the key-num
	if (key_num != 0) {
		return false;
	}

	// check the expiration
	if (static_cast<unsigned int>((static_cast<int>(expiration_day) - static_cast<int>(today())) + 1000) % 1000 > lifetime) {
		return false;
	}

	// validate the HMAC
	// hash-source = K DDD <orig-mailfrom>
	std::vector<unsigned char>	hash_source(4 + orig_mailfrom.size());
	std::copy(val.begin(), val.begin() + 4, hash_source.begin());
	std::copy(orig_mailfrom.begin(), orig_mailfrom.end(), hash_source.begin() + 4);

	unsigned char			correct_hmac[20];
	HMAC(EVP_sha1(),
			&key[0], key.size(),
			&hash_source[0], hash_source.size(),
			correct_hmac, NULL);

	return ((claimed_hmac[0] ^ correct_hmac[0]) |
		(claimed_hmac[1] ^ correct_hmac[1]) |
		(claimed_hmac[2] ^ correct_hmac[2])) == 0;
}

std::string	batv_milter::prvs_generate (const std::string& orig_mailfrom, unsigned int lifetime, const std::vector<unsigned char>& key)
{
	// tag-val        =  K DDD SSSSSS
	char				val[11];
	
	// key-num
	val[0] = '0';

	// expiration
	snprintf(val + 1, 4, "%03u", (today() + lifetime) % 1000);

	// HMAC
	// hash-source = K DDD <orig-mailfrom>
	std::vector<unsigned char>	hash_source(4 + orig_mailfrom.size());
	std::copy(val, val + 4, hash_source.begin());
	std::copy(orig_mailfrom.begin(), orig_mailfrom.end(), hash_source.begin() + 4);

	unsigned char			hmac[20];
	HMAC(EVP_sha1(),
			&key[0], key.size(),
			&hash_source[0], hash_source.size(),
			hmac, NULL);

	snprintf(val + 4, 7, "%02x%02x%02x", static_cast<unsigned int>(hmac[0]),
						static_cast<unsigned int>(hmac[1]),
						static_cast<unsigned int>(hmac[2]));

	std::string			address("prvs=");
	address.append(val, val + 10).append("=").append(orig_mailfrom);
	return address;
}

