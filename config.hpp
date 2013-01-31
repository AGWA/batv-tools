#pragma once

#include <utility>
#include <netinet/in.h>
#include <set>
#include <vector>
#include <string>
#include <iosfwd>

namespace batv_milter {
	struct Config {
		typedef std::pair<struct in6_addr, unsigned int> Ipv6_cidr;	// an IPv6 address and prefix length
		typedef std::vector<unsigned char> Key;

		enum Failure_mode {
			FAILURE_TEMPFAIL,
			FAILURE_ACCEPT,
			FAILURE_REJECT
		};

		bool			daemon;
		int			debug;
		std::string		pid_file;
		std::string		socket_spec;
		int			socket_mode;		// or -1 to use the umask
		bool			do_sign;
		bool			do_verify;
		std::vector<Ipv6_cidr>	internal_hosts;		// we generate BATV addresses only for mail from these hosts
		std::set<std::string>	batv_senders;		// we generate BATV addresses only for these senders/domains
		unsigned int		address_lifetime;	// in days, how long BATV address is valid
		Key			key;			// HMAC key for PRVS
		char			sub_address_delimiter;	// e.g. "+"
		Failure_mode		on_internal_error;	// what to do when an internal error happens

		bool			is_batv_sender (const std::string& address) const;
		bool			is_internal_host (const struct in6_addr&) const;
		bool			is_internal_host (const struct in_addr&) const;

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
			address_lifetime = 7;
			sub_address_delimiter = 0;
			on_internal_error = FAILURE_TEMPFAIL;
		}

		struct Error {
			std::string	message;

			explicit Error (const std::string& m) : message(m) { }
		};
	};

	// TODO: multiple key numbers (for key rollover), different key for each sender
}

