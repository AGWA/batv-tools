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
#include "config-milter.hpp"
#include "address.hpp"
#include "verify.hpp"
#include "key.hpp"
#include "common.hpp"
#include <iostream>
#include <signal.h>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <algorithm>
#include <libmilter/mfapi.h>
#include <cstring>
#include <netinet/in.h>
#include <vector>
#include <utility>
#include <set>
#include <string>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace batv;

namespace {
	const Config*			config;

	struct Batv_context {
		// Connection state (applicable to entire SMTP connection):
		bool			client_is_internal;

		// Message state (applicable only to the current message):
		unsigned int		num_batv_status_headers;// number of existing X-Batv-Status headers in the message
		std::string		env_from;		// the message's envelope sender
		std::string		env_rcpt;		// the message's (last) envelope recipient
		bool			multiple_recipients;	// true iff message has >1 envelope recipients

		Batv_context ()
		{
			client_is_internal = false;
			num_batv_status_headers = 0;
			multiple_recipients = false;
		}

		void clear_message_state ()
		{
			num_batv_status_headers = 0;
			env_from.clear();
			env_rcpt.clear();
			multiple_recipients = false;
		}
	};

	sfsistat milter_status (Config::Failure_mode failure_mode)
	{
		switch (failure_mode) {
		case Config::FAILURE_TEMPFAIL:	return SMFIS_TEMPFAIL;
		case Config::FAILURE_ACCEPT:	return SMFIS_ACCEPT;
		case Config::FAILURE_REJECT:	return SMFIS_REJECT;
		case Config::FAILURE_DISCARD:	return SMFIS_DISCARD;
		}
		return SMFIS_TEMPFAIL;
	}

	sfsistat on_connect (SMFICTX* ctx, char* hostname, struct sockaddr* hostaddr)
	{
		if (config->debug) std::cerr << "on_connect " << ctx << '\n';

		Batv_context*		batv_ctx = new Batv_context;
		if (smfi_setpriv(ctx, batv_ctx) == MI_FAILURE) {
			delete batv_ctx;
			std::clog << "on_connect: smfi_setpriv failed" << std::endl;
			return milter_status(config->on_internal_error);
		}

		if (!hostaddr) {
			// Probably a local user calling sendmail directly
			batv_ctx->client_is_internal = true;
		} else if (hostaddr->sa_family == AF_INET) {
			sockaddr_in	sin;
			std::memcpy(&sin, hostaddr, sizeof(sin));
			batv_ctx->client_is_internal = config->is_internal_host(sin.sin_addr);
		} else if (hostaddr->sa_family == AF_INET6) {
			sockaddr_in6	sin6;
			std::memcpy(&sin6, hostaddr, sizeof(sin6));
			batv_ctx->client_is_internal = config->is_internal_host(sin6.sin6_addr);
		} else {
			// Unsupported socket family. Can't tell if client is internal.
		}

		return SMFIS_CONTINUE;
	}

	sfsistat on_envfrom (SMFICTX* ctx, char** args)
	{
		if (config->debug) std::cerr << "on_envfrom " << ctx << '\n';

		Batv_context*		batv_ctx = static_cast<Batv_context*>(smfi_getpriv(ctx));
		if (batv_ctx == NULL) {
			std::clog << "on_envfrom: smfi_getpriv failed" << std::endl;
			return milter_status(config->on_internal_error);
		}

		if (!batv_ctx->client_is_internal && smfi_getsymval(ctx, const_cast<char*>("{auth_authen}")) != NULL) {
			// Authenticated client
			batv_ctx->client_is_internal = true;
		}

		// Make note of the envelope sender
		batv_ctx->env_from = args[0];

		return SMFIS_CONTINUE;
	}

	sfsistat on_envrcpt (SMFICTX* ctx, char** args)
	{
		if (config->debug) std::cerr << "on_envrcpt " << ctx << '\n';

		Batv_context*		batv_ctx = static_cast<Batv_context*>(smfi_getpriv(ctx));
		if (batv_ctx == NULL) {
			std::clog << "on_envrcpt: smfi_getpriv failed" << std::endl;
			return milter_status(config->on_internal_error);
		}

		// Make note of the envelope recipient
		batv_ctx->multiple_recipients = !batv_ctx->env_rcpt.empty();
		batv_ctx->env_rcpt = args[0];

		return SMFIS_CONTINUE;
	}

	sfsistat on_header (SMFICTX* ctx, char* name, char* value)
	{
		if (config->debug) std::cerr << "on_header " << ctx << '\n';

		Batv_context*		batv_ctx = static_cast<Batv_context*>(smfi_getpriv(ctx));
		if (batv_ctx == NULL) {
			std::clog << "on_header: smfi_getpriv failed" << std::endl;
			return milter_status(config->on_internal_error);
		}

		// Count the number of existing X-Batv-Status headers so we can remove them later.
		if (strcasecmp(name, "X-Batv-Status") == 0) {
			++batv_ctx->num_batv_status_headers;
			if (batv_ctx->num_batv_status_headers == 0) {
				// integer overflow; rather unlikely since a message with 4 billion X-Batv-Status headers would be enormous
				std::clog << "on_header: rejecting incoming message because it has too many existing X-Batv-Status headers, which is likely malicious" << std::endl;
				return SMFIS_REJECT;
			}
		}

		return SMFIS_CONTINUE;
	}

	Verify_result verify (Batv_context* batv_ctx, std::string* true_rcpt)
	{
		if (batv_ctx->multiple_recipients) {
			true_rcpt->clear();
			// This can't be a valid bounce because it has more than one recipient.
			// Section 4.5.5 of RFC5321 states that messages with a null reverse-path
			// "are notifications about a previous message, and they are sent to the
			// reverse-path of the previous mail message."  A message has exactly
			// one reverse-path (section 3.3), ergo messages with a null reverse-path
			// must have exactly one recipient.
			return VERIFY_MULTIPLE_RCPT;
		}

		Email_address		env_rcpt;
		env_rcpt.parse(canon_address(batv_ctx->env_rcpt.c_str()).c_str());

		return batv::verify(env_rcpt, true_rcpt, *config);
	}

	sfsistat on_eom (SMFICTX* ctx)
	{
		if (config->debug) std::cerr << "on_eom " << ctx << '\n';

		Batv_context*		batv_ctx = static_cast<Batv_context*>(smfi_getpriv(ctx));
		if (batv_ctx == NULL) {
			std::clog << "on_eom: smfi_getpriv failed" << std::endl;
			return milter_status(config->on_internal_error);
		}

		if (config->do_verify) {
			// Remove all existing X-Batv-Status headers from the message.
			// This is to prevent a malicious sender from trying to fake us out.
			while (batv_ctx->num_batv_status_headers > 0) {
				if (smfi_chgheader(ctx, const_cast<char*>("X-Batv-Status"), batv_ctx->num_batv_status_headers--, NULL) == MI_FAILURE) {
					std::clog << "on_eom: smfi_chgheader failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
			}

			const bool		is_bounce = canon_address(batv_ctx->env_from.c_str()).empty(); // bounces have null envelope senders (TODO: there should be configurable bounce detection logic)

			std::string		true_rcpt;
			Verify_result		result = verify(batv_ctx, &true_rcpt);
			const char*		batv_status = NULL;
			sfsistat		our_milter_status = SMFIS_ACCEPT;

			if (result == VERIFY_SUCCESS) {
				batv_status = "valid";
			} else if (result == VERIFY_MISSING && is_bounce) {
				batv_status = "invalid, missing";
				our_milter_status = milter_status(config->on_invalid);
			} else if (result == VERIFY_BAD_SIGNATURE && is_bounce) {
				batv_status = "invalid, bad-signature";
				our_milter_status = milter_status(config->on_invalid);
			} else if (result == VERIFY_MULTIPLE_RCPT && is_bounce) {
				batv_status = "invalid, multiple-rcpt";
				our_milter_status = milter_status(config->on_invalid);
			} else if (result == VERIFY_ERROR) {
				our_milter_status = milter_status(config->on_internal_error);
			}

			if (our_milter_status != SMFIS_ACCEPT) {
				batv_ctx->clear_message_state();
				return our_milter_status;
			}

			if (batv_status) {
				// Add the X-Batv-Status header
				if (smfi_addheader(ctx, const_cast<char*>("X-Batv-Status"), const_cast<char*>(batv_status)) == MI_FAILURE) {
					std::clog << "on_eom: smfi_addheader failed (1)" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
			}

			if (result == VERIFY_SUCCESS) {
				// Add a X-Batv-Delivered-To header containing the envelope recipient, pre-rewrite
				if (smfi_addheader(ctx, const_cast<char*>("X-Batv-Delivered-To"), const_cast<char*>(batv_ctx->env_rcpt.c_str())) == MI_FAILURE) { // TODO: I should probably be filling this with the *canonicalized* env recipient, since you don't see angle brackets in the normal Delivered-To header.
					std::clog << "on_eom: smfi_addheader failed (2)" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}

				// Restore the recipient to the original value
				if (smfi_delrcpt(ctx, const_cast<char*>(batv_ctx->env_rcpt.c_str())) == MI_FAILURE) {
					std::clog << "on_eom: smfi_delrcpt failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
				if (smfi_addrcpt(ctx, const_cast<char*>(true_rcpt.c_str())) == MI_FAILURE) {
					std::clog << "on_eom: smfi_addrcpt failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
			}
		}

		if (config->do_sign && batv_ctx->client_is_internal) {
			const Key*	sender_key = NULL;
			Email_address	env_from;
			env_from.parse(canon_address(batv_ctx->env_from.c_str()).c_str());
			if (!is_batv_address(env_from, config->sub_address_delimiter) &&
					(sender_key = config->get_key(env_from.make_string())) != NULL) {
				// Message from internal sender who uses BATV -> rewrite the envelope sender to a BATV address.
				// (We only do this if the envelope sender isn't already a BATV address)
				Batv_address new_sender(prvs_generate(env_from, config->address_lifetime, *sender_key));

				if (smfi_chgfrom(ctx, const_cast<char*>(new_sender.make_string(config->sub_address_delimiter).c_str()), NULL) == MI_FAILURE) {
					std::clog << "on_eom: smfi_chgfrom failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
			}
		}


		batv_ctx->clear_message_state();
		return SMFIS_ACCEPT;
	}

	sfsistat on_abort (SMFICTX* ctx)
	{
		if (config->debug) std::cerr << "on_abort " << ctx << '\n';
		if (Batv_context* batv_ctx = static_cast<Batv_context*>(smfi_getpriv(ctx))) {
			batv_ctx->clear_message_state();
		}
		return SMFIS_CONTINUE; // return value doesn't matter in on_abort()
	}
	sfsistat on_close (SMFICTX* ctx)
	{
		if (config->debug) std::cerr << "on_close " << ctx << '\n';

		delete static_cast<Batv_context*>(smfi_getpriv(ctx));
		smfi_setpriv(ctx, NULL); // this shouldn't matter because we never access the private
					 // data again but libmilter complains if it's not NULL'ed out.
		return SMFIS_CONTINUE; // return value doesn't matter in on_close()
	}

	const char* get_socket_path (const std::string& conn_spec)
	{
		if (conn_spec.substr(0, 5) == "unix:") {
			return conn_spec.c_str() + 5;
		} else if (conn_spec.substr(0, 6) == "local:") {
			return conn_spec.c_str() + 6;
		}
		return NULL;
	}
}

int main (int argc, const char** argv)
try {
	Config		main_config;
	// Command line arguments come in pairs of the form "--name value" and correspond
	// directly to the name/value option pairs in the config file (a la OpenVPN).
	for (int i = 1; i < argc; i += 2) {
		if (std::strncmp(argv[i], "--", 2) == 0 && i + 1 < argc) {
			main_config.set(argv[i] + 2, argv[i+1]);
		} else {
			std::clog << argv[0] << ": Bad arguments" << std::endl;
			return 2;
		}
	}
	main_config.validate();
	if (main_config.keys.empty()) {
		std::clog << argv[0] << ": Warning: no keys specified in config.  This program will do nothing useful." << std::endl;
	}
	config = &main_config;

	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_IGN);

	// Populate the smfiDesc struct with details about this milter and the callbacks we use
	struct smfiDesc		milter_desc;
	std::memset(&milter_desc, '\0', sizeof(milter_desc));

	milter_desc.xxfi_name = const_cast<char*>("batv-milter");
	milter_desc.xxfi_version = SMFI_VERSION;
	milter_desc.xxfi_flags = SMFIF_CHGFROM | SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_DELRCPT | SMFIF_ADDRCPT;
	milter_desc.xxfi_connect = on_connect;
	milter_desc.xxfi_helo = NULL;
	milter_desc.xxfi_envfrom = on_envfrom;
	milter_desc.xxfi_envrcpt = on_envrcpt;
	milter_desc.xxfi_header = on_header;
	milter_desc.xxfi_eoh = NULL;
	milter_desc.xxfi_body = NULL;
	milter_desc.xxfi_eom = on_eom;
	milter_desc.xxfi_abort = on_abort;
	milter_desc.xxfi_close = on_close;
	milter_desc.xxfi_unknown = NULL;
	milter_desc.xxfi_data = NULL;
	milter_desc.xxfi_negotiate = NULL;

	std::string		conn_spec;
	if (config->socket_spec[0] == '/') {
		// If the socket starts with a /, assume it's a path to a UNIX domain socket
		conn_spec = "unix:" + config->socket_spec;
	} else {
		conn_spec = config->socket_spec;
	}

	if (const char* path = get_socket_path(conn_spec)) {
		struct stat status;
		if (lstat(path, &status) == 0) {
			if (!S_ISSOCK(status.st_mode)) {
				std::clog << path << ": socket file already exists (as a non-socket file)" << std::endl;
				return 1;
			}
			if (unix_socket_is_alive(path, 5000)) {
				std::clog << path << ": socket file already exists and is in use by a running process" << std::endl;
				return 1;
			}
			if (unlink(path) == -1) {
				std::clog << path << ": could not remove stale socket file: " << strerror(errno) << std::endl;
				return 1;
			}
		} else if (errno != ENOENT) {
			std::clog << path << ": " << strerror(errno) << std::endl;
			return 1;
		}
	}

	drop_privileges(config->user_name, config->group_name);

	if (config->daemon) {
		daemonize(config->pid_file, "");
	}

	if (config->socket_mode != -1) {
		// We don't have much control over the permissions of the socket, so
		// approximate it by setting a umask that should result in the desired
		// permissions on the socket.  This program doesn't create any other
		// files so this shouldn't have any undesired side-effects.
		umask(~config->socket_mode & 0777);
	}

	smfi_setdbg(config->debug);

	bool			ok = true;

	if (ok && smfi_setconn(const_cast<char*>(conn_spec.c_str())) == MI_FAILURE) {
		std::clog << "smfi_setconn failed" << std::endl;
		ok = false;
	}

	if (ok && smfi_register(milter_desc) == MI_FAILURE) {
		std::clog << "smfi_register failed" << std::endl;
		ok = false;
	}

	// Run the milter
	if (ok && smfi_main() == MI_FAILURE) {
		std::clog << "smfi_main failed" << std::endl;
		ok = false;
	}

	// Clean up
	if (const char* path = get_socket_path(conn_spec)) {
		unlink(path);
	}
	if (!config->pid_file.empty()) {
		unlink(config->pid_file.c_str());
	}
       
	return ok ? 0 : 1;
} catch (const Initialization_error& e) {
	std::clog << argv[0] << ": " << e.message << std::endl;
	return 1;
}
