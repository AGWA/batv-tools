#include "prvs.hpp"
#include "config.hpp"
#include "address.hpp"
#include "openssl-threads.hpp"
#include <iostream>
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

using namespace batv;

namespace {
	const Config*		config;

	struct Batv_context {
		// Connection state:
		bool		client_is_internal;

		// Message state:
		unsigned int		num_batv_status_headers;// number of existing X-Batv-Status headers in the message
		Email_address		env_from; 		// the message's envelope sender
		bool			is_batv_rcpt;		// is the message destined to a BATV address?
		Batv_address		batv_rcpt;		// the message recipient, valid iff is_batv_rcpt==true
		std::string		batv_rcpt_string;	// original message recipient string, iff is_batv_rcpt==true
		const Config::Key*	batv_rcpt_key;		// the key to be used to sign the address, iff is_batv_rcpt==true


		Batv_context ()
		{
			client_is_internal = false;
			num_batv_status_headers = 0;
			is_batv_rcpt = false;
			batv_rcpt_key = NULL;
		}

		void clear_message_state ()
		{
			num_batv_status_headers = 0;
			env_from.clear();
			is_batv_rcpt = false;
		}
	};

	sfsistat milter_status (Config::Failure_mode failure_mode)
	{
		switch (failure_mode) {
		case Config::FAILURE_TEMPFAIL:	return SMFIS_TEMPFAIL;
		case Config::FAILURE_ACCEPT:	return SMFIS_ACCEPT;
		case Config::FAILURE_REJECT:	return SMFIS_REJECT;
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
			batv_ctx->client_is_internal = config->is_internal_host(reinterpret_cast<struct sockaddr_in*>(hostaddr)->sin_addr);
		} else if (hostaddr->sa_family == AF_INET6) {
			batv_ctx->client_is_internal = config->is_internal_host(reinterpret_cast<struct sockaddr_in6*>(hostaddr)->sin6_addr);
		} else {
			// Unsupported socket family
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
		batv_ctx->env_from.parse(canon_address(args[0]).c_str());

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

		// Check to see if this message is destined to a BATV address
		// (if we haven't already determined that it is)
		if (!batv_ctx->is_batv_rcpt) {
			Email_address		rcpt_to;
			rcpt_to.parse(canon_address(args[0]).c_str());
			// Make sure that the BATV address is syntactically valid AND it's using a known tag type:
			if (batv_ctx->batv_rcpt.parse(rcpt_to, config->sub_address_delimiter) &&
					batv_ctx->batv_rcpt.tag_type == "prvs") {
				// Get the key for this sender:
				batv_ctx->batv_rcpt_key = config->get_key(batv_ctx->batv_rcpt.orig_mailfrom.make_string());
				if (batv_ctx->batv_rcpt_key != NULL) {
					// A non-NULL key means this is a BATV sender.
					batv_ctx->is_batv_rcpt = true;
					batv_ctx->batv_rcpt_string = args[0];
				}
			}
		}

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
		}

		return SMFIS_CONTINUE;
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

			if (batv_ctx->is_batv_rcpt) {
				// Message has a BATV recipient -> validate the BATV signature
				// Set the X-Batv-Status header to "valid" or "invalid"
				const char* status = "invalid";

				if (batv_ctx->batv_rcpt.tag_type == "prvs") {
					if (prvs_validate(batv_ctx->batv_rcpt, config->address_lifetime, *batv_ctx->batv_rcpt_key)) {
						status = "valid";
					}
				}

				if (smfi_addheader(ctx, const_cast<char*>("X-Batv-Status"), const_cast<char*>(status)) == MI_FAILURE) {
					std::clog << "on_eom: smfi_addheader failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}

				// Restore the recipient to the original value
				if (smfi_delrcpt(ctx, const_cast<char*>(batv_ctx->batv_rcpt_string.c_str())) == MI_FAILURE) {
					std::clog << "on_eom: smfi_delrcpt failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
				if (smfi_addrcpt(ctx, const_cast<char*>(batv_ctx->batv_rcpt.orig_mailfrom.make_string().c_str())) == MI_FAILURE) {
					std::clog << "on_eom: smfi_addrcpt failed" << std::endl;
					batv_ctx->clear_message_state();
					return milter_status(config->on_internal_error);
				}
			}
		}

		if (config->do_sign) {
			const Config::Key*	sender_key = NULL;
			if (batv_ctx->client_is_internal &&
					!is_batv_address(batv_ctx->env_from, config->sub_address_delimiter) &&
					(sender_key = config->get_key(batv_ctx->env_from.make_string())) != NULL) {
				// Message from internal sender who uses BATV -> rewrite the envelope sender to a BATV address.
				// (We only do this if the envelope sender isn't already a BATV address)
				Batv_address new_sender(prvs_generate(batv_ctx->env_from, config->address_lifetime, *sender_key));

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
		return SMFIS_CONTINUE; // return value doesn't matter
	}
	sfsistat on_close (SMFICTX* ctx)
	{
		if (config->debug) std::cerr << "on_close " << ctx << '\n';

		delete static_cast<Batv_context*>(smfi_getpriv(ctx));
		return SMFIS_CONTINUE; // return value doesn't matter
	}
}

int main (int argc, const char** argv)
{
	Config		main_config;
	try {
		for (int i = 1; i < argc; i += 2) {
			if (std::strncmp(argv[i], "--", 2) == 0 && i + 1 < argc) {
				main_config.set(argv[i] + 2, argv[i+1]);
			} else {
				std::clog << argv[0] << ": Bad arguments" << std::endl;
				return 2;
			}
		}
		main_config.validate();
	} catch (Config::Error e) {
		std::clog << argv[0] << ": Configuration error: " << e.message << std::endl;
		return 1;
	}
	config = &main_config;



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
		if (access(config->socket_spec.c_str(), F_OK) == 0) {
			std::clog << config->socket_spec << ": socket file already exists" << std::endl;
			return 1;
		}
		conn_spec = "unix:" + config->socket_spec;
	} else {
		conn_spec = config->socket_spec;
	}

	// Daemonize, if applicable
	if (config->daemon) {
		// Open the PID file (open before forking so we can report errors)
		std::ofstream	pid_out;
		if (!config->pid_file.empty()) {
			pid_out.open(config->pid_file.c_str(), std::ofstream::out | std::ofstream::trunc);
			if (!pid_out) {
				std::clog << "Unable to open PID file " << config->pid_file << " for writing." << std::endl;
				return 1;
			}
		}

		pid_t		pid = fork();
		if (pid == -1) {
			std::clog << "fork: " << strerror(errno) << std::endl;
			return 1;
		}
		if (pid != 0) {
			// Exit parent
			return 0;
		}
		setsid();
		
		// Write the PID file now that we've forked
		if (pid_out) {
			pid_out << getpid() << '\n';
			pid_out.close();
		}

		// dup stdin, stdout, stderr to /dev/null
		if (isatty(0) || errno == EBADF) {
			close(0);
			open("/dev/null", O_RDONLY);
		}
		if (isatty(1) || errno == EBADF) {
			close(1);
			open("/dev/null", O_WRONLY);
		}
		if (isatty(2) || errno == EBADF) {
			close(2);
			open("/dev/null", O_WRONLY);
		}
	}

	if (config->socket_mode != -1) {
		// We don't have much control over the permissions of the socket, so
		// approximate it by setting a umask that should result in the desired
		// permissions on the socket.  This program doesn't create any other
		// files so this shouldn't have any undesired side-effects.
		umask(~config->socket_mode & 0777);
	}

	// Initialize the milter library
	openssl_init_threads();

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
	openssl_cleanup_threads();

	if (config->socket_spec[0] == '/') {
		unlink(config->socket_spec.c_str());
	}
	if (!config->pid_file.empty()) {
		unlink(config->pid_file.c_str());
	}
       
	return ok ? 0 : 1;
}

