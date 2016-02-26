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

#include "common.hpp"
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <fstream>
#include <sys/socket.h>
#include <sys/un.h>

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
				throw Initialization_error(path + ": " + strerror(errno));
			}
			path.clear();
		}
	} else if (access(path.c_str(), R_OK) == -1) {
		throw Initialization_error(path + ": " + strerror(errno));
	}
}

void batv::drop_privileges (const std::string& username, const std::string& groupname)
{
	if (username.empty() && groupname.empty()) {
		return;
	}

	struct passwd*		usr = NULL;
	struct group*		grp = NULL;
	if (!username.empty()) {
		errno = 0;
		if (!(usr = getpwnam(username.c_str()))) {
			throw Initialization_error(username + ": " + (errno ? strerror(errno) : "No such user"));
		}
	}

	if (!groupname.empty()) {
		errno = 0;
		if (!(grp = getgrnam(groupname.c_str()))) {
			throw Initialization_error(groupname + ": " + (errno ? strerror(errno) : "No such group"));
		}
	}

	// If no group is specified, but a user is specified, drop to the primary GID of that user
	if (setgid(grp ? grp->gr_gid : usr->pw_gid) == -1) {
		throw Initialization_error(std::string("Failed to drop privileges: setgid: ") + strerror(errno));
	}

	if (usr) {
		if (initgroups(usr->pw_name, usr->pw_gid) == -1) {
			throw Initialization_error(std::string("Failed to drop privileges: initgroups: ") + strerror(errno));
		}
		if (setuid(usr->pw_uid) == -1) {
			throw Initialization_error(std::string("Failed to drop privileges: setuid: ") + strerror(errno));
		}
	}
}

void batv::daemonize (const std::string& pid_file, const std::string& stderr_file)
{
	// Open the PID file (open before forking so we can report errors)
	std::ofstream	pid_out;
	if (!pid_file.empty()) {
		pid_out.open(pid_file.c_str(), std::ofstream::out | std::ofstream::trunc);
		if (!pid_out) {
			throw Initialization_error("Unable to open PID file " + pid_file + " for writing.");
		}
	}

	// Open the file descriptor for stderr (open before forking so we can report errors)
	int		stderr_fd;
       	if (stderr_file.empty()) {
		stderr_fd = open("/dev/null", O_WRONLY);
	} else if ((stderr_fd = open(stderr_file.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0666)) == -1) {
		throw Initialization_error("Failed to open " + stderr_file + ": " + strerror(errno));
	}

	// Fork
	pid_t		pid = fork();
	if (pid == -1) {
		std::perror("fork");
		std::exit(127);
	}
	if (pid != 0) {
		// Exit parent
		_exit(0);
	}
	setsid();

	// Write the PID file now that we've forked
	if (pid_out) {
		pid_out << getpid() << '\n';
		pid_out.close();
	}

	// dup the stderr file to stderr
	if (stderr_fd != 2) {
		dup2(stderr_fd, 2);
		close(stderr_fd);
	}
	
	// dup stdin, stdout to /dev/null
	close(0);
	close(1);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
}

bool batv::unix_socket_is_alive (const std::string& path, int timeout_milliseconds)
{
	struct sockaddr_un	addr;
	if (path.size() >= sizeof(addr.sun_path) - 1) {
		// path too long
		return false;
	}
	addr.sun_family = AF_UNIX;
	std::strcpy(addr.sun_path, path.c_str()); // safe - length of path checked above

	const int		sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		// socket(AF_UNIX) failed
		return false;
	}
	const int		sock_flags = fcntl(sockfd, F_GETFL);
	if (sock_flags == -1) {
		// fcntl(F_GETFL) failed
		close(sockfd);
		return false;
	}
	if (fcntl(sockfd, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
		// fcntl(F_SETFL) failed
		close(sockfd);
		return false;
	}
	if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr.sun_family) + path.size()) == -1 && errno != EINPROGRESS) {
		// connect() failed
		close(sockfd);
		return false;
	}
	struct pollfd		pfd;
	pfd.fd = sockfd;
	pfd.events = POLLOUT;
	const int		poll_res = poll(&pfd, 1, timeout_milliseconds);
	if (poll_res == -1) {
		// poll() failed
		close(sockfd);
		return false;
	}
	if (poll_res == 0) {
		// Timeout
		close(sockfd);
		return false;
	}

	int			sock_error;
	socklen_t		sock_error_len = sizeof(sock_error);
	if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_error, &sock_error_len) == -1) {
		// getsockopt(SO_ERROR) failed
		close(sockfd);
		return false;
	}
	if (sock_error != 0) {
		// connect() failed
		close(sockfd);
		return false;
	}
	// connect() succeeded
	close(sockfd);
	return true;
}
