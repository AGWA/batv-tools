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
#include <cstdio>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <fstream>

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
			throw Config_error(username + ": " + (errno ? strerror(errno) : "No such user"));
		}
	}

	if (!groupname.empty()) {
		errno = 0;
		if (!(grp = getgrnam(groupname.c_str()))) {
			throw Config_error(groupname + ": " + (errno ? strerror(errno) : "No such group"));
		}
	}

	// If no group is specified, but a user is specified, drop to the primary GID of that user
	if (setgid(grp ? grp->gr_gid : usr->pw_gid) == -1) {
		throw Config_error(std::string("Failed to drop privileges: setgid: ") + strerror(errno));
	}

	if (usr) {
		if (initgroups(usr->pw_name, usr->pw_gid) == -1) {
			throw Config_error(std::string("Failed to drop privileges: initgroups: ") + strerror(errno));
		}
		if (setuid(usr->pw_uid) == -1) {
			throw Config_error(std::string("Failed to drop privileges: setuid: ") + strerror(errno));
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
			throw Config_error("Unable to open PID file " + pid_file + " for writing.");
		}
	}

	// Open the file descriptor for stderr (open before forking so we can report errors)
	int		stderr_fd;
       	if (stderr_file.empty()) {
		stderr_fd = open("/dev/null", O_WRONLY);
	} else if ((stderr_fd = open(stderr_file.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0666)) == -1) {
		throw Config_error("Failed to open " + stderr_file + ": " + strerror(errno));
	}

	// Fork
	pid_t		pid = fork();
	if (pid == -1) {
		std::perror("fork");
		std::exit(127);
	}
	if (pid != 0) {
		// Exit parent
		std::exit(0);
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

