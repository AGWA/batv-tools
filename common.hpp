#pragma once

#include <string>

namespace batv {
	struct Config_error {
		std::string	message;

		explicit Config_error (const std::string& m) : message(m) { }
	};
}
