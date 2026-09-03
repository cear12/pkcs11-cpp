#pragma once

#include <iostream>
#include <string>

namespace pkcs11cpp::log {

// Minimal, dependency-free logging used consistently across pkcs11-cpp.
// A real deployment would swap this for the host application's logger
// (spdlog, a syslog wrapper, ...); every module in this repo goes through
// these three functions so that swap is a one-file change.
inline void info(const std::string& message) { std::cout << "[INFO] " << message << '\n'; }
inline void warn(const std::string& message) { std::cerr << "[WARN] " << message << '\n'; }
inline void error(const std::string& message) { std::cerr << "[ERROR] " << message << '\n'; }

}  // namespace pkcs11cpp::log
