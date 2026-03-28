#pragma once

#include "SecureString.h"

namespace seal
{

/**
 * @brief Generate a cryptographically uniform random password.
 * @author Alex (https://github.com/lextpf)
 *
 * Uses OpenSSL `RAND_bytes` with rejection sampling to eliminate
 * modular bias. The charset includes uppercase, lowercase, digits,
 * and common symbols (76 characters total). Length is clamped to
 * [8, 128].
 *
 * The returned string lives in VirtualLock'd memory backed by a
 * locked_allocator, so it will not be paged to disk.
 *
 * @param length Desired password length (clamped to 8..128).
 * @return The generated password in locked memory.
 * @throw std::runtime_error if `RAND_bytes` fails.
 */
[[nodiscard]] secure_string<> GeneratePassword(int length);

}  // namespace seal
