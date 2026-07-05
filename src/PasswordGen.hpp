#pragma once

#include "SecureString.hpp"

namespace seal
{

/**
 * @brief Generate a cryptographically uniform random password.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Uses OpenSSL `RAND_bytes` with rejection sampling to eliminate
 * modular bias. The charset includes uppercase, lowercase, digits,
 * and common symbols (76 characters total). Length is clamped to
 * [8, 128].
 *
 * The returned string lives in VirtualLock'd memory backed by a
 * locked_allocator, so it will not be paged to disk.
 *
 * @par Character set (L = 76)
 * | Class     | Characters      | Count |
 * |-----------|-----------------|-------|
 * | Uppercase | `A`-`Z`         | 26    |
 * | Lowercase | `a`-`z`         | 26    |
 * | Digits    | `0`-`9`         | 10    |
 * | Symbols   | `!@#$%^&*()-_=+` | 14    |
 * | Total     |                 | 76    |
 *
 * Rejection sampling keeps only random bytes below the largest multiple of
 * @f$L@f$ that fits in one byte (@f$\lfloor 256/76 \rfloor \cdot 76 = 228@f$), so
 * each of the 76 characters is reachable from exactly 3 byte values and the
 * modular bias is zero. The acceptance probability per random byte is:
 * @f[
 *   P_{\text{accept}} = \frac{\lfloor 256 / L \rfloor \cdot L}{256}
 *                     = \frac{228}{256} \approx 0.891
 * @f]
 *
 * @param length Desired password length (clamped to 8..128).
 * @return The generated password in locked memory.
 * @throw std::runtime_error if `RAND_bytes` fails.
 */
[[nodiscard]] secure_string<> GeneratePassword(int length);

}  // namespace seal
