#pragma once

#include "SecureString.hpp"

namespace seal
{

/**
 * @brief Cryptographically uniform random password generation.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * One entry point, built on OpenSSL `RAND_bytes` with rejection sampling to remove modular bias.
 *
 * The returned string lives in locked memory backed by a locked_allocator, so it
 * is never paged to disk.
 *
 * @par Character set (L = 76)
 * | Class     | Characters       | Count |
 * |-----------|------------------|-------|
 * | Uppercase | `A`-`Z`          | 26    |
 * | Lowercase | `a`-`z`          | 26    |
 * | Digits    | `0`-`9`          | 10    |
 * | Symbols   | `!@#$%^&*()-_=+` | 14    |
 * | Total     |                  | 76    |
 *
 * Rejection sampling keeps only a random byte below the largest multiple of
 * @f$L@f$ that fits in one byte (@f$\lfloor 256/76 \rfloor \cdot 76 = 228@f$).
 * Each of the 76 characters is then reachable from 3 byte values, so the modular
 * bias is zero. The acceptance probability per random byte is:
 * @f[
 *   P_{\text{accept}} = \frac{\lfloor 256 / L \rfloor \cdot L}{256}
 *                     = \frac{228}{256} \approx 0.891
 * @f]
 */

/**
 * @brief Generate a cryptographically uniform random password.
 * @ingroup Crypto
 *
 * Draws random bytes in blocks of at most 128, keeps only the bytes that pass rejection
 * sampling, and maps each kept byte onto the 76-character set. Blocks are re-drawn until the
 * requested length is reached, so the number of `RAND_bytes` calls is not fixed.
 *
 * The random block is a stack buffer in pageable memory, wiped with `SecureZeroMemory` before
 * returning. The password itself is built directly in locked memory.
 *
 * @param length Desired password length. A value outside 8..128 is clamped silently, so the
 *               returned length can differ from the requested one.
 * @return The generated password in locked memory, exactly the clamped length.
 * @throw std::runtime_error when `RAND_bytes` fails. No password is returned. The stack block
 *        is left unwiped and can hold bytes from an earlier accepted block, but the partial
 *        password built from them is wiped by its destructor during unwinding.
 */
[[nodiscard]] secure_string<> GeneratePassword(int length);

}  // namespace seal
