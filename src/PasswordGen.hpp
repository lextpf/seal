#pragma once

#include "SecureString.hpp"

namespace seal
{

/**
 * @fn secure_string<> GeneratePassword(int length)
 * @brief Generate a uniform random password in guarded memory.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Crypto
 *
 * Each character is chosen independently; the result need not contain every character class.
 * The locked allocator attempts page locking but does not fail if VirtualLock fails.
 *
 * | Class     | Characters       | Count |
 * |-----------|------------------|-------|
 * | Uppercase | `A`-`Z`          | 26    |
 * | Lowercase | `a`-`z`          | 26    |
 * | Digits    | `0`-`9`          | 10    |
 * | Symbols   | `!@#$%^&*()-_=+` | 14    |
 *
 * Rejection sampling discards RAND_bytes values at or above 228. Each of the 76 characters
 * then has three possible byte values, so reduction modulo 76 adds no bias. Random bytes use
 * pageable stack blocks of up to 128 bytes; the block is wiped on success.
 *
 * @param length Clamped to 8..128 characters.
 * @return Password with exactly the clamped length; destruction wipes its allocation.
 * @throw std::runtime_error On RAND_bytes failure. The stack block can retain earlier bytes;
 *        the partial password is wiped during unwinding.
 */
[[nodiscard]] secure_string<> GeneratePassword(int length);

}  // namespace seal
