#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32
#error "Platform not supported: This source targets Windows APIs."
#endif

#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace seal
{
/**
 * @namespace seal::cfg
 * @brief Cryptographic and framing constants for AES-256-GCM encryption.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Packet wire format:
 * $[\text{AAD}_{4} \mid \text{Salt}_{16} \mid \text{IV}_{12} \mid \text{CT}_{n} \mid
 * \text{Tag}_{16}]$ where $n = |\text{plaintext}|$.
 *
 * scrypt memory usage: $M = 128 \cdot r \cdot N = 128 \cdot 8 \cdot 2^{16} = 64\text{ MiB}$.
 */
namespace cfg
{
static constexpr size_t SALT_LEN = 16;         ///< scrypt salt length in bytes.
static constexpr size_t KEY_LEN = 32;          ///< AES-256 key length in bytes.
static constexpr size_t IV_LEN = 12;           ///< AES-GCM initialisation vector length in bytes.
static constexpr size_t TAG_LEN = 16;          ///< GCM authentication tag length in bytes.
static constexpr size_t FILE_CHUNK = 1 << 20;  ///< Read-buffer chunk size (1 MiB).
static constexpr char AAD_HDR[] = "seal";      ///< Additional authenticated data header
static constexpr size_t AAD_LEN =
    sizeof(AAD_HDR) - 1;  ///< AAD header length excluding null terminator.
static constexpr uint64_t SCRYPT_N =
    1ULL << 16;                          ///< scrypt CPU/memory cost parameter ($2^{16} = 65536$).
static constexpr uint64_t SCRYPT_R = 8;  ///< scrypt block size parameter.
static constexpr uint64_t SCRYPT_P = 1;  ///< scrypt parallelisation parameter.
static constexpr uint64_t SCRYPT_MAXMEM =
    128ULL * 1024 * 1024;  ///< scrypt maximum memory allowance (128 MiB, ~2x working set).

/// @brief Compile-time validation of cryptographic configuration invariants.
consteval bool validate()
{
    static_assert(SALT_LEN >= 16, "salt must be at least 16 bytes (NIST SP 800-132)");
    static_assert(KEY_LEN == 32, "AES-256 requires a 32-byte key");
    static_assert(IV_LEN == 12, "AES-GCM requires a 12-byte IV (NIST SP 800-38D)");
    static_assert(TAG_LEN == 16, "GCM tag must be 16 bytes for full authentication strength");
    static_assert(SCRYPT_N > 0 && (SCRYPT_N & (SCRYPT_N - 1)) == 0,
                  "scrypt N must be a power of 2");
    static_assert(SCRYPT_R >= 1, "scrypt r must be at least 1");
    static_assert(SCRYPT_P >= 1, "scrypt p must be at least 1");
    static_assert(SCRYPT_MAXMEM >= 128ULL * SCRYPT_R * SCRYPT_N,
                  "scrypt MAXMEM must cover the working set (128 * r * N)");
    return true;
}
inline constexpr bool kConfigValid = validate();
}  // namespace cfg

/// @brief Concept for byte-addressable element types.
template <class T>
concept byte_like =
    std::same_as<std::remove_cv_t<T>, unsigned char> || std::same_as<std::remove_cv_t<T>, char> ||
    std::same_as<std::remove_cv_t<T>, std::byte>;

/// @brief Concept for secure password containers (e.g. basic_secure_string).
/// @details Requires a `.s` member with `.data()` and `.size()` (the locked vector).
template <class T>
concept secure_password = requires(const T& pwd) {
    { pwd.s.data() };
    { pwd.s.size() } -> std::convertible_to<std::size_t>;
};

/// @brief Round up to the next multiple of an alignment.
static constexpr size_t align_up(size_t v, size_t a)
{
    assert(a > 0);
    return (v + (a - 1)) & ~(a - 1);
}

static constexpr uint32_t kMagic =
    0x6C616573u;  //!< locked_allocator header integrity magic ("seal"); not the vault file magic.
static constexpr uint32_t kVersion =
    1u;  //!< locked_allocator header version; not the vault format version.
static constexpr size_t kCanaryBytes = 32;  //!< Canary bytes after payload (0xD0)

}  // namespace seal
