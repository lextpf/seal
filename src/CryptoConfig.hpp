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
 * Packet wire format (the 8-byte AAD header is the magic plus the four raw
 * KDF-parameter bytes, fed verbatim as GCM AAD):
 * @f$[\text{AAD}_{8} \mid \text{Salt}_{16} \mid \text{IV}_{12} \mid \text{CT}_{n} \mid
 * \text{Tag}_{16}]@f$ where @f$n = |\text{plaintext}|@f$.
 *
 * scrypt memory usage: @f$M = 128 \cdot r \cdot N = 128 \cdot 8 \cdot 2^{16} = 64\text{ MiB}@f$.
 *
 * @par AAD header layout (8 bytes, fed verbatim as GCM AAD)
 * | Offset | Size | Field | Value / source                          |
 * |--------|------|-------|-----------------------------------------|
 * | 0..3   | 4    | magic | `AAD_HDR` = "seal" (`MAGIC_LEN` bytes)   |
 * | 4      | 1    | alg   | `KdfParams::alg` (0x01 = scrypt)        |
 * | 5      | 1    | log2N | `KdfParams::log2N`; scrypt N = 2^log2N  |
 * | 6      | 1    | r     | `KdfParams::r` (scrypt block size)      |
 * | 7      | 1    | p     | `KdfParams::p` (scrypt parallelism)     |
 */
namespace cfg
{
static constexpr size_t SALT_LEN = 16;         ///< scrypt salt length in bytes.
static constexpr size_t KEY_LEN = 32;          ///< AES-256 key length in bytes.
static constexpr size_t IV_LEN = 12;           ///< AES-GCM initialisation vector length in bytes.
static constexpr size_t TAG_LEN = 16;          ///< GCM authentication tag length in bytes.
static constexpr size_t FILE_CHUNK = 1 << 20;  ///< Read-buffer chunk size (1 MiB).
static constexpr uint64_t SCRYPT_N =
    1ULL << 16;  ///< scrypt CPU/memory cost parameter (@f$2^{16} = 65536@f$).
static constexpr uint64_t SCRYPT_R = 8;  ///< scrypt block size parameter.
static constexpr uint64_t SCRYPT_P = 1;  ///< scrypt parallelisation parameter.
static constexpr uint64_t SCRYPT_MAXMEM =
    128ULL * 1024 * 1024;  ///< scrypt maximum memory allowance (128 MiB, ~2x working set).

/// @brief AAD magic identifying a seal packet (prefixes the self-describing KDF header).
static constexpr char AAD_HDR[] = "seal";
/// @brief Magic-prefix length: bytes compared to identify a packet before parsing.
static constexpr size_t MAGIC_LEN = sizeof(AAD_HDR) - 1;
/// @brief Packet header length: magic(4) + alg(1) + log2N(1) + r(1) + p(1).
static constexpr size_t HDR_LEN = 8;

/**
 * @brief Self-describing KDF parameters carried in the packet header.
 *
 * Serialized as four raw bytes (alg, log2N, r, p) inside the
 * GCM-authenticated AAD, so they are tamper-evident. `alg` 0x01 = scrypt.
 */
struct KdfParams
{
    uint8_t alg = 0x01;  ///< KDF algorithm id (0x01 = scrypt).
    uint8_t log2N = 16;  ///< scrypt N as a power of two.
    uint8_t r = 8;       ///< scrypt block size.
    uint8_t p = 1;       ///< scrypt parallelisation.
};

/// @brief Default write-side parameters (identical to the legacy constants).
static constexpr KdfParams DEFAULT_KDF{};

static constexpr uint8_t KDF_ALG_SCRYPT = 0x01;  ///< scrypt algorithm id.
static constexpr uint8_t KDF_LOG2N_MIN = 14;     ///< floor: 16 MiB working set.
static constexpr uint8_t KDF_LOG2N_MAX = 22;     ///< ceiling: 4 Mi iterations.
static constexpr uint8_t KDF_R_MAX = 32;         ///< scrypt r ceiling.
static constexpr uint8_t KDF_P_MAX = 16;         ///< scrypt p ceiling.
/// @brief Decrypt-side memory ceiling: hostile packets cannot demand more.
static constexpr uint64_t KDF_MAX_MEM_BYTES = 512ULL * 1024 * 1024;

/**
 * @brief Validate decode-side KDF parameters against the acceptance caps.
 *
 * A hostile packet cannot demand an oversized scrypt call: every field is
 * range-checked and the implied working-set memory must satisfy
 *
 * @f[ 128 \cdot r \cdot 2^{\log_2 N} \;\le\; \text{KDF\_MAX\_MEM\_BYTES}
 *     \;=\; 512\ \text{MiB} @f]
 *
 * @par Write-side default vs. decode-side caps
 * | Field | Default (`DEFAULT_KDF`) | Accepted range                  |
 * |-------|-------------------------|---------------------------------|
 * | alg   | 0x01 (scrypt)           | `== KDF_ALG_SCRYPT` (0x01)       |
 * | log2N | 16                      | `KDF_LOG2N_MIN..MAX` = 14..22    |
 * | r     | 8                       | 1..`KDF_R_MAX` = 32             |
 * | p     | 1                       | 1..`KDF_P_MAX` = 16             |
 *
 * @param k Parameters parsed from a packet header.
 * @return `true` when every field and the implied memory cost are in range.
 */
constexpr bool kdfParamsAcceptable(const KdfParams& k)
{
    if (k.alg != KDF_ALG_SCRYPT)
    {
        return false;
    }
    if (k.log2N < KDF_LOG2N_MIN || k.log2N > KDF_LOG2N_MAX)
    {
        return false;
    }
    if (k.r < 1 || k.r > KDF_R_MAX)
    {
        return false;
    }
    if (k.p < 1 || k.p > KDF_P_MAX)
    {
        return false;
    }
    const uint64_t mem = 128ULL * k.r * (1ULL << k.log2N);
    return mem <= KDF_MAX_MEM_BYTES;
}

/// @brief Compile-time validation of cryptographic configuration invariants.
consteval bool validate()
{
    static_assert(kdfParamsAcceptable(DEFAULT_KDF),
                  "default KDF params must satisfy their own caps");
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
/// @brief Forces validate() to run at compile time; a failed static_assert breaks the build.
inline constexpr bool kConfigValid = validate();
}  // namespace cfg

/// @brief Concept for byte-addressable element types.
template <class T>
concept byte_like =
    std::same_as<std::remove_cv_t<T>, unsigned char> || std::same_as<std::remove_cv_t<T>, char> ||
    std::same_as<std::remove_cv_t<T>, std::byte>;

/// @brief Concept for secure password containers (e.g. basic_secure_string).
/// @details Requires public `.data()` and `.size()` accessors on the container.
template <class T>
concept secure_password = requires(const T& pwd) {
    { pwd.data() };
    { pwd.size() } -> std::convertible_to<std::size_t>;
};

/**
 * @brief Round @p v up to the next multiple of @p a.
 *
 * @param v Value to round up.
 * @param a Alignment step.
 * @return The smallest multiple of @p a that is not less than @p v.
 * @pre @p a is a non-zero power of two.
 */
static constexpr size_t align_up(size_t v, size_t a)
{
    assert(a > 0);
    return (v + (a - 1)) & ~(a - 1);
}

static constexpr uint32_t kMagic =
    0x6C616573u;  ///< locked_allocator header integrity magic ("seal"); not the vault file magic.
static constexpr uint32_t kVersion =
    1u;  ///< locked_allocator header version; not the vault format version.
static constexpr size_t kCanaryBytes = 32;  ///< Canary bytes (0xD0) placed after the payload.

}  // namespace seal
