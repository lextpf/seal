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
 * Packet wire format; the 8-byte AAD header is the magic plus the four raw KDF-parameter
 * bytes, fed verbatim as GCM AAD:
 * @f$[\text{AAD}_{8} \mid \text{Salt}_{16} \mid \text{IV}_{12} \mid \text{CT}_{n} \mid
 * \text{Tag}_{16}]@f$ where @f$n = |\text{plaintext}|@f$. GCM is a stream mode, so
 * ciphertext length equals plaintext length and framing costs a constant 52 bytes:
 * @f$|\text{packet}| = 52 + n@f$. scrypt memory at the default parameters is
 * @f$M = 128 \cdot r \cdot N = 128 \cdot 8 \cdot 2^{16} = 64\text{ MiB}@f$.
 *
 * @note The header stays plaintext so a packet is rejected before key derivation runs; the
 *       GCM tag still covers it, so an edited header fails authentication. This magic names
 *       one packet, while a vault file writes its own frame magic `SVH2` ahead of the
 *       packet records; the two values differ on purpose.
 *
 * @par AAD header layout (8 bytes, fed verbatim as GCM AAD)
 * | Offset | Size | Field | Value / source                          |
 * |--------|------|-------|-----------------------------------------|
 * | 0..3   | 4    | magic | `AAD_HDR` = "seal" (`MAGIC_LEN` bytes)  |
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
static constexpr size_t FILE_CHUNK = 1 << 20;  ///< File block size and stream threshold (1 MiB).
static constexpr uint64_t SCRYPT_N =
    1ULL << 16;  ///< scrypt cost reference (@f$2^{16} = 65536@f$); runtime N comes from KdfParams.
static constexpr uint64_t SCRYPT_R = 8;  ///< scrypt block size reference; see KdfParams::r.
static constexpr uint64_t SCRYPT_P = 1;  ///< scrypt parallelisation reference; see KdfParams::p.
static constexpr uint64_t SCRYPT_MAXMEM =
    128ULL * 1024 * 1024;  ///< scrypt maxmem floor (128 MiB = 2x the default working set).

/// @brief AAD magic identifying a seal packet (prefixes the self-describing KDF header).
/// Only the first `MAGIC_LEN` bytes reach the wire; the string terminator is not written.
static constexpr char AAD_HDR[] = "seal";
/// @brief Magic-prefix length: bytes compared to identify a packet before parsing.
static constexpr size_t MAGIC_LEN = sizeof(AAD_HDR) - 1;
/// @brief Packet header length: magic(4) + alg(1) + log2N(1) + r(1) + p(1).
static constexpr size_t HDR_LEN = 8;

/**
 * @struct KdfParams
 * @brief Self-describing KDF parameters carried in the packet header.
 *
 * Serialized as four raw bytes (alg, log2N, r, p) at header offsets 4..7, inside the
 * GCM-authenticated AAD, so they are tamper-evident. The defaults below are the write-side
 * values; a parsed packet may carry any values that kdfParamsAcceptable() admits.
 */
struct KdfParams
{
    uint8_t alg = 0x01;  ///< KDF algorithm id (0x01 = scrypt).
    uint8_t log2N = 16;  ///< scrypt N as a power of two.
    uint8_t r = 8;       ///< scrypt block size.
    uint8_t p = 1;       ///< scrypt parallelisation.
};

/// @brief Default write-side parameters; the values mirror SCRYPT_N, SCRYPT_R and SCRYPT_P.
static constexpr KdfParams DEFAULT_KDF{};

static constexpr uint8_t KDF_ALG_SCRYPT = 0x01;  ///< scrypt algorithm id.
static constexpr uint8_t KDF_LOG2N_MIN = 14;     ///< Floor: 16 MiB working set at r = 8.
static constexpr uint8_t KDF_LOG2N_MAX = 22;     ///< Ceiling: N = 2^22; see the memory cap.
static constexpr uint8_t KDF_R_MAX = 32;         ///< scrypt r ceiling.
static constexpr uint8_t KDF_P_MAX = 16;         ///< scrypt p ceiling.
/// @brief Decrypt-side memory ceiling: hostile packets cannot demand more.
/// Cryptography::deriveKey() passes `max(SCRYPT_MAXMEM, 2 * 128 * r * N)` to OpenSSL, so
/// SCRYPT_MAXMEM is a floor and this constant is the real ceiling. kdfParamsAcceptable()
/// enforces it before derivation starts; OpenSSL does not.
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
 * | alg   | 0x01 (scrypt)           | `== KDF_ALG_SCRYPT` (0x01)      |
 * | log2N | 16                      | `KDF_LOG2N_MIN..MAX` = 14..22   |
 * | r     | 8                       | 1..`KDF_R_MAX` = 32             |
 * | p     | 1                       | 1..`KDF_P_MAX` = 16             |
 *
 * @param k Parameters parsed from a packet header.
 * @return `true` when every field and the implied memory cost are in range.
 * @note At the top of the log2N range the memory bound binds first:
 *       `log2N == KDF_LOG2N_MAX` passes only with `r == 1`, because
 *       @f$128 \cdot 2 \cdot 2^{22}@f$ is already past the cap.
 * @warning This is the decode-side gate. Cryptography::makeHeader() serializes whatever
 *          parameters it is given, so encode-side callers must not take them from a packet.
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

/**
 * @brief Compile-time validation of the cryptographic configuration invariants.
 *
 * The static_asserts in the body are checked when this definition is compiled, so a broken
 * invariant fails the build even when nothing calls the function.
 *
 * @return Always `true`; the value exists so that @ref kConfigValid can bind to it.
 */
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
/// @brief Names the validated configuration set and constant-evaluates validate().
/// The build fails inside validate() itself, so this variable records the invariant set
/// rather than enforcing it. Nothing reads the value.
inline constexpr bool kConfigValid = validate();
}  // namespace cfg

/// @brief Concept for element types that may alias raw bytes.
/// @details Accepts `char`, `unsigned char` and `std::byte` with any cv-qualification.
///          `signed char` and `wchar_t` are rejected; `std::uint8_t` is accepted because
///          MSVC defines it as `unsigned char`.
template <class T>
concept byte_like =
    std::same_as<std::remove_cv_t<T>, unsigned char> || std::same_as<std::remove_cv_t<T>, char> ||
    std::same_as<std::remove_cv_t<T>, std::byte>;

/// @brief Concept for secure password containers (e.g. basic_secure_string).
/// @details Requires public `.data()` and `.size()` accessors. The concept does not demand
///          locked memory, and `.size()` counts code units, not bytes: key derivation
///          scales it by `sizeof(CharT)` to get the scrypt password length.
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
 * @warning @p a must be a power of two. `NDEBUG` (every Release build) drops the assert,
 *          so @p a == 0 silently returns 0, and @p v near `SIZE_MAX` wraps.
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
