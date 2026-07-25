#include "ProtectedFolderProfile.hpp"

#include "Cryptography.hpp"

#include <windows.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace
{

// Frame: magic(4) | version(1) | packetLen(4, big endian) | packet | SHA-256(32).
// The digest is an unkeyed integrity check over the packet only; the packet's
// own GCM tag is what authenticates it. Minimum frame is 4+1+4+32 = 41 bytes.
constexpr std::array<unsigned char, 4> kProfileMagic{'S', 'F', 'P', '1'};
constexpr unsigned char kProfileVersion = 1;
constexpr std::size_t kDigestSize = 32;
constexpr std::size_t kMaximumProfileBytes = 4096;
// Fixed plaintext sealed into every profile. The profile stores no password and
// no credential; a correct decrypt of these 32 bytes is the whole proof.
constexpr std::array<unsigned char, 32> kVerifier{
    's', 'e', 'a', 'l', '-', 'f', 'o', 'l', 'd', 'e', 'r', '-', 'p', 'r', 'o', 'f',
    'i', 'l', 'e', '-', 'v', 'e', 'r', 'i', 'f', 'i', 'e', 'r', '-', 'v', '1', '\0',
};

struct ParsedProfile
{
    seal::ProtectedFolderProfileState state = seal::ProtectedFolderProfileState::Invalid;
    std::vector<unsigned char> packet;
    std::string message;
};

void setError(std::string* destination, std::string message)
{
    if (destination)
    {
        *destination = std::move(message);
    }
}

void appendU32BE(std::vector<unsigned char>& out, std::uint32_t value)
{
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffu));
    out.push_back(static_cast<unsigned char>(value & 0xffu));
}

std::uint32_t readU32BE(std::span<const unsigned char> bytes)
{
    return (static_cast<std::uint32_t>(bytes[0]) << 24) |
           (static_cast<std::uint32_t>(bytes[1]) << 16) |
           (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

bool sha256(std::span<const unsigned char> bytes, std::array<unsigned char, kDigestSize>& digest)
{
    unsigned int length = 0;
    return EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) ==
               1 &&
           length == digest.size();
}

bool hasReparsePoint(const std::filesystem::path& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

ParsedProfile parseProfile(const std::filesystem::path& path)
{
    ParsedProfile parsed;

    std::error_code existsError;
    const bool exists = std::filesystem::exists(path, existsError);
    if (existsError)
    {
        parsed.message = "Could not inspect the folder profile.";
        return parsed;
    }
    if (!exists)
    {
        parsed.state = seal::ProtectedFolderProfileState::Missing;
        parsed.message = "The folder profile is missing.";
        return parsed;
    }
    if (hasReparsePoint(path))
    {
        parsed.message = "The folder profile must not be a symlink or reparse point.";
        return parsed;
    }

    std::error_code statusError;
    if (!std::filesystem::is_regular_file(path, statusError) || statusError)
    {
        parsed.message = "The folder profile is not a regular file.";
        return parsed;
    }

    const std::uintmax_t fileSize = std::filesystem::file_size(path, statusError);
    if (statusError || fileSize > kMaximumProfileBytes ||
        fileSize < kProfileMagic.size() + 1 + 4 + kDigestSize)
    {
        parsed.message = "The folder profile has an invalid size.";
        return parsed;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        parsed.message = "Could not open the folder profile.";
        return parsed;
    }
    std::vector<unsigned char> frame(static_cast<std::size_t>(fileSize));
    input.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
    // Require exactly the stated size and then EOF: a file that shrank or grew
    // between the size query and the read is rejected instead of half-parsed.
    if (!input || input.peek() != std::ifstream::traits_type::eof())
    {
        parsed.message = "Could not read the folder profile.";
        return parsed;
    }

    std::size_t position = 0;
    if (!std::equal(kProfileMagic.begin(), kProfileMagic.end(), frame.begin()))
    {
        parsed.message = "The folder profile magic is invalid.";
        return parsed;
    }
    position += kProfileMagic.size();
    if (frame[position++] != kProfileVersion)
    {
        parsed.message = "The folder profile version is not supported.";
        return parsed;
    }

    // The declared length must consume the frame exactly: no slack before the
    // digest and no bytes after it. The size floor checked above keeps
    // "frame.size() - position - kDigestSize" from wrapping.
    const std::uint32_t packetLength =
        readU32BE(std::span<const unsigned char>(frame).subspan(position, 4));
    position += 4;
    if (packetLength == 0 ||
        static_cast<std::size_t>(packetLength) > frame.size() - position - kDigestSize ||
        position + static_cast<std::size_t>(packetLength) + kDigestSize != frame.size())
    {
        parsed.message = "The folder profile packet length is invalid.";
        return parsed;
    }

    parsed.packet.assign(frame.begin() + static_cast<std::ptrdiff_t>(position),
                         frame.begin() + static_cast<std::ptrdiff_t>(
                                             position + static_cast<std::size_t>(packetLength)));
    position += packetLength;

    std::array<unsigned char, kDigestSize> expectedDigest{};
    if (!sha256(parsed.packet, expectedDigest) ||
        !seal::Cryptography::ctEqualRaw(
            expectedDigest.data(), frame.data() + position, expectedDigest.size()))
    {
        parsed.packet.clear();
        parsed.message = "The folder profile checksum is invalid.";
        return parsed;
    }

    // Cap-validate the embedded KDF header now, so a hostile profile cannot
    // make a later verify call run an oversized scrypt.
    try
    {
        (void)seal::Cryptography::parsePacketHeader(parsed.packet);
    }
    catch (const std::exception&)
    {
        parsed.packet.clear();
        parsed.message = "The folder profile contains an invalid crypto header.";
        return parsed;
    }

    parsed.state = seal::ProtectedFolderProfileState::Valid;
    return parsed;
}

bool writeProfile(const std::filesystem::path& profilePath,
                  const seal::ProtectedFolderPassword& password,
                  bool replaceExisting,
                  std::string* errorMessage,
                  const seal::cfg::KdfParams& kdf)
{
    if (password.empty())
    {
        setError(errorMessage, "The folder password must not be empty.");
        return false;
    }
    if (profilePath.empty() || profilePath.filename() != seal::kProtectedFolderProfileFileName)
    {
        setError(errorMessage, "The folder profile path is invalid.");
        return false;
    }

    std::error_code parentError;
    if (!std::filesystem::is_directory(profilePath.parent_path(), parentError) || parentError)
    {
        setError(errorMessage, "The folder profile parent directory is unavailable.");
        return false;
    }

    std::error_code existsError;
    const bool destinationExists = std::filesystem::exists(profilePath, existsError);
    if (existsError || hasReparsePoint(profilePath))
    {
        setError(errorMessage, "The folder profile destination could not be inspected safely.");
        return false;
    }
    // create and replace are exact mirrors: create refuses an existing
    // destination, replace refuses a missing one. Neither ever creates the
    // other's case by accident.
    if ((!replaceExisting && destinationExists) || (replaceExisting && !destinationExists))
    {
        setError(errorMessage,
                 replaceExisting ? "The folder profile is missing."
                                 : "A folder profile already exists.");
        return false;
    }

    std::filesystem::path temporaryPath = profilePath;
    temporaryPath += L".tmp";
    const bool temporaryExists = std::filesystem::exists(temporaryPath, existsError);
    if (existsError || temporaryExists || hasReparsePoint(temporaryPath))
    {
        setError(errorMessage, "The folder profile staging path is already occupied.");
        return false;
    }

    try
    {
        std::vector<unsigned char> packet = seal::Cryptography::encryptPacket(
            std::span<const unsigned char>(kVerifier), password, kdf);
        if (packet.size() > std::numeric_limits<std::uint32_t>::max())
        {
            setError(errorMessage, "The folder profile packet is too large.");
            return false;
        }

        std::array<unsigned char, kDigestSize> digest{};
        if (!sha256(packet, digest))
        {
            seal::Cryptography::cleanseString(packet);
            setError(errorMessage, "Could not checksum the folder profile.");
            return false;
        }

        std::vector<unsigned char> frame;
        frame.reserve(kProfileMagic.size() + 1 + 4 + packet.size() + digest.size());
        frame.insert(frame.end(), kProfileMagic.begin(), kProfileMagic.end());
        frame.push_back(kProfileVersion);
        appendU32BE(frame, static_cast<std::uint32_t>(packet.size()));
        frame.insert(frame.end(), packet.begin(), packet.end());
        frame.insert(frame.end(), digest.begin(), digest.end());
        seal::Cryptography::cleanseString(packet);

        // CREATE_NEW closes the check/open race for the deterministic staging
        // name: an unrelated file or reparse point can never be truncated.
        HANDLE output = CreateFileW(temporaryPath.c_str(),
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_NEW,
                                    FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH,
                                    nullptr);
        if (output == INVALID_HANDLE_VALUE)
        {
            seal::Cryptography::cleanseString(frame);
            setError(errorMessage, "Could not create the folder profile staging file.");
            return false;
        }

        DWORD bytesWritten = 0;
        const bool wrote =
            frame.size() <= std::numeric_limits<DWORD>::max() &&
            WriteFile(
                output, frame.data(), static_cast<DWORD>(frame.size()), &bytesWritten, nullptr) !=
                0 &&
            bytesWritten == frame.size() && FlushFileBuffers(output) != 0;
        CloseHandle(output);
        seal::Cryptography::cleanseString(frame);
        if (!wrote)
        {
            DeleteFileW(temporaryPath.c_str());
            setError(errorMessage, "Could not durably write the folder profile.");
            return false;
        }

        const DWORD moveFlags =
            MOVEFILE_WRITE_THROUGH | (replaceExisting ? MOVEFILE_REPLACE_EXISTING : 0);
        if (!MoveFileExW(temporaryPath.c_str(), profilePath.c_str(), moveFlags))
        {
            DeleteFileW(temporaryPath.c_str());
            setError(errorMessage, "Could not commit the folder profile.");
            return false;
        }

        const DWORD attributes = GetFileAttributesW(profilePath.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES)
        {
            (void)SetFileAttributesW(profilePath.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
        }
        return true;
    }
    catch (const std::exception& error)
    {
        DeleteFileW(temporaryPath.c_str());
        setError(errorMessage, error.what());
        return false;
    }
}

}  // namespace

namespace seal
{

ProtectedFolderProfileInspection inspectProtectedFolderProfile(
    const std::filesystem::path& profilePath) noexcept
{
    try
    {
        ParsedProfile parsed = parseProfile(profilePath);
        return {parsed.state, std::move(parsed.message)};
    }
    catch (const std::exception& error)
    {
        return {ProtectedFolderProfileState::Invalid, error.what()};
    }
    catch (...)
    {
        return {ProtectedFolderProfileState::Invalid, "Could not inspect the folder profile."};
    }
}

ProtectedFolderProfileVerifyResult verifyProtectedFolderProfile(
    const std::filesystem::path& profilePath, const ProtectedFolderPassword& password) noexcept
{
    try
    {
        ParsedProfile parsed = parseProfile(profilePath);
        if (parsed.state == ProtectedFolderProfileState::Missing)
        {
            return {ProtectedFolderProfileVerification::Missing, std::move(parsed.message)};
        }
        if (parsed.state != ProtectedFolderProfileState::Valid)
        {
            return {ProtectedFolderProfileVerification::Invalid, std::move(parsed.message)};
        }

        try
        {
            std::vector<unsigned char> plaintext =
                Cryptography::decryptPacket(parsed.packet, password);
            const bool matches = Cryptography::ctEqualAny(plaintext, kVerifier);
            Cryptography::cleanseString(plaintext);
            Cryptography::cleanseString(parsed.packet);
            return matches ? ProtectedFolderProfileVerifyResult{ProtectedFolderProfileVerification::
                                                                    Verified,
                                                                {}}
                           : ProtectedFolderProfileVerifyResult{
                                 ProtectedFolderProfileVerification::Invalid,
                                 "The folder profile verifier is invalid."};
        }
        catch (const std::exception& error)
        {
            Cryptography::cleanseString(parsed.packet);
            // The crypto layer reports a bad password and a tampered packet the
            // same way, so the message prefix is the only signal that separates
            // "re-prompt" from "this folder is damaged". Keep the prefix in step
            // with Cryptography::decryptPacket.
            const std::string message = error.what();
            if (message.starts_with("Authentication failed"))
            {
                return {ProtectedFolderProfileVerification::WrongPassword,
                        "Wrong folder password."};
            }
            return {ProtectedFolderProfileVerification::Invalid, message};
        }
    }
    catch (const std::exception& error)
    {
        return {ProtectedFolderProfileVerification::Invalid, error.what()};
    }
    catch (...)
    {
        return {ProtectedFolderProfileVerification::Invalid,
                "Could not verify the folder profile."};
    }
}

bool createProtectedFolderProfile(const std::filesystem::path& profilePath,
                                  const ProtectedFolderPassword& password,
                                  std::string* errorMessage,
                                  const cfg::KdfParams& kdf) noexcept
{
    return writeProfile(profilePath, password, false, errorMessage, kdf);
}

bool replaceProtectedFolderProfile(const std::filesystem::path& profilePath,
                                   const ProtectedFolderPassword& password,
                                   std::string* errorMessage,
                                   const cfg::KdfParams& kdf) noexcept
{
    return writeProfile(profilePath, password, true, errorMessage, kdf);
}

}  // namespace seal
