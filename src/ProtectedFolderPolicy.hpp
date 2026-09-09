#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace seal::protected_folder
{

/**
 * @enum SkipReason
 * @brief append-only exclusion reasons for diagnostics and support tools.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * never renumber values or respell tokens; append new pairs to both lists.
 * commonSkipReason chooses the first matching rule below. planEncrypt applies AlreadyEncrypted
 * only after these rules; planDecrypt never emits it.
 *
 * @verbatim
 *   1 Symlink                  entry.symlink is set
 *   2 QtDeployDir              first path component is a Qt deploy directory
 *   3 CredentialVault          entry.credentialVault is set
 *   4 NativeMessagingManifest  file name "com.seal.fill*.json"
 *   5 Lockfile                 file name ends in ".zombielock"
 *   6 AppRuntime               marker, profile, profile + ".tmp", "qt.conf",
 *                              or an ".exe" / ".dll" / ".pdb" extension
 * @endverbatim
 */
enum class SkipReason : std::uint8_t
{
    AppRuntime = 0,               ///< application, runtime or folder-state file.
    QtDeployDir = 1,              ///< inside a top-level Qt deployment directory.
    NativeMessagingManifest = 2,  ///< Chromium native-messaging host manifest.
    CredentialVault = 3,          ///< file the scan identified as a seal vault.
    AlreadyEncrypted = 4,         ///< encrypt plan only: the name already ends in `.seal`.
    Symlink = 5,                  ///< reparse point: symlink, junction or mount point.
    Lockfile = 6,                 ///< runtime lock file (`*.zombielock`).
};

/// append tokens with their enum values; spelling and positions are stable.
inline constexpr std::array<std::string_view, 7> kSkipReasonTokens{
    "app_runtime",
    "qt_deploy_dir",
    "native_messaging_manifest",
    "credential_vault",
    "already_encrypted",
    "symlink",
    "lockfile",
};

static_assert(static_cast<std::size_t>(SkipReason::Lockfile) + 1 == kSkipReasonTokens.size());

/**
 * @brief borrow a process-lifetime exclusion token.
 * @ingroup Vault
 *
 * @pre reason is a declared enumerator; indexing is unchecked.
 */
[[nodiscard]] constexpr std::string_view skipReasonToken(SkipReason reason) noexcept
{
    return kSkipReasonTokens[static_cast<std::size_t>(reason)];
}

/**
 * @struct Entry
 * @brief filesystem snapshot used by the pure folder policy.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * scanProtectedFolder supplies root-relative paths; processFolderPlan revalidates live state
 * before acting. the policy performs no I/O.
 */
struct Entry
{
    /**
     * path relative to the protected root. rules compare it after
     * `lexically_normal()`, with generic separators, ASCII case-insensitively.
     */
    std::filesystem::path relativePath;
    std::uintmax_t size = 0;       ///< size in bytes; 0 when the scan could not read it.
    bool symlink = false;          ///< Entry is a reparse point: symlink, junction or mount.
    bool credentialVault = false;  ///< Entry carries the seal vault magic.
};

/**
 * @struct PolicyContext
 * @brief application names protected by folder policy.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * overrides replace the default names rather than adding to them.
 */
struct PolicyContext
{
    /// only the parent directory is used by deployment preflight; skip rules match .exe extensions.
    std::filesystem::path executableRelativePath{"seal.exe"};
    /// marker file that records the folder as unprotected. always AppRuntime.
    std::filesystem::path markerRelativePath{".seal-folder-unprotected"};
    /**
     * protects this path and its .tmp sibling. the default must match
     * kProtectedFolderProfileFileName; a mismatch can encrypt the live verifier.
     */
    std::filesystem::path profileRelativePath{".seal-folder-profile"};
};

/**
 * @struct FolderPlan
 * @brief ordered actionable and protected entries.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * an input appears in at most one vector. encryption includes every input; decryption omits
 * unprotected plaintext from both.
 */
struct FolderPlan
{
    /// entries the operation will transform.
    std::vector<Entry> act;
    /// protected entries paired with the reason to report.
    std::vector<std::pair<Entry, SkipReason>> skipped;

    /// total actionable bytes; unreadable sizes contribute zero.
    [[nodiscard]] std::uintmax_t totalBytes() const noexcept
    {
        std::uintmax_t total = 0;
        for (const Entry& entry : act)
        {
            total += entry.size;
        }
        return total;
    }
};

/**
 * @struct OutputConflict
 * @brief a planned encryption output or staging path that is already occupied.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct OutputConflict
{
    Entry source;    ///< Entry planEncrypt() would transform.
    Entry occupied;  ///< inventory entry already holding the output or `.tmp` path.
};

namespace detail
{

[[nodiscard]] inline wchar_t foldAscii(wchar_t ch) noexcept
{
    if (ch >= L'A' && ch <= L'Z')
    {
        return static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return ch;
}

// compare ASCII-insensitively; non-ASCII units must match exactly.
[[nodiscard]] inline bool equalsAsciiCi(std::wstring_view lhs, std::wstring_view rhs) noexcept
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        if (foldAscii(lhs[i]) != foldAscii(rhs[i]))
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool startsWithAsciiCi(std::wstring_view text,
                                            std::wstring_view prefix) noexcept
{
    return text.size() >= prefix.size() && equalsAsciiCi(text.substr(0, prefix.size()), prefix);
}

[[nodiscard]] inline bool endsWithAsciiCi(std::wstring_view text, std::wstring_view suffix) noexcept
{
    return text.size() >= suffix.size() &&
           equalsAsciiCi(text.substr(text.size() - suffix.size()), suffix);
}

// normalize separators and ASCII case; empty paths match the root directory.
[[nodiscard]] inline bool sameRelativePath(const std::filesystem::path& lhs,
                                           const std::filesystem::path& rhs)
{
    return equalsAsciiCi(lhs.lexically_normal().generic_wstring(),
                         rhs.lexically_normal().generic_wstring());
}

// use the same normalized equivalence as sameRelativePath().
[[nodiscard]] inline std::wstring relativePathKey(const std::filesystem::path& path)
{
    std::wstring key = path.lexically_normal().generic_wstring();
    for (wchar_t& ch : key)
    {
        ch = foldAscii(ch);
    }
    return key;
}

// first non-empty, non-dot component after normalization; nullopt if absent.
[[nodiscard]] inline std::optional<std::wstring> firstPathComponent(
    const std::filesystem::path& path)
{
    for (const auto& component : path.lexically_normal())
    {
        const std::wstring value = component.wstring();
        if (!value.empty() && value != L".")
        {
            return value;
        }
    }
    return std::nullopt;
}

// protect top-level Qt directories only: qml/user.qml is runtime data;
// documents/qml/user-data.txt remains user data.
[[nodiscard]] inline bool isInQtDeployDirectory(const std::filesystem::path& relativePath)
{
    static constexpr std::array<std::wstring_view, 9> kQtDeployDirectories{
        L"qml",
        L"platforms",
        L"imageformats",
        L"iconengines",
        L"networkinformation",
        L"tls",
        L"generic",
        L"qmltooling",
        L"translations",
    };

    const auto first = firstPathComponent(relativePath);
    if (!first)
    {
        return false;
    }
    for (std::wstring_view protectedDirectory : kQtDeployDirectories)
    {
        if (equalsAsciiCi(*first, protectedDirectory))
        {
            return true;
        }
    }
    return false;
}

// match com.seal.fill*.json basenames in any directory.
[[nodiscard]] inline bool isNativeMessagingManifest(const std::filesystem::path& relativePath)
{
    const std::wstring fileName = relativePath.filename().wstring();
    return startsWithAsciiCi(fileName, L"com.seal.fill") && endsWithAsciiCi(fileName, L".json");
}

// protect context marker/profile/staging, qt.conf and executable/library/debug extensions.
[[nodiscard]] inline bool isAppRuntime(const Entry& entry, const PolicyContext& context)
{
    if (sameRelativePath(entry.relativePath, context.markerRelativePath))
    {
        return true;
    }
    if (sameRelativePath(entry.relativePath, context.profileRelativePath))
    {
        return true;
    }

    std::filesystem::path profileTemporary = context.profileRelativePath;
    profileTemporary += L".tmp";
    if (sameRelativePath(entry.relativePath, profileTemporary))
    {
        return true;
    }

    const std::wstring fileName = entry.relativePath.filename().wstring();
    if (equalsAsciiCi(fileName, L"qt.conf"))
    {
        return true;
    }

    const std::wstring extension = entry.relativePath.extension().wstring();
    return equalsAsciiCi(extension, L".exe") || equalsAsciiCi(extension, L".dll") ||
           equalsAsciiCi(extension, L".pdb");
}

// first matching SkipReason, or nullopt; planners apply their .seal rule afterward.
[[nodiscard]] inline std::optional<SkipReason> commonSkipReason(const Entry& entry,
                                                                const PolicyContext& context)
{
    if (entry.symlink)
    {
        return SkipReason::Symlink;
    }
    if (isInQtDeployDirectory(entry.relativePath))
    {
        return SkipReason::QtDeployDir;
    }
    if (entry.credentialVault)
    {
        return SkipReason::CredentialVault;
    }
    if (isNativeMessagingManifest(entry.relativePath))
    {
        return SkipReason::NativeMessagingManifest;
    }
    if (endsWithAsciiCi(entry.relativePath.filename().wstring(), L".zombielock"))
    {
        return SkipReason::Lockfile;
    }
    if (isAppRuntime(entry, context))
    {
        return SkipReason::AppRuntime;
    }
    return std::nullopt;
}

}  // namespace detail

/**
 * @brief select unprotected plaintext from an inventory without I/O.
 * @ingroup Vault
 *
 * common skip rules run first; remaining .seal entries receive AlreadyEncrypted.
 *
 * @return act and skipped partition the input while preserving its order.
 */
[[nodiscard]] inline FolderPlan planEncrypt(std::span<const Entry> entries,
                                            const PolicyContext& context)
{
    FolderPlan plan;
    plan.act.reserve(entries.size());
    plan.skipped.reserve(entries.size());

    for (const Entry& entry : entries)
    {
        if (const auto reason = detail::commonSkipReason(entry, context))
        {
            plan.skipped.emplace_back(entry, *reason);
            continue;
        }
        if (detail::equalsAsciiCi(entry.relativePath.extension().wstring(), L".seal"))
        {
            plan.skipped.emplace_back(entry, SkipReason::AlreadyEncrypted);
            continue;
        }
        plan.act.push_back(entry);
    }
    return plan;
}

/**
 * @brief select unprotected .seal entries without I/O.
 * @ingroup Vault
 *
 * | entry                 | destination    |
 * |-----------------------|----------------|
 * | protected             | skipped        |
 * | unprotected .seal     | act            |
 * | unprotected plaintext | neither vector |
 *
 * input order is preserved. AlreadyEncrypted is never emitted.
 */
[[nodiscard]] inline FolderPlan planDecrypt(std::span<const Entry> entries,
                                            const PolicyContext& context)
{
    FolderPlan plan;
    plan.act.reserve(entries.size());
    plan.skipped.reserve(entries.size());

    for (const Entry& entry : entries)
    {
        if (const auto reason = detail::commonSkipReason(entry, context))
        {
            plan.skipped.emplace_back(entry, *reason);
            continue;
        }
        if (detail::equalsAsciiCi(entry.relativePath.extension().wstring(), L".seal"))
        {
            plan.act.push_back(entry);
        }
    }
    return plan;
}

/**
 * @brief detect occupied encryption destinations and deterministic staging names.
 * @ingroup Vault
 *
 * checks both `<source>.seal` and `<source>.seal.tmp` against the entire inventory, including
 * protected entries, using ASCII-insensitive normalized path keys. execution repeats the check.
 *
 * @return one conflict per occupied path, in encryption-plan order, destination before staging.
 */
[[nodiscard]] inline std::vector<OutputConflict> findEncryptOutputConflicts(
    std::span<const Entry> entries, const PolicyContext& context)
{
    std::unordered_map<std::wstring, const Entry*> byPath;
    byPath.reserve(entries.size());
    for (const Entry& entry : entries)
    {
        byPath.try_emplace(detail::relativePathKey(entry.relativePath), &entry);
    }

    const FolderPlan plan = planEncrypt(entries, context);
    std::vector<OutputConflict> conflicts;
    for (const Entry& source : plan.act)
    {
        std::filesystem::path destination = source.relativePath;
        destination += L".seal";
        std::filesystem::path temporary = destination;
        temporary += L".tmp";

        for (const std::filesystem::path& occupiedPath : {destination, temporary})
        {
            const auto occupied = byPath.find(detail::relativePathKey(occupiedPath));
            if (occupied != byPath.end())
            {
                conflicts.push_back({source, *occupied->second});
            }
        }
    }
    return conflicts;
}

/**
 * @brief reject dynamic Qt deployments before arming folder protection.
 * @ingroup Vault
 *
 * only a sibling Qt6Core.dll beside the executable is checked, ignoring ASCII case.
 * links with that name also fail the check; portable protection requires a static deployment.
 */
[[nodiscard]] inline bool deploymentPreflightPasses(std::span<const Entry> entries,
                                                    const PolicyContext& context)
{
    const std::filesystem::path executableDirectory =
        context.executableRelativePath.parent_path().lexically_normal();
    for (const Entry& entry : entries)
    {
        if (detail::sameRelativePath(entry.relativePath.parent_path(), executableDirectory) &&
            detail::equalsAsciiCi(entry.relativePath.filename().wstring(), L"Qt6Core.dll"))
        {
            return false;
        }
    }
    return true;
}

}  // namespace seal::protected_folder
