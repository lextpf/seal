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
 * @brief Stable telemetry reason for excluding an entry from a folder plan.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * The enum and its tokens are append-only: log consumers and support tooling
 * read the token spelling to explain why an entry was protected from directory
 * encryption or decryption. Never renumber an enumerator and never respell a
 * token; append new pairs at the end.
 *
 * @par Reporting precedence
 * Several rules can match one entry. detail::commonSkipReason() returns the
 * first match in this fixed order, and that is the token diagnostics show:
 * @verbatim
 *   1 Symlink                  entry.symlink is set
 *   2 QtDeployDir              first path component is a Qt deploy directory
 *   3 CredentialVault          entry.credentialVault is set
 *   4 NativeMessagingManifest  file name "com.seal.fill*.json"
 *   5 Lockfile                 file name ends in ".zombielock"
 *   6 AppRuntime               marker, profile, profile + ".tmp", "qt.conf",
 *                              or an ".exe" / ".dll" / ".pdb" extension
 * @endverbatim
 * AlreadyEncrypted is outside this ladder: planEncrypt() applies it only after
 * the ladder finds no match, and planDecrypt() never reports it.
 */
enum class SkipReason : std::uint8_t
{
    AppRuntime = 0,               ///< Application, runtime or folder-state file.
    QtDeployDir = 1,              ///< Inside a top-level Qt deployment directory.
    NativeMessagingManifest = 2,  ///< Chromium native-messaging host manifest.
    CredentialVault = 3,          ///< File the scan identified as a seal vault.
    AlreadyEncrypted = 4,         ///< Encrypt plan only: the name already ends in `.seal`.
    Symlink = 5,                  ///< Reparse point: symlink, junction or mount point.
    Lockfile = 6,                 ///< Runtime lock file (`*.zombielock`).
};

/// Telemetry token for each SkipReason, indexed by the enumerator value. The
/// spelling is a stable contract. The static_assert below only checks that the
/// array length still matches the last enumerator; a new pair must be appended
/// to both lists in the same position.
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
 * @brief Return the append-only telemetry token for a skip reason.
 * @ingroup Vault
 *
 * @param reason A declared SkipReason enumerator.
 * @return Token for @p reason. The view points into static storage and stays
 *         valid for the life of the process.
 *
 * @pre @p reason is one of the declared enumerators. The lookup is an
 *      unchecked `std::array` index, so a value cast in from outside that set
 *      reads out of bounds.
 */
[[nodiscard]] constexpr std::string_view skipReasonToken(SkipReason reason) noexcept
{
    return kSkipReasonTokens[static_cast<std::size_t>(reason)];
}

/**
 * @struct Entry
 * @brief One filesystem entry as observed by the I/O-facing inventory scan.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * The policy never touches the filesystem. Callers supply paths relative to
 * the protected root plus the metadata needed to make a decision. The
 * inventory that fills these entries comes from seal::scanProtectedFolder() in
 * Vault.hpp, whose documentation holds the pipeline diagram. An entry is a
 * snapshot; the executor, seal::processFolderPlan() in Vault.hpp, revalidates
 * every acted-on entry against live filesystem state before it transforms
 * anything.
 */
struct Entry
{
    /// Path relative to the protected root. Rules compare it after
    /// `lexically_normal()`, with generic separators, ASCII case-insensitively.
    std::filesystem::path relativePath;
    std::uintmax_t size = 0;       ///< Size in bytes; 0 when the scan could not read it.
    bool symlink = false;          ///< Entry is a reparse point: symlink, junction or mount.
    bool credentialVault = false;  ///< Entry carries the seal vault magic.
};

/**
 * @struct PolicyContext
 * @brief Inputs whose names depend on the embedding application.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * The defaults describe seal's own portable layout. Overriding a name protects
 * that name instead of the default: no rule hardcodes the default spellings.
 */
struct PolicyContext
{
    /// Executable path relative to the root. Only its parent directory is
    /// read, and only by deploymentPreflightPasses(); the skip rules match
    /// `.exe` by extension instead of by this name.
    std::filesystem::path executableRelativePath{"seal.exe"};
    /// Marker file that records the folder as unprotected. Always AppRuntime.
    std::filesystem::path markerRelativePath{".seal-folder-unprotected"};
    /// Folder password profile. This path and its `.tmp` staging sibling are
    /// both AppRuntime, so arming never encrypts its own verifier. The default
    /// must stay equal to seal::kProtectedFolderProfileFileName in
    /// ProtectedFolderProfile.hpp, the name the write paths enforce. This
    /// header does not include that file, so the two spellings are separate
    /// copies; changing one alone makes arming encrypt the live verifier.
    std::filesystem::path profileRelativePath{".seal-folder-profile"};
};

/**
 * @struct FolderPlan
 * @brief Actionable entries plus protected entries and their stable reasons.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Both vectors keep the order of the input span, and an entry reaches at most
 * one of them. planEncrypt() places every input entry in one of the two;
 * planDecrypt() drops unprotected plaintext from both.
 */
struct FolderPlan
{
    /// Entries the operation will transform.
    std::vector<Entry> act;
    /// Protected entries paired with the reason to report.
    std::vector<std::pair<Entry, SkipReason>> skipped;

    /**
     * @brief Sum the sizes of the actionable entries.
     * @return Bytes across `act` only. `skipped` contributes nothing, and an
     *         entry whose size the scan could not read counts as zero.
     */
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
 * @brief A planned encryption output or staging path that is already occupied.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct OutputConflict
{
    Entry source;    ///< Entry planEncrypt() would transform.
    Entry occupied;  ///< Inventory entry already holding the output or `.tmp` path.
};

namespace detail
{

/// Fold one ASCII upper-case letter to lower case. Every other code unit,
/// including all non-ASCII, is returned unchanged.
[[nodiscard]] inline wchar_t foldAscii(wchar_t ch) noexcept
{
    if (ch >= L'A' && ch <= L'Z')
    {
        return static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return ch;
}

/// Compare two views code unit by code unit, ignoring ASCII letter case only.
/// Non-ASCII code units must match exactly, so a Unicode-cased name never
/// matches a rule spelled in ASCII.
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

/// Prefix test using equalsAsciiCi(). An empty prefix matches every text.
[[nodiscard]] inline bool startsWithAsciiCi(std::wstring_view text,
                                            std::wstring_view prefix) noexcept
{
    return text.size() >= prefix.size() && equalsAsciiCi(text.substr(0, prefix.size()), prefix);
}

/// Suffix test using equalsAsciiCi(). An empty suffix matches every text.
[[nodiscard]] inline bool endsWithAsciiCi(std::wstring_view text, std::wstring_view suffix) noexcept
{
    return text.size() >= suffix.size() &&
           equalsAsciiCi(text.substr(text.size() - suffix.size()), suffix);
}

/// Compare two relative paths after `lexically_normal()`, on generic
/// separators, ignoring ASCII case. Two empty paths compare equal, which is
/// how a root-level entry matches a root-level executable directory.
[[nodiscard]] inline bool sameRelativePath(const std::filesystem::path& lhs,
                                           const std::filesystem::path& rhs)
{
    return equalsAsciiCi(lhs.lexically_normal().generic_wstring(),
                         rhs.lexically_normal().generic_wstring());
}

/// Build the hash-map key for a relative path: normalised, generic
/// separators, ASCII lower-cased. Two paths share a key exactly when
/// sameRelativePath() reports them equal.
[[nodiscard]] inline std::wstring relativePathKey(const std::filesystem::path& path)
{
    std::wstring key = path.lexically_normal().generic_wstring();
    for (wchar_t& ch : key)
    {
        ch = foldAscii(ch);
    }
    return key;
}

/// First component of a normalised path that is neither empty nor `.`.
/// Returns nullopt when the path has no such component.
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

/// True when the first path component names a Qt deployment directory. The
/// test is top-level only on purpose: `qml/user.qml` is protected, while
/// `documents/qml/user-data.txt` is user data and stays actionable.
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

/// True for a native-messaging host manifest, matched on the file name only:
/// prefix `com.seal.fill` plus suffix `.json`, in any directory. This covers
/// the per-browser variants such as `com.seal.fill.brave.json`.
[[nodiscard]] inline bool isNativeMessagingManifest(const std::filesystem::path& relativePath)
{
    const std::wstring fileName = relativePath.filename().wstring();
    return startsWithAsciiCi(fileName, L"com.seal.fill") && endsWithAsciiCi(fileName, L".json");
}

/// True for the application's own files: the context marker, the context
/// profile, the profile's `.tmp` staging sibling, any `qt.conf`, and any
/// `.exe`, `.dll` or `.pdb` extension. Binaries are recognised by extension
/// alone, so `context.executableRelativePath` is not consulted here.
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

/// Apply the rules shared by both planners and return the first match, in the
/// precedence order documented on SkipReason. Returns nullopt when no rule
/// protects the entry. The `.seal` extension is not tested here; each planner
/// applies its own extension rule afterwards.
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
 * @brief Plan plaintext entries to encrypt without performing I/O.
 * @ingroup Vault
 *
 * Arming is the operation that puts a folder under protection: the executor
 * runs this plan over the folder. Every entry runs through
 * detail::commonSkipReason() first. An entry that no rule protects and whose
 * extension is already `.seal` is reported as SkipReason::AlreadyEncrypted, so
 * a second arming run cannot double-encrypt. Everything else is actionable.
 *
 * @param entries Inventory snapshot; paths are relative to the protected root.
 * @param context Names supplied by the embedding application.
 * @return A plan whose `act` and `skipped` together cover every input entry,
 *         in input order.
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
 * @brief Plan encrypted entries to decrypt without performing I/O.
 * @ingroup Vault
 *
 * Only an entry with the `.seal` extension can become actionable. The skip
 * rules run before the extension test, so:
 * - A plaintext entry that no rule protects is outside the decrypt operation
 *   and is absent from both vectors on purpose.
 * - A plaintext entry that a rule protects is still reported in `skipped`.
 * - A protected `.seal` entry stays in `skipped`, so diagnostics can explain
 *   why a credential vault was not decrypted.
 *
 * SkipReason::AlreadyEncrypted is never produced here.
 *
 * @param entries Inventory snapshot; paths are relative to the protected root.
 * @param context Names supplied by the embedding application.
 * @return A plan whose `act` holds only unprotected `.seal` entries, in input
 *         order.
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
 * @brief Find existing paths that would be replaced or used as staging files.
 * @ingroup Vault
 *
 * The transform layer writes `<source>.seal` through a deterministic
 * `<source>.seal.tmp` sibling. Arming must not claim either path is safe to
 * use when it already belongs to the user. The inventory is a snapshot, so the
 * executor repeats this check against live filesystem state.
 *
 * Both candidate paths are looked up across the whole inventory, not only the
 * actionable entries, so a protected `.seal` file still counts as occupied.
 * Lookup uses detail::relativePathKey(), so it is ASCII case-insensitive. One
 * source yields two records when its destination and its staging path are both
 * occupied.
 *
 * @param entries Inventory snapshot; paths are relative to the protected root.
 * @param context Names supplied by the embedding application.
 * @return One record per occupied path, in planEncrypt() order, destination
 *         before staging path. Empty when arming would collide with nothing.
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
 * @brief Whether arming is safe for the supplied deployment inventory.
 * @ingroup Vault
 *
 * A Qt6Core DLL beside the executable means this is a dynamic Qt deployment
 * whose runtime is interleaved with user files. Portable folder protection is
 * deliberately limited to static deployments.
 *
 * Only the executable's own directory is examined, and only the exact file
 * name `Qt6Core.dll`, compared ASCII case-insensitively. The entry's symlink
 * flag is not consulted, so a link named `Qt6Core.dll` also fails the check.
 *
 * @param entries Inventory snapshot; paths are relative to the protected root.
 * @param context Supplies `executableRelativePath`; only its parent directory
 *                is read.
 * @return `false` when a sibling `Qt6Core.dll` is present, `true` otherwise.
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
