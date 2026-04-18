#include "Diagnostics.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <sstream>

namespace
{

std::atomic<unsigned long long> g_NextOpId{1};

std::string trimScope(std::string_view scope)
{
    std::string result;
    result.reserve(scope.size());

    for (unsigned char ch : scope)
    {
        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))
        {
            result.push_back(static_cast<char>(ch));
        }
        else if ((ch >= 'A' && ch <= 'Z'))
        {
            result.push_back(static_cast<char>(std::tolower(ch)));
        }
        else if (ch == '_' || ch == '-')
        {
            result.push_back(static_cast<char>(ch));
        }
    }

    if (result.empty())
        return "op";
    return result;
}

std::string extToken(std::string_view path)
{
    try
    {
        const std::filesystem::path fsPath(path);
        const std::string ext = fsPath.extension().string();
        if (ext.empty())
            return "none";
        return seal::diag::sanitizeAscii(ext, 16);
    }
    catch (...)
    {
        return "unknown";
    }
}

size_t baseLen(std::string_view path)
{
    try
    {
        const std::filesystem::path fsPath(path);
        return fsPath.filename().string().size();
    }
    catch (...)
    {
        return 0;
    }
}

std::string loweredAscii(std::string_view text)
{
    std::string result;
    result.reserve(text.size());
    for (unsigned char ch : text)
    {
        if (ch < 128)
            result.push_back(static_cast<char>(std::tolower(ch)));
    }
    return result;
}

std::string normalizeValueToken(std::string_view value)
{
    const std::string ascii = seal::diag::sanitizeAscii(value, 192);

    std::string out;
    out.reserve(ascii.size());
    for (unsigned char ch : ascii)
    {
        const bool alphaNum =
            (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
        const bool allowedPunct =
            ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == ':' || ch == '+';

        if (alphaNum || allowedPunct)
        {
            out.push_back(static_cast<char>(ch));
        }
        else if (ch == ' ')
        {
            out.push_back('_');
        }
        else
        {
            out.push_back('?');
        }
    }

    if (out.empty())
        return "none";
    return out;
}

}  // namespace

namespace seal::diag
{

std::string nextOpId(std::string_view scope)
{
    const unsigned long long next = g_NextOpId.fetch_add(1, std::memory_order_relaxed);

    std::ostringstream out;
    out << trimScope(scope) << '-' << std::setfill('0') << std::setw(6) << next;
    return out.str();
}

std::string sanitizeAscii(std::string_view text, size_t maxLen)
{
    std::string out;
    out.reserve(std::min(text.size(), maxLen));

    for (unsigned char ch : text)
    {
        if (out.size() >= maxLen)
            break;

        if (ch >= 32 && ch <= 126)
        {
            out.push_back(static_cast<char>(ch));
        }
        else
        {
            out.push_back('?');
        }
    }

    if (out.empty())
        return "none";

    if (text.size() > maxLen && maxLen >= 3)
    {
        out.resize(maxLen - 3);
        out += "...";
    }
    return out;
}

std::string pathSummary(std::string_view path)
{
    std::string kind = "opaque";
    if (path.empty())
    {
        kind = "empty";
    }
    else if (path == "-")
    {
        kind = "stdin";
    }
    else if (!path.empty() && (path.back() == '\\' || path.back() == '/'))
    {
        kind = "dir_hint";
    }
    else if (extToken(path) != "none")
    {
        kind = "file_hint";
    }

    return joinFields({kv("kind", kind),
                       kv("path_len", path.size()),
                       kv("base_len", baseLen(path)),
                       kv("ext", extToken(path))});
}

std::string pathSummary(std::string_view path, std::string_view prefix)
{
    const std::string keyPrefix = normalizeValueToken(prefix);
    std::string kind = "opaque";
    if (path.empty())
    {
        kind = "empty";
    }
    else if (path == "-")
    {
        kind = "stdin";
    }
    else if (!path.empty() && (path.back() == '\\' || path.back() == '/'))
    {
        kind = "dir_hint";
    }
    else if (extToken(path) != "none")
    {
        kind = "file_hint";
    }

    return joinFields({kv(keyPrefix + "_kind", kind),
                       kv(keyPrefix + "_path_len", path.size()),
                       kv(keyPrefix + "_base_len", baseLen(path)),
                       kv(keyPrefix + "_ext", extToken(path))});
}

std::string reasonFromMessage(std::string_view message)
{
    const std::string lowered = loweredAscii(message);

    if (lowered.find("wrong password") != std::string::npos)
        return "wrong_password";
    if (lowered.find("authentication") != std::string::npos ||
        lowered.find("auth failed") != std::string::npos)
        return "auth_failed";
    if (lowered.find("timeout") != std::string::npos)
        return "timeout";
    if (lowered.find("cannot open") != std::string::npos ||
        lowered.find("failed to open") != std::string::npos)
        return "open_failed";
    if (lowered.find("rename") != std::string::npos)
        return "rename_failed";
    if (lowered.find("invalid") != std::string::npos)
        return "invalid_input";
    if (lowered.find("unsupported") != std::string::npos)
        return "unsupported_format";
    if (lowered.find("truncated") != std::string::npos ||
        lowered.find("corrupt") != std::string::npos ||
        lowered.find("malformed") != std::string::npos ||
        lowered.find("bad magic") != std::string::npos ||
        lowered.find("payload too short") != std::string::npos)
        return "corrupt_data";
    if (lowered.find("no data") != std::string::npos || lowered.find("empty") != std::string::npos)
        return "empty_input";
    return "exception";
}

std::string kv(std::string_view key, std::string_view value)
{
    std::string out;
    const std::string safeValue = normalizeValueToken(value);
    out.reserve(key.size() + safeValue.size() + 1);
    out.append(key);
    out.push_back('=');
    out.append(safeValue);
    return out;
}

std::string kv(std::string_view key, const std::string& value)
{
    return kv(key, std::string_view(value));
}

std::string kv(std::string_view key, bool value)
{
    return kv(key, std::string_view(value ? "true" : "false"));
}

std::string kv(std::string_view key, int value)
{
    return kv(key, std::to_string(value));
}

std::string kv(std::string_view key, unsigned int value)
{
    return kv(key, std::to_string(value));
}

std::string kv(std::string_view key, long long value)
{
    return kv(key, std::to_string(value));
}

std::string kv(std::string_view key, unsigned long long value)
{
    return kv(key, std::to_string(value));
}

std::string kv(std::string_view key, double value, int precision)
{
    std::ostringstream out;
    out << std::fixed << std::setprecision(precision) << value;
    return kv(key, out.str());
}

std::string joinFields(std::initializer_list<std::string> fields)
{
    std::string out;
    bool first = true;
    for (const auto& field : fields)
    {
        if (field.empty())
            continue;
        if (!first)
            out.push_back(' ');
        out.append(field);
        first = false;
    }
    return out;
}

}  // namespace seal::diag
