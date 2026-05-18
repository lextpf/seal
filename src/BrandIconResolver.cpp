#include "BrandIconResolver.hpp"

#include <array>
#include <cctype>
#include <unordered_map>
#include <vector>

#ifdef USE_QT_UI
#include <QDir>
#include <QDirIterator>
#include <QHash>

#include <mutex>
#endif

namespace seal
{
namespace brand
{

namespace
{

const std::unordered_map<std::string, std::string>& aliasTable()
{
    static const std::unordered_map<std::string, std::string> s_Table = {
        {"x", "x-twitter"},
        {"twitter", "x-twitter"},
        {"btc", "bitcoin"},
        {"signal", "signal-messenger"},
        {"messenger", "facebook-messenger"},
        {"fbmessenger", "facebook-messenger"},
        {"mastercard", "cc-mastercard"},
        {"mc", "cc-mastercard"},
        {"visa", "cc-visa"},
        {"diners", "cc-diners-club"},
        {"dinersclub", "cc-diners-club"},
        {"discover", "cc-discover"},
        {"msedge", "edge"},
        {"microsoftedge", "edge"},
        {"gh", "github"},
        {"githubdesktop", "github"},
        {"psn", "playstation"},
        {"whatsapp", "whatsapp-square"},
        {"wp", "wordpress"},
    };
    return s_Table;
}

constexpr std::array<const char*, 8> kTrailingTlds = {
    "com", "io", "net", "org", "app", "tld", "tv", "ai"};

bool tryDirectOrAlias(const std::string& candidate,
                      const std::function<std::string(const std::string&)>& lookupAsset,
                      std::string& outRealSlug)
{
    if (candidate.empty())
    {
        return false;
    }

    std::string real = lookupAsset(candidate);
    if (!real.empty())
    {
        outRealSlug = std::move(real);
        return true;
    }

    const auto& aliases = aliasTable();
    auto it = aliases.find(candidate);
    if (it != aliases.end())
    {
        const std::string aliasKey = normalizeSlug(it->second);
        std::string aliasReal = lookupAsset(aliasKey);
        if (!aliasReal.empty())
        {
            outRealSlug = std::move(aliasReal);
            return true;
        }
    }

    return false;
}

}  // namespace

std::string normalizeSlug(const std::string& platformName)
{
    std::string out;
    out.reserve(platformName.size());
    for (unsigned char c : platformName)
    {
        if (std::isalnum(c))
        {
            out.push_back(static_cast<char>(std::tolower(c)));
        }
    }
    return out;
}

std::string resolveBrandIconSlug(const std::string& platformName,
                                 const std::function<std::string(const std::string&)>& lookupAsset)
{
    // Tokenize on non-alphanumeric boundaries, lower-cased. The joined
    // form matches normalizeSlug(); keeping tokens lets us retry word-by-
    // word for inputs like "Twitter, Inc." or "Google LLC".
    std::vector<std::string> tokens;
    std::string current;
    for (char c : platformName)
    {
        auto uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc) != 0)
        {
            current += static_cast<char>(std::tolower(uc));
        }
        else if (!current.empty())
        {
            tokens.push_back(std::move(current));
            current.clear();
        }
    }
    if (!current.empty())
    {
        tokens.push_back(std::move(current));
    }
    if (tokens.empty())
    {
        return {};
    }

    std::string joined;
    for (const auto& t : tokens)
    {
        joined += t;
    }

    std::string real;

    if (tryDirectOrAlias(joined, lookupAsset, real))
    {
        return real;
    }

    for (const char* tld : kTrailingTlds)
    {
        const std::size_t tldLen = std::char_traits<char>::length(tld);
        if (joined.size() > tldLen && joined.compare(joined.size() - tldLen, tldLen, tld) == 0)
        {
            const std::string stripped = joined.substr(0, joined.size() - tldLen);
            if (tryDirectOrAlias(stripped, lookupAsset, real))
            {
                return real;
            }
        }
    }

    // Per-token fallback: "Twitter, Inc." -> ["twitter","inc"]; "twitter"
    // aliases to "x-twitter".
    for (const auto& token : tokens)
    {
        if (token == joined)
        {
            continue;
        }
        if (tryDirectOrAlias(token, lookupAsset, real))
        {
            return real;
        }
    }

    return {};
}

#ifdef USE_QT_UI

namespace
{

const QHash<QString, QString>& brandAssetIndex()
{
    static QHash<QString, QString> s_Index;
    static std::once_flag s_Flag;
    std::call_once(s_Flag,
                   []
                   {
                       QDirIterator it(QStringLiteral(":/qt/qml/seal/assets/brands"),
                                       QStringList{QStringLiteral("*.svg")},
                                       QDir::Files);
                       while (it.hasNext())
                       {
                           it.next();
                           const QString base = it.fileInfo().completeBaseName();
                           QString key;
                           key.reserve(base.size());
                           for (QChar ch : base)
                           {
                               if (ch.isLetterOrNumber())
                               {
                                   key.append(ch.toLower());
                               }
                           }
                           if (!key.isEmpty())
                           {
                               s_Index.insert(key, base);
                           }
                       }
                   });
    return s_Index;
}

}  // namespace

QString resolveBrandIconPath(const QString& platformName)
{
    const auto& index = brandAssetIndex();
    auto lookup = [&index](const std::string& candidate) -> std::string
    {
        auto it = index.constFind(QString::fromStdString(candidate));
        if (it == index.constEnd())
        {
            return {};
        }
        return it.value().toStdString();
    };

    const std::string real = resolveBrandIconSlug(platformName.toStdString(), lookup);
    if (real.empty())
    {
        return {};
    }

    return QStringLiteral("qrc:/qt/qml/seal/assets/brands/") + QString::fromStdString(real) +
           QStringLiteral(".svg");
}

#endif  // USE_QT_UI

}  // namespace brand
}  // namespace seal
