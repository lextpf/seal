#include "CredentialCsv.hpp"

#include "UrlBinding.hpp"

#include <algorithm>
#include <cctype>

namespace
{

// RFC 4180 tokenizer: emits rows of fields; quotes, doubled-quote escapes,
// and embedded separators per the spec; tolerates LF-only endings and a
// missing final newline. Blank lines are skipped.
std::vector<std::vector<std::string>> parseRows(std::string_view content)
{
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string field;
    bool inQuotes = false;
    bool fieldStarted = false;

    auto endField = [&]()
    {
        row.push_back(std::move(field));
        field.clear();
        fieldStarted = false;
    };
    auto endRow = [&]()
    {
        endField();
        if (!(row.size() == 1 && row[0].empty()))
        {
            rows.push_back(std::move(row));
        }
        row.clear();
    };

    for (size_t i = 0; i < content.size(); ++i)
    {
        const char c = content[i];
        if (inQuotes)
        {
            if (c == '"')
            {
                if (i + 1 < content.size() && content[i + 1] == '"')
                {
                    field.push_back('"');
                    ++i;
                }
                else
                {
                    inQuotes = false;
                }
            }
            else
            {
                field.push_back(c);
            }
            continue;
        }
        if (c == '"' && !fieldStarted && field.empty())
        {
            inQuotes = true;
            fieldStarted = true;
        }
        else if (c == ',')
        {
            endField();
        }
        else if (c == '\r')
        {
            // Swallow; the following '\n' (if any) ends the row.
            if (i + 1 >= content.size() || content[i + 1] != '\n')
            {
                endRow();
            }
        }
        else if (c == '\n')
        {
            endRow();
        }
        else
        {
            field.push_back(c);
            fieldStarted = true;
        }
    }
    if (fieldStarted || !field.empty() || !row.empty())
    {
        endRow();
    }
    return rows;
}

std::string asciiLower(std::string_view s)
{
    std::string out(s);
    std::transform(out.begin(),
                   out.end(),
                   out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string_view stripBom(std::string_view s)
{
    if (s.size() >= 3 && s.substr(0, 3) == "\xEF\xBB\xBF")
    {
        return s.substr(3);
    }
    return s;
}

bool fieldNeedsQuoting(std::string_view f)
{
    return f.find_first_of(",\"\r\n") != std::string_view::npos;
}

}  // namespace

namespace seal::csv
{

bool LooksLikeChromeCsv(std::string_view firstLine)
{
    std::string_view line = stripBom(firstLine);
    if (const auto cr = line.find('\r'); cr != std::string_view::npos)
    {
        line = line.substr(0, cr);
    }
    const std::string lower = asciiLower(line);
    return lower.find("name") != std::string::npos && lower.find("url") != std::string::npos &&
           lower.find("username") != std::string::npos &&
           lower.find("password") != std::string::npos && lower.find(',') != std::string::npos &&
           lower.find(':') == std::string::npos;
}

bool ParseChromeCsv(std::string_view content, std::vector<Credential>& out, Stats& stats)
{
    content = stripBom(content);
    const auto rows = parseRows(content);
    if (rows.empty())
    {
        return false;
    }

    // Column lookup from the header row (case-insensitive, extras ignored).
    int colName = -1;
    int colUrl = -1;
    int colUser = -1;
    int colPass = -1;
    for (int c = 0; c < static_cast<int>(rows[0].size()); ++c)
    {
        const std::string h = asciiLower(rows[0][static_cast<size_t>(c)]);
        if (h == "name")
        {
            colName = c;
        }
        else if (h == "url")
        {
            colUrl = c;
        }
        else if (h == "username")
        {
            colUser = c;
        }
        else if (h == "password")
        {
            colPass = c;
        }
    }
    if (colName < 0 || colUrl < 0 || colUser < 0 || colPass < 0)
    {
        return false;
    }

    auto cell = [](const std::vector<std::string>& row, int col) -> std::string_view
    {
        if (col < 0 || col >= static_cast<int>(row.size()))
        {
            return {};
        }
        return row[static_cast<size_t>(col)];
    };

    const int maxNeeded = std::max({colName, colUrl, colUser, colPass});
    for (size_t r = 1; r < rows.size(); ++r)
    {
        const auto& row = rows[r];
        if (static_cast<int>(row.size()) <= maxNeeded)
        {
            ++stats.badRows;
            continue;
        }
        Credential cred;
        cred.platform = std::string(cell(row, colName));
        if (cred.platform.empty())
        {
            cred.platform = seal::url::extractHost(cell(row, colUrl));
        }
        cred.username = std::string(cell(row, colUser));
        cred.password = std::string(cell(row, colPass));

        if (cred.platform.empty())
        {
            ++stats.skippedNoPlatform;
            continue;
        }
        if (cred.password.empty())
        {
            ++stats.skippedNoPassword;
            continue;
        }
        ++stats.imported;
        out.push_back(std::move(cred));
    }
    return true;
}

std::string WriteCsvRow(std::initializer_list<std::string_view> fields)
{
    std::string row;
    bool first = true;
    for (std::string_view f : fields)
    {
        if (!first)
        {
            row.push_back(',');
        }
        first = false;
        if (fieldNeedsQuoting(f))
        {
            row.push_back('"');
            for (char c : f)
            {
                if (c == '"')
                {
                    row.push_back('"');
                }
                row.push_back(c);
            }
            row.push_back('"');
        }
        else
        {
            row.append(f);
        }
    }
    row.append("\r\n");
    return row;
}

}  // namespace seal::csv
