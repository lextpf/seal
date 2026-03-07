/**
 * @file Vault.cpp
 * @brief Vault file management implementation for seal
 * @author seal Contributors
 * @date 2024
 */

#ifdef USE_QT_UI

#include "Vault.h"

#include "Cryptography.h"
#include "FileOperations.h"
#include "Logging.h"
#include "Utils.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QString>

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

static std::string qstringToStd(const QString& qstr)
{
    QByteArray bytes = qstr.toLocal8Bit();
    return std::string(bytes.constData(), bytes.size());
}

static std::string wcharToUtf8(const wchar_t* data, size_t len)
{
    if (!data || len == 0)
        return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, data, (int)len, nullptr, 0, nullptr, nullptr);
    std::string out(need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, data, (int)len, out.data(), need, nullptr, nullptr);
    return out;
}

static seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> utf8ToSecureWide(
    const std::string& utf8)
{
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> result;
    if (utf8.empty())
        return result;
    int need = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (need > 0)
    {
        result.s.resize(need);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), result.s.data(), need);
    }
    return result;
}

namespace seal
{

void DecryptedCredential::cleanse()
{
    seal::Cryptography::cleanseString(m_Username, m_Password);
}

static std::vector<unsigned char> encryptString(
    const std::string& plaintext,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword)
{
    return seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(plaintext.data()),
                                       plaintext.size()),
        masterPassword);
}

static std::string decryptToString(
    const std::vector<unsigned char>& packet,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    auto plainBytes =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);
    std::string result(reinterpret_cast<const char*>(plainBytes.data()), plainBytes.size());
    seal::Cryptography::cleanseString(plainBytes);
    return result;
}

std::vector<VaultRecord> loadVaultIndex(
    const QString& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    qCInfo(logVault) << "loadVaultIndex:" << QFileInfo(vaultPath).fileName();
    std::ifstream in(qstringToStd(vaultPath), std::ios::in);
    if (!in)
    {
        qCWarning(logVault) << "loadVaultIndex: cannot open file";
        throw std::runtime_error("Cannot open vault file");
    }

    std::vector<VaultRecord> records;
    std::string line;
    int decryptAttempted = 0;

    while (std::getline(in, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        if (line.empty())
            continue;

        auto sepPos = line.find(':');
        if (sepPos == std::string::npos)
            sepPos = line.find('|');  // backwards compat with v1 vaults
        if (sepPos == std::string::npos)
            continue;

        std::string platformHex = line.substr(0, sepPos);
        std::string credHex = line.substr(sepPos + 1);

        std::vector<unsigned char> platformBlob, credBlob;
        if (!seal::utils::from_hex(platformHex, platformBlob))
            continue;
        if (!seal::utils::from_hex(credHex, credBlob))
            continue;

        try
        {
            ++decryptAttempted;
            std::string platformName = decryptToString(platformBlob, password);

            VaultRecord rec;
            rec.m_Platform = std::move(platformName);
            rec.m_EncryptedPlatform = std::move(platformBlob);
            rec.m_EncryptedBlob = std::move(credBlob);
            rec.m_Dirty = false;
            rec.m_Deleted = false;
            records.push_back(std::move(rec));
        }
        catch (...)
        {
            continue;
        }
    }

    if (decryptAttempted > 0 && records.empty())
    {
        qCWarning(logVault) << "loadVaultIndex: wrong password (parsed" << decryptAttempted
                            << "record(s), 0 decrypted)";
        throw std::runtime_error("Wrong password");
    }

    qCInfo(logVault) << "loadVaultIndex: parsed" << records.size() << "record(s) from"
                     << decryptAttempted << "line(s)";
    return records;
}

bool saveVaultV2(
    const QString& vaultPath,
    const std::vector<VaultRecord>& records,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    qCInfo(logVault) << "saveVaultV2:" << QFileInfo(vaultPath).fileName()
                     << "records=" << records.size();
    std::ofstream out(qstringToStd(vaultPath), std::ios::out | std::ios::trunc);
    if (!out)
    {
        qCWarning(logVault) << "saveVaultV2: cannot open file for writing";
        return false;
    }

    for (const auto& rec : records)
    {
        if (rec.m_Deleted)
            continue;

        // Use existing encrypted platform if available, otherwise encrypt it
        std::vector<unsigned char> platformBlob;
        if (!rec.m_EncryptedPlatform.empty() && !rec.m_Dirty)
        {
            platformBlob = rec.m_EncryptedPlatform;
        }
        else
        {
            platformBlob = encryptString(rec.m_Platform, password);
        }

        out << seal::utils::to_hex(platformBlob) << ":" << seal::utils::to_hex(rec.m_EncryptedBlob)
            << "\n";
    }

    bool ok = out.good();
    if (ok)
        qCInfo(logVault) << "saveVaultV2: success";
    else
        qCWarning(logVault) << "saveVaultV2: write error";
    return ok;
}

DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    qCDebug(logVault) << "decryptCredentialOnDemand: platform=" << record.m_Platform.c_str();
    auto plainBytes = seal::Cryptography::decryptPacket(
        std::span<const unsigned char>(record.m_EncryptedBlob), password);

    const char* data = reinterpret_cast<const char*>(plainBytes.data());
    size_t len = plainBytes.size();

    size_t sep = len;
    for (size_t i = 0; i < len; ++i)
    {
        if (data[i] == '\0')
        {
            sep = i;
            break;
        }
    }

    std::string userUtf8(data, sep);
    std::string passUtf8;
    if (sep + 1 < len)
    {
        passUtf8.assign(data + sep + 1, len - sep - 1);
    }
    seal::Cryptography::cleanseString(plainBytes);

    DecryptedCredential cred;
    cred.m_Username = utf8ToSecureWide(userUtf8);
    cred.m_Password = utf8ToSecureWide(passUtf8);
    seal::Cryptography::cleanseString(userUtf8, passUtf8);
    return cred;
}

VaultRecord encryptCredential(
    const std::string& platform,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword)
{
    qCDebug(logVault) << "encryptCredential: platform=" << platform.c_str();
    std::string userUtf8 = wcharToUtf8(username.data(), username.size());
    std::string passUtf8 = wcharToUtf8(password.data(), password.size());

    std::string credPlain;
    credPlain.reserve(userUtf8.size() + 1 + passUtf8.size());
    credPlain.append(userUtf8);
    credPlain.push_back('\0');
    credPlain.append(passUtf8);
    seal::Cryptography::cleanseString(userUtf8, passUtf8);

    auto credBlob = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(credPlain.data()),
                                       credPlain.size()),
        masterPassword);
    seal::Cryptography::cleanseString(credPlain);

    auto platformBlob = encryptString(platform, masterPassword);

    VaultRecord rec;
    rec.m_Platform = platform;
    rec.m_EncryptedPlatform = std::move(platformBlob);
    rec.m_EncryptedBlob = std::move(credBlob);
    rec.m_Dirty = true;
    rec.m_Deleted = false;
    return rec;
}

int encryptDirectory(
    const QString& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    std::string path = qstringToStd(dirPath);
    int count = 0;

    qCInfo(logVault) << "encryptDirectory:" << dirPath;
    try
    {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(path))
        {
            if (!entry.is_regular_file())
                continue;
            std::string filePath = entry.path().string();

            std::string lowerPath = filePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
            if (lowerPath.ends_with(".seal") || lowerPath.ends_with(".seal") ||
                lowerPath.ends_with(".exe") || lowerPath.ends_with(".dll") ||
                lowerPath.ends_with(".pdb"))
            {
                continue;
            }

            if (FileOperations::encryptFileInPlace(filePath.c_str(), password))
            {
                std::string newPath = filePath + ".seal";
                if (std::filesystem::exists(newPath))
                    std::filesystem::remove(newPath);
                std::filesystem::rename(filePath, newPath);
                count++;
            }
        }
    }
    catch (const std::exception& e)
    {
        qCWarning(logVault) << "encryptDirectory: error:" << e.what();
    }

    qCInfo(logVault) << "encryptDirectory: encrypted" << count << "file(s)";
    return count;
}

int decryptDirectory(
    const QString& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    std::string path = qstringToStd(dirPath);
    int count = 0;

    qCInfo(logVault) << "decryptDirectory:" << dirPath;
    try
    {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(path))
        {
            if (!entry.is_regular_file())
                continue;
            std::string filePath = entry.path().string();

            std::string lowerPath = filePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
            if (!lowerPath.ends_with(".seal"))
                continue;

            if (FileOperations::decryptFileInPlace(filePath.c_str(), password))
            {
                std::string newPath = filePath.substr(0, filePath.size() - 5);
                if (std::filesystem::exists(newPath))
                    std::filesystem::remove(newPath);
                std::filesystem::rename(filePath, newPath);
                count++;
            }
        }
    }
    catch (const std::exception& e)
    {
        qCWarning(logVault) << "decryptDirectory: error:" << e.what();
    }

    qCInfo(logVault) << "decryptDirectory: decrypted" << count << "file(s)";
    return count;
}

}  // namespace seal

#endif  // USE_QT_UI
