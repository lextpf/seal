#pragma once

// Include headers to access internal functions
#include "../src/Clipboard.hpp"
#include "../src/Console.hpp"
#include "../src/Cryptography.hpp"
#include "../src/FileOperations.hpp"
#include "../src/Utils.hpp"

/**
 * @brief Helper to create secure_string from std::string for testing
 * @param s Standard string to convert
 * @return secure_string containing the same data
 */
inline seal::secure_string<> make_secure_string(const std::string& s)
{
    seal::secure_string<> result;
    for (char c : s)
    {
        result.push_back(c);
    }
    return result;
}
