/**
 * @file test_helpers.h
 * @brief Shared test helper functions for seal tests
 * @author seal Contributors
 * @date 2024
 */

#pragma once

// Include headers to access internal functions
#include "../src/Clipboard.h"
#include "../src/Console.h"
#include "../src/Cryptography.h"
#include "../src/FileOperations.h"
#include "../src/Utils.h"

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
