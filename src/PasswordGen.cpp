#include "PasswordGen.hpp"

#include <openssl/rand.h>

#include <windows.h>

#include <algorithm>
#include <stdexcept>

namespace seal
{

secure_string<> GeneratePassword(int length)
{
    length = std::clamp(length, 8, 128);

    static constexpr char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    static constexpr int charsetLen = sizeof(charset) - 1;

    // Rejection sampling: `limit` is the largest multiple of charsetLen
    // that fits in a byte (truncating integer division).
    static constexpr unsigned char limit =
        static_cast<unsigned char>((256 / charsetLen) * charsetLen);

    secure_string<> password;
    password.reserve(static_cast<size_t>(length));

    unsigned char rndBuf[128];
    int filled = 0;
    while (filled < length)
    {
        int need = length - filled;
        // Over-request to amortise RAND_bytes calls; ~89% acceptance at
        // charsetLen=76 (228/256 useful bytes).
        int request = std::min(need * 2, static_cast<int>(sizeof(rndBuf)));
        if (RAND_bytes(rndBuf, request) != 1)
            throw std::runtime_error("RAND_bytes failed");
        for (int i = 0; i < request && filled < length; ++i)
        {
            if (rndBuf[i] < limit)
            {
                password.push_back(charset[rndBuf[i] % charsetLen]);
                ++filled;
            }
        }
    }
    SecureZeroMemory(rndBuf, sizeof(rndBuf));

    return password;
}

}  // namespace seal
