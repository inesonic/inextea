/*-*-c++-*-*************************************************************************************************************
* Copyright 2021 - 2022 Inesonic, LLC.
*
* MIT License:
*   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
*   documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
*   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
*   permit persons to whom the Software is furnished to do so, subject to the following conditions:
*   
*   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
*   Software.
*   
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
*   WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
*   OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
*   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
********************************************************************************************************************//**
* \file
*
* This file implements the IneXTea encryptor and decryptor low level functions.
***********************************************************************************************************************/

#include <cstdint>
#include <cstring>

#include "inextea.h"

namespace IneXtea {
    // The algorithm has been shamelessly lifted from:
    //
    //   http://en.wikipedia.org/wiki/XTEA

    static constexpr std::uint32_t delta = 0x9E3779B9;

    void encrypt(Block block, const Key key, unsigned numberRounds) {
        std::uint32_t*       v   = reinterpret_cast<std::uint32_t*>(block);
        const std::uint32_t* k   = reinterpret_cast<const std::uint32_t*>(key);
        std::uint32_t        sum = 0;

        for (unsigned j=0 ; j<numberRounds ; ++j) {
            v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + k[sum & 3]);
            sum  += delta;
            v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + k[(sum >> 11) & 3]);
        }
    }

    void decrypt(Block block, const Key key, unsigned numberRounds) {
        std::uint32_t*       v   = reinterpret_cast<std::uint32_t*>(block);
        const std::uint32_t* k   = reinterpret_cast<const std::uint32_t*>(key);
        std::uint32_t        sum = numberRounds * delta;

        for (unsigned j=0 ; j<numberRounds ; ++j) {
            v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + k[(sum >> 11) & 3]);
            sum  -= delta;
            v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + k[sum & 3]);
        }
    }


    void toCustomerIdentifier(Block customerIdentifier, unsigned long customerId, const Key key) {
        std::uint32_t* b = reinterpret_cast<std::uint32_t*>(customerIdentifier);
        b[1] = static_cast<std::uint32_t>(customerId);
        b[0] = static_cast<std::uint32_t>(0x18BA3187UL * b[1] + 0x1AC2F23BUL);

        encrypt(customerIdentifier, key, defaultFeistelRounds);
    }


    unsigned long toCustomerId(const Block customerIdentifier, const Key key) {
        Block volatileBlock;
        std::memcpy(volatileBlock, customerIdentifier, blockLength);

        decrypt(volatileBlock, key, defaultFeistelRounds);

        std::uint32_t* b = reinterpret_cast<std::uint32_t*>(volatileBlock);
        std::uint32_t checkValue         = b[0];
        std::uint32_t customerId         = b[1];
        std::uint32_t expectedCheckValue = static_cast<std::uint32_t>(0x18BA3187UL * customerId + 0x1AC2F23BUL);

        if (expectedCheckValue != checkValue) {
            customerId = 0;
        }

        return customerId;
    }
}
