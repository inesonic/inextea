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
* This header defines the IneXtea encryptor and decryptor low level functions.
***********************************************************************************************************************/

/* .. sphinx-project inextea */

#ifndef INEXTEA_H
#define INEXTEA_H

#include <cstdint>
namespace IneXtea {
    /**
     * The XTEA algorithm key length, in bytes.
     */
    static constexpr unsigned keyLength = 16;

    /**
     * Type you can use to represent an XTEA key.
     */
    typedef std::uint8_t Key[keyLength];

    /**
     * The default number of Feistel cipher rounds to apply.
     */
    static constexpr unsigned defaultFeistelRounds = 64;

    /**
     * The XTEA block length, in bytes.
     */
    static constexpr unsigned blockLength = 8;

    /**
     * Type representing an individual chunk of data.
     */
    typedef std::uint8_t Block[blockLength];

    /**
     * Function you can use to encrypt a chunk of data.
     *
     * \param[in,out] block        The block to be encrypted.  The encrypted data will be returned in-place.
     *
     * \param[in]     key          The encryption key to be employed for this round.
     *
     * \param[in]     numberRounds The number of Feistel rounds to be performed.
     */
    void encrypt(Block block, const Key key, unsigned numberRounds = defaultFeistelRounds);

    /**
     * Function you can use to decrypt a chunk of data.
     *
     * \param[in,out] block        The block to be encrypted.  The encrypted data will be returned in-place.
     *
     * \param[in]     key          The encryption key to be employed for this round.
     *
     * \param[in]     numberRounds The number of Feistel rounds to be performed.
     */
    void decrypt(Block block, const Key key, unsigned numberRounds = defaultFeistelRounds);

    /**
     * Function you can use to convert a 32-bit customer ID value to an encrypted 8-byte customer identifier.
     *
     * \param[out] customerIdentifier The generated customer identifier.
     *
     * \param[in]  customerId         The customer ID to be converted.
     *
     * \param[in]  key                The encryption key to be employed for this round.
     */
    void toCustomerIdentifier(Block customerIdentifier, unsigned long customerId, const Key key);

    /**
     * Function you can use to convert an 8 byte customer identifier to an internal customer ID.
     *
     * \param[in] customerIdentifier The customer identifier to be converted.
     *
     * \param[in] key                The encryption key to be employed for this round.
     *
     * \return Returns the resulting customer ID.  A value of 0 is returned if the customer identifier is invalid.
     */
    unsigned long toCustomerId(const Block customerIdentifier, const Key key);
}

#endif
