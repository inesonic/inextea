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
* This file implements a Python wrapper to the IneXTea functions.
***********************************************************************************************************************/

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdio>

#define PY_SSIZE_T_CLEAN (true)
#include <Python.h>

#include "inextea.h"

static PyObject* methodEncrypt(PyObject* /* self */, PyObject* arguments) {
    PyObject* result = nullptr;
    Py_buffer blockBuffer;
    Py_buffer keyBuffer;
    unsigned  numberRounds;

    if (PyArg_ParseTuple(arguments, "y*y*I", &blockBuffer, &keyBuffer, &numberRounds)) {
        std::uint8_t* block = reinterpret_cast<std::uint8_t*>(blockBuffer.buf);
        Py_ssize_t    blockLength = blockBuffer.len;

        std::uint8_t* key = reinterpret_cast<std::uint8_t*>(keyBuffer.buf);
        Py_ssize_t    keyLength = keyBuffer.len;

        if (blockLength == IneXtea::blockLength && keyLength == IneXtea::keyLength) {
            IneXtea::Block volatileBlock;
            std::memcpy(volatileBlock, block, IneXtea::blockLength);

            IneXtea::encrypt(volatileBlock, key, numberRounds);

            result = Py_BuildValue("y#", volatileBlock, IneXtea::blockLength);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Array lengths invalid.  See help for details.");
        }
    } else {
        PyErr_SetString(PyExc_RuntimeError, "Invalid arguments.");
    }

    return result;
}


static PyObject* methodDecrypt(PyObject* /* self */, PyObject* arguments) {
    PyObject* result = nullptr;
    Py_buffer blockBuffer;
    Py_buffer keyBuffer;
    unsigned  numberRounds;

    if (PyArg_ParseTuple(arguments, "y*y*I", &blockBuffer, &keyBuffer, &numberRounds)) {
        std::uint8_t* block = reinterpret_cast<std::uint8_t*>(blockBuffer.buf);
        Py_ssize_t    blockLength = blockBuffer.len;

        std::uint8_t* key = reinterpret_cast<std::uint8_t*>(keyBuffer.buf);
        Py_ssize_t    keyLength = keyBuffer.len;

        if (blockLength == IneXtea::blockLength && keyLength == IneXtea::keyLength) {
            IneXtea::Block volatileBlock;
            std::memcpy(volatileBlock, block, IneXtea::blockLength);

            IneXtea::decrypt(volatileBlock, key, numberRounds);

            result = Py_BuildValue("y#", volatileBlock, IneXtea::blockLength);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Array lengths invalid.  See help for details.");
        }
    } else {
        PyErr_SetString(PyExc_RuntimeError, "Invalid arguments.");
    }

    return result;
}


static PyObject* methodToCustomerIdentifier(PyObject* /* self */, PyObject* arguments) {
    PyObject*     result = nullptr;
    unsigned long customerId;
    Py_buffer     keyBuffer;

    if (PyArg_ParseTuple(arguments, "ky*", &customerId, &keyBuffer)) {
        std::uint8_t* key = reinterpret_cast<std::uint8_t*>(keyBuffer.buf);
        Py_ssize_t    keyLength = keyBuffer.len;

        if (keyLength == IneXtea::keyLength) {
            IneXtea::Block customerIdentifier;
            IneXtea::toCustomerIdentifier(customerIdentifier, customerId, key);

            result = Py_BuildValue("y#", customerIdentifier, IneXtea::blockLength);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Array lengths invalid.  See help for details.");
        }
    } else {
        PyErr_SetString(PyExc_RuntimeError, "Invalid arguments.");
    }

    return result;
}


static PyObject* methodToCustomerId(PyObject* /* self */, PyObject* arguments) {
    PyObject* result = nullptr;
    Py_buffer customerIdentifierBuffer;
    Py_buffer keyBuffer;

    if (PyArg_ParseTuple(arguments, "y*y*", &customerIdentifierBuffer, &keyBuffer)) {
        std::uint8_t* customerIdentifierBlock  = reinterpret_cast<std::uint8_t*>(customerIdentifierBuffer.buf);
        Py_ssize_t    customerIdentifierLength = customerIdentifierBuffer.len;

        std::uint8_t* keyBlock = reinterpret_cast<std::uint8_t*>(keyBuffer.buf);
        Py_ssize_t    keyLength = keyBuffer.len;

        if (customerIdentifierLength == IneXtea::blockLength && keyLength == IneXtea::keyLength) {
            IneXtea::Block customerIdentifier;
            IneXtea::Key   key;

            std::memcpy(&customerIdentifier, customerIdentifierBlock, IneXtea::blockLength);
            std::memcpy(&key, keyBlock, IneXtea::keyLength);

            unsigned long customerId = IneXtea::toCustomerId(customerIdentifier, key);
            result = Py_BuildValue("k", customerId);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Array lengths invalid.  See help for details.");
        }
    } else {
        PyErr_SetString(PyExc_RuntimeError, "Invalid arguments.");
    }

    return result;
}


static PyMethodDef xteaMethods[] = {
    {
        "decrypt",
        &methodDecrypt,
        METH_VARARGS,
        "Function:\n"
        "  decrypt(block, key, number_rounds)\n\n"
        "Description:\n"
        "  You can use this function to perform a specified number of reversed Feistel\n"
        "  rounds on a block.\n\n"
        "Parameters:\n"
        "  block -         The block to perform the Feistel rounds on.  Each block must\n"
        "                  be exactly 8 bytes in length.\n\n"
        "  key -           The Feistel key to be applied.  The key must be exactly 16\n"
        "                  bytes in length.\n\n"
        "  number_rounds - The number of Feistel rounds to be performed.\n\n"
        "Returns:\n"
        "  Returns a bytes object holding the decrypted block.\n",
    },
    {
        "encrypt",
        &methodEncrypt,
        METH_VARARGS,
        "Function:\n"
        "  encrypt(block, key, number_rounds)\n\n"
        "Description:\n"
        "  You can use this function to perform a specified number of Feistel rounds on\n"
        "  a block.\n\n"
        "Parameters:\n"
        "  block -         The block to perform the Feistel rounds on.  Each block must\n"
        "                  be exactly 8 bytes in length.\n\n"
        "  key -           The Feistel key to be applied.  The key must be exactly 16\n"
        "                  bytes in length.\n\n"
        "  number_rounds - The number of Feistel rounds to be performed.\n\n"
        "Returns:\n"
        "  Returns a bytes object holding the encrypted block.\n",
    },
    {
        "to_customer_identifier",
        &methodToCustomerIdentifier,
        METH_VARARGS,
        "Function:\n"
        "  to_customer_identifier(customer_id, key)\n\n"
        "Description:\n"
        "  You can use this function to convert a 32-bit non-zero unsigned integer\n"
        "  value to an lightly encrypted 8-byte sequence with checking.\n\n"
        "Parameters:\n"
        "  customer_id - The integer value to be converted.\n\n"
        "  key -         The Feistel key to be applied.  The key must be exactly 16\n"
        "                bytes in length.\n\n"
        "Returns:\n"
        "  Returns a bytes object holding the lightly encrypted value.\n",
    },
    {
        "to_customer_id",
        &methodToCustomerId,
        METH_VARARGS,
        "Function:\n"
        "  to_customer_id(customer_identifier, key)\n\n"
        "Description:\n"
        "  You can use this function to convert a customer identifier generated by\n"
        "  to_customer_identifier back to a 32-bit non-zero unsigned integer.\n\n"
        "Parameters:\n"
        "  customer_identifier - The customer identifier to be converted.\n\n"
        "  key -                 The Feistel key to be applied.  The key must be\n"
        "                        exactly 16 bytes in length.\n\n"
        "Returns:\n"
        "  Returns the 32-bit integer.  The value 0 is returned if the checksum\n"
        "  failed.\n"
    },
    { nullptr, nullptr, 0, nullptr }
};


static PyModuleDef inexteaModule = {
    PyModuleDef_HEAD_INIT,
    "inextea",
    "Python interface to the Inesonic XTEA encryptor implementation.",
    -1, // We have no global state.
    xteaMethods,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};


PyMODINIT_FUNC PyInit_inextea(void) {
    return PyModule_Create(&inexteaModule);
}
