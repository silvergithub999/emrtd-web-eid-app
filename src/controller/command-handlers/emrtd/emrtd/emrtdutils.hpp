#ifndef EMRTD_UTILS_H
#define EMRTD_UTILS_H

// designed to cause the current source file to be included only once in a single compilation
// #pragma once

#include <set>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <algorithm>
#include <iostream>
#include <openssl/sha.h>
#include <cstring>
#include "../../../../../lib/libelectronic-id/include/electronic-id/enums.hpp"
#include "../../../../../lib/libelectronic-id/lib/libpcsc-cpp/include/pcsc-cpp/pcsc-cpp.hpp"
#include <cstdint>
#include <vector>
#include "emrtdenums.hpp"
#include <openssl/des.h>
#include <sstream>
#include <iomanip>
#include <map>
#include "asn1utils.hpp"

#pragma GCC diagnostic ignored "-Wunused-parameter"

using byte_vector = std::vector<unsigned char>;
using namespace electronic_id;

const inline EVP_MD* hashToMD(HashAlgorithm algorithm) {
    switch (algorithm) {
    case electronic_id::HashAlgorithm::SHA1:
        return EVP_sha1();
    case electronic_id::HashAlgorithm::SHA224:
        return EVP_sha224();
    case electronic_id::HashAlgorithm::SHA256:
        return EVP_sha256();
    case electronic_id::HashAlgorithm::SHA384:
        return EVP_sha384();
    case electronic_id::HashAlgorithm::SHA512:
        return EVP_sha512();
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    case electronic_id::HashAlgorithm::SHA3_224:
        return EVP_sha3_224();
    case electronic_id::HashAlgorithm::SHA3_256:
        return EVP_sha3_256();
    case electronic_id::HashAlgorithm::SHA3_384:
        return EVP_sha3_384();
    case electronic_id::HashAlgorithm::SHA3_512:
        return EVP_sha3_512();
    #endif
    default:
        throw std::logic_error("hashToMD: unknown hash algorithm");
    }
}

inline pcsc_cpp::byte_vector calculateDigest(HashAlgorithm hashAlgo, const pcsc_cpp::byte_vector& data) {
    pcsc_cpp::byte_vector digest(size_t(EVP_MAX_MD_SIZE));
    const EVP_MD* md = hashToMD(hashAlgo);
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &size, md, nullptr) != 1) {
        throw std::runtime_error("calculateDigest: EVP_Digest failed");
    }
    digest.resize(size);
    return digest;
}

// copied from utils.cpp
inline std::string bytes2hexstr2(const byte_vector& bytes)
{
    std::ostringstream hexStringBuilder;

    hexStringBuilder << std::setfill('0') << std::hex;

    for (const auto byte : bytes)
        hexStringBuilder << std::setw(2) << short(byte);

    return hexStringBuilder.str();
}

inline pcsc_cpp::byte_vector sendApduAndValidate(
    const pcsc_cpp::SmartCard& card,
    const pcsc_cpp::CommandApdu& apdu
) {
    const auto response = card.transmit(apdu);
    if (response.sw1 != 0x90 || response.sw2 != 0x00) {
        throw std::runtime_error(
            "The APDU response is" + bytes2hexstr2({response.sw1, response.sw2}) + " not [0x90 0x00]");
    }
    return response.data;
}

inline byte_vector readFileFromIdApplet(
    const pcsc_cpp::SmartCard& card,
    const byte_vector& fileName
) {
    pcsc_cpp::CommandApdu apdu(0x00, 0xB0, 0x00, 0x00, {}, 0x00);

    const auto response = card.transmit(apdu);

    if (response.sw1 == 0x90 && response.sw2 == 0x00) {
        return response.data;
    } else if (response.sw1 == 0x61) {
        return sendApduAndValidate(
            card,
            pcsc_cpp::CommandApdu(0x00,  0xC0, 0x00, 0x00, {}, response.sw2)
            );
    } else if (response.sw1 == 0x6C) {
        return sendApduAndValidate(
            card,
            pcsc_cpp::CommandApdu(apdu.cla, apdu.ins, apdu.p1, apdu.p2, {}, response.sw2)
            );
    } else {
        throw std::runtime_error("readFileBasic(): error");
    }
}

inline void debugPrint(
    const pcsc_cpp::byte_vector& vec,
    const std::string& name
) {
    std::cout << "TODO-" << name << "-" << vec.size() << std::endl;
    for (auto val : vec) {
        int t = int(val);
        std::cout << std::hex << t << " ";
    }
    std::cout << std::endl;
}

inline int calculateCheckDigit(const byte_vector& data) {
    std::map<unsigned char, int> values = {
        {'0', 0}, {'1', 1}, {'2', 2}, {'3', 3}, {'4', 4}, {'5', 5}, {'6', 6},
        {'7', 7}, {'8', 8}, {'9', 9}, {'<', 0}, {'A', 10}, {'B', 11},
        {'C', 12}, {'D', 13}, {'E', 14}, {'F', 15}, {'G', 16}, {'H', 17},
        {'I', 18}, {'J', 19}, {'K', 20}, {'L', 21}, {'M', 22}, {'N', 23},
        {'O', 24}, {'P', 25}, {'Q', 26}, {'R', 27}, {'S', 28}, {'T', 29},
        {'U', 30}, {'V', 31}, {'W', 32}, {'X', 33}, {'Y', 34}, {'Z', 35}
    };

    byte_vector weights = {7, 3, 1};
    int total = 0;

    for (size_t i = 0; i < data.size(); i++) {
        total += weights[i % 3] * values.at(data[i]);
    }

    return total % 10;
}


inline void selectEmrtdApplet(const pcsc_cpp::SmartCard& card) {
    const byte_vector emrtdId = {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
    pcsc_cpp::CommandApdu apdu(0x00, 0xA4, 0x04, 0x0C, emrtdId);

    // TODO: if error then this applet is not present
    sendApduAndValidate(card, apdu);
}

inline byte_vector readInfoFromIdAppletAndGetMrz(const pcsc_cpp::SmartCard& card) {
    // Select id applet as file
    byte_vector idApplet = {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00};
    pcsc_cpp::CommandApdu apdu(0x00, 0xA4, 0x04, 0x00, idApplet);
    sendApduAndValidate(card, apdu);

    // SELECT FILE (MF/5000)
    pcsc_cpp::CommandApdu selectMF5000(0x00, 0xA4, 0x01, 0x0C, {0x50, 0x00});
    sendApduAndValidate(card, selectMF5000);

    // TODO: different files for different id cards 2018 vs present

    sendApduAndValidate(card, pcsc_cpp::CommandApdu(0x00, 0xA4, 0x01, 0x0C, {0x50, 0x07}));
    byte_vector documentNumber = readFileFromIdApplet(card, {0x50, 0x07});

    sendApduAndValidate(card, pcsc_cpp::CommandApdu(0x00, 0xA4, 0x01, 0x0C, {0x50, 0x05}));
    byte_vector dateOfBirthOriginal = readFileFromIdApplet(card, {0x50, 0x05});

    byte_vector dateOfBirth(0);
    dateOfBirth.insert(dateOfBirth.end(), dateOfBirthOriginal.begin() + 8, dateOfBirthOriginal.begin() + 10);
    dateOfBirth.insert(dateOfBirth.end(), dateOfBirthOriginal.begin() + 3, dateOfBirthOriginal.begin() + 5);
    dateOfBirth.insert(dateOfBirth.end(), dateOfBirthOriginal.begin(), dateOfBirthOriginal.begin() + 2);

    sendApduAndValidate(card, pcsc_cpp::CommandApdu(0x00, 0xA4, 0x01, 0x0C, {0x50, 0x08}));
    byte_vector expirationDateOriginal = readFileFromIdApplet(card, {0x50, 0x08});

    byte_vector expirationDate(0);
    expirationDate.insert(expirationDate.end(), expirationDateOriginal.end() - 2, expirationDateOriginal.end());
    expirationDate.insert(expirationDate.end(), expirationDateOriginal.begin() + 3, expirationDateOriginal.begin() + 5);
    expirationDate.insert(expirationDate.end(), expirationDateOriginal.begin(), expirationDateOriginal.begin() + 2);

    std::string mrzString =
        std::string(documentNumber.begin(),documentNumber.end())
        + std::to_string(calculateCheckDigit(documentNumber))
        + std::string(dateOfBirth.begin(),dateOfBirth.end())
        + std::to_string(calculateCheckDigit(dateOfBirth))
        + std::string(expirationDate.begin(),expirationDate.end())
        + std::to_string(calculateCheckDigit(expirationDate));

    // Select LDS applet
    const byte_vector ldsId = {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0xFF};
    sendApduAndValidate(
        card,
        pcsc_cpp::CommandApdu(0x00, 0xA4, 0x04, 0x0C, ldsId)
        );

    // std::cout << "MRZ: " << mrzString << std::endl;

    return {mrzString.begin(), mrzString.end()};
}

inline void xorBlock(unsigned char* src, unsigned char* dest) {
    for (int x = 0; x < 8; x++) {
        src[x] =  src[x] ^ dest[x];
    }
}

inline byte_vector xorByteVectors(byte_vector* a, byte_vector* b) {
    if ((*a).size() != (*b).size()) {
        throw std::runtime_error("Arrays not equal length for XOR");
    }

    byte_vector result((*a).size());
    for (unsigned long i = 0; i < (*a).size(); i++) {
        result[i] = (*a)[i] ^ (*b)[i];
    }

    return result;
}

// TODO: endianess of the two functions below

inline unsigned long byteVectorToLong(pcsc_cpp::byte_vector bytes) {
    if (bytes.empty()) {
        throw std::runtime_error("cannot convert empty vector to integer");
    }

    unsigned long l = 0;
    for (int i = 0; i < 8; i++) {
        l |= (unsigned long) bytes[7 - i] << (8 * i);
    }

    return l;
}

inline pcsc_cpp::byte_vector longToByteVector(unsigned long i) {
    pcsc_cpp::byte_vector byteVector;
    // long is 8 bytes
    for (int k = 0; k < 8; k++) {
        byteVector.insert(byteVector.begin(), (i >> (k * 8)) & 0xFF);
    }
    return byteVector;
}

inline pcsc_cpp::byte_vector combineByteVectors(
    std::initializer_list<pcsc_cpp::byte_vector> vecs
) {
    byte_vector result;
    for (auto v: vecs) {
        result.insert(result.end(), v.begin(), v.end());
    }
    return result;
}

// TODO: stuff below is inline, bt should be moved a common static class or smthing

inline byte_vector paddingMethod2(byte_vector data)
{
    byte_vector paddedData(data.begin(), data.end());

    int dataSize = data.size() & INT_MAX;
    dataSize++;
    int padLength = 8 - (dataSize % 8);

    paddedData.push_back(0x80);

    if (padLength == 8) {
        return paddedData;
    }

    for (int i = 0; i < padLength; i++) {
        paddedData.push_back(0x00);
    }

    return paddedData;
}

inline byte_vector removePadding2(byte_vector data) {
    int dataSize = data.size() & INT_MAX;
    for (int i = dataSize - 1; i > 0; i--) {
        if (data[i] == 0x80) {
            return byte_vector(data.begin(), data.begin() + i);
        }
    }
    throw std::runtime_error("Could not remove padding");
}

// https://www.icao.int/publications/documents/9303_p11_cons_en.pdf
//  page 30 - oids for which alg is supproted cmac vs des


inline byte_vector des_ede3_cbc_encrypt(const byte_vector& input, byte_vector key, int enc) {
    DES_cblock iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    DES_cblock key1;
    DES_cblock key2;
    DES_cblock key3;

    std::memcpy(key1, &key[0], 8);
    std::memcpy(key2, &key[8], 8);
    std::memcpy(key3, &key[0], 8);

    DES_key_schedule schKey1, schKey2, schKey3;

    DES_set_key_unchecked(&key1, &schKey1);
    DES_set_key_unchecked(&key2, &schKey2);
    DES_set_key_unchecked(&key3, &schKey3);

    byte_vector output(input.size());

    DES_ede3_cbc_encrypt(
        &input[0],
        &output[0],
        input.size(),
        &schKey1, &schKey2, &schKey3,
        &iv, enc
    );

    return output;
}

inline void des_ecb_crypt(unsigned char* input, unsigned char* output, int encrypt, unsigned char* key) {

    DES_key_schedule sched;

    DES_set_key((const_DES_cblock *) key, &sched);

    DES_ecb_encrypt((const_DES_cblock *)input,
                    (const_DES_cblock *)output,
                    &sched,
                    encrypt);
}

inline byte_vector iso9797_alg3_mac(byte_vector data, byte_vector k1, byte_vector k2) {
    unsigned char output[8];
    unsigned char h[8];

    des_ecb_crypt(&byte_vector(data.begin(), data.begin() + 8)[0], h, DES_ENCRYPT, &k1[0]);

    for (int i = 1; i < int(data.size() / 8); i++) {
        xorBlock(h, &byte_vector(data.begin() + 8 * i, data.begin() + 8 * (i + 1))[0]);

        des_ecb_crypt(h, output, DES_ENCRYPT, &k1[0]);

        std::memcpy(h, output, 8);
    }

    des_ecb_crypt(h, output, DES_DECRYPT, &k2[0]);
    std::memcpy(h, output, 8);

    des_ecb_crypt(h, output, DES_ENCRYPT, &k1[0]);
    std::memcpy(h, output, 8);

    byte_vector result(std::begin(h), std::end(h));

    return result;
}

inline byte_vector computeMac(const byte_vector key, const byte_vector data, MacAlg alg) {
    if (alg == AES_CMAC) {
        throw std::runtime_error("TODO: AES_CMAC no implemented, currently unsupported mac");
    } else if (alg == DES) {
        byte_vector k1(key.begin(), key.begin() + 8);
        byte_vector k2(key.end() - 8, key.end());

        return iso9797_alg3_mac(data, k1, k2);
    } else {
        throw std::runtime_error("Unsupported MAC algorithm. Only AES-CMAC and DES supported for now.");
    }
}

#endif
