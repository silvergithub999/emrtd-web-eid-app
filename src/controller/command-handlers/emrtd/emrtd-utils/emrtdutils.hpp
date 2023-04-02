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

inline byte_vector readInfoFromIdAppletAndGetSecret(const pcsc_cpp::SmartCard& card) {
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

    std::string secret =
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

    return {secret.begin(), secret.end()};
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

#endif
