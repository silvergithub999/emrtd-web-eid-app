
//
// Created by silver on 22.14.6.
//

#include "securemessagingobject.hpp"
#include <cmath>

#include <utility>

void SecureMessagingObject::incrementSsc() {
    unsigned long sscCounterLong = byteVectorToLong(this->ssc_counter);
    sscCounterLong += 1;
    this->ssc_counter = longToByteVector(sscCounterLong);
}

byte_vector SecureMessagingObject::getSscBytes() {
    return static_cast<byte_vector>(this->ssc_counter);
}

SecureMessagingObject::SecureMessagingObject(
    byte_vector ssc_counter,
    Alg encAlgorithm,
    MacAlg macAlgorithm,
    int paddingLen,
    const byte_vector& sessionEncKey,
    const byte_vector& sessionMacKey
) {
    this->ssc_counter = std::move(ssc_counter);
    this->encAlgorithm = encAlgorithm;
    this->macAlgorithm = macAlgorithm;
    this->paddingLen = paddingLen;
    this->sessionEncKey = sessionEncKey;
    this->sessionMacKey = sessionMacKey;
}

byte_vector SecureMessagingObject::send(const pcsc_cpp::SmartCard& card, const pcsc_cpp::CommandApdu& apdu) {
    pcsc_cpp::CommandApdu protectedApdu = secureMessaging(apdu);
    const auto response = sendApduAndValidate(card, protectedApdu);
    return processResponseData(response);
}

// TODO: create sub-functions for steps
pcsc_cpp::CommandApdu SecureMessagingObject::secureMessaging(const pcsc_cpp::CommandApdu& apdu) {
    incrementSsc();

    unsigned char modifiedCla = apdu.cla | 0x0C;

    byte_vector payload;
    if (!apdu.data.empty()) {
        byte_vector data = paddingMethod2(apdu.data);

        byte_vector encryptedData;
        if (encAlgorithm == DES3) {
            encryptedData =
                des_ede3_cbc_encrypt(data, sessionEncKey, DES_ENCRYPT);
        } else if (encAlgorithm == AES256) {
            throw std::runtime_error("AES256 currently not supported");
        }

        if (((int) apdu.ins) % 2 == 0) {
            byte_vector do87(0);

            do87.push_back(0x87);

            byte_vector len = asn1_len(1 + encryptedData.size());
            do87.insert(do87.end(), len.begin(), len.end());

            do87.push_back(0x01);
            do87.insert(do87.end(), encryptedData.begin(), encryptedData.end());

            payload.insert(payload.end(), do87.begin(), do87.end());
        } else {
            byte_vector do85(0);

            do85.push_back(0x85);

            byte_vector len = asn1_len(encryptedData.size());
            do85.insert(do85.end(), len.begin(), len.end());

            do85.insert(do85.end(), encryptedData.begin(), encryptedData.end());

            payload.insert(payload.end(), do85.begin(), do85.end());
        }
    }

    if (!std::isnan(apdu.le)) {
        byte_vector do97(0);

        do97.push_back(0x97);

        byte_vector len = asn1_len(1);
        do97.insert(do97.end(), len.begin(), len.end());

        do97.push_back(apdu.le);

        payload.insert(payload.end(), do97.begin(), do97.end());
    }

    byte_vector paddedHeader = paddingMethod2({modifiedCla, apdu.ins, apdu.p1, apdu.p2});

    byte_vector sum(0);
    sum.insert(sum.end(), this->ssc_counter.begin(), this->ssc_counter.end());
    sum.insert(sum.end(), paddedHeader.begin(), paddedHeader.end());
    sum.insert(sum.end(), payload.begin(), payload.end());

    byte_vector n = paddingMethod2(sum);

    byte_vector cc = computeMac(this->sessionMacKey, n, this->macAlgorithm);

    byte_vector do8e(0);
    do8e.push_back(0x8E);

    byte_vector len = asn1_len(cc.size());
    do8e.insert(do8e.end(), len.begin(), len.end());
    do8e.insert(do8e.end(), cc.begin(), cc.end());

    payload.insert(payload.end(), do8e.begin(), do8e.end());

    pcsc_cpp::CommandApdu protectedApdu(
        modifiedCla,
        apdu.ins,
        apdu.p1,
        apdu.p2,
        payload,
        0x00
        );

    return protectedApdu;
}



byte_vector SecureMessagingObject::processResponseData(const byte_vector& responseData)
{
    this->incrementSsc();

    byte_vector encryptedData;
    byte_vector decryptedData;

    // https://www.icao.int/publications/documents/9303_p11_cons_en.pdf - page 91
    byte_vector do85(0);
    byte_vector do87(0);
    byte_vector do99(0);
    byte_vector do8e(0);

    // [DO'85 or DO'87][DO'99][DO'8E]
    std::vector<byte_vector> vecs = parse_asn1_sequence(responseData);

    for (const auto& vec : vecs) {
        switch (vec[0]) {
        case 0x85: // 133
            encryptedData = asn1_get_value(vec);
            do85 = vec;
            break;
        case 0x87: // 135
            encryptedData = asn1_get_value(vec);
            do87 = vec;
            break;
        case 0x99: // 153
            do99 = vec;
            break;
        case 0x8E: // 142
            do8e = asn1_get_value(vec);
            break;
        };
    }

    // ssc + (do85 or b"") + (do87 or b"") + (do99 or b"")
    byte_vector ssc = getSscBytes();
    byte_vector sum(0);
    sum.insert(sum.end(), ssc.begin(), ssc.end());
    sum.insert(sum.end(), do85.begin(), do85.end());
    sum.insert(sum.end(), do87.begin(), do87.end());
    sum.insert(sum.end(), do99.begin(), do99.end());
    byte_vector k = paddingMethod2(sum);

    byte_vector cc = computeMac(this->sessionMacKey, k, this->macAlgorithm);

    if (cc != do8e) {
        throw std::runtime_error("Reply APDU is not valid");
    }

    if (!encryptedData.empty()) {
        if (!do87.empty()) {
            encryptedData = byte_vector(encryptedData.begin() + 1, encryptedData.end());
        }

        if (this->encAlgorithm == DES3) {
            decryptedData =
                des_ede3_cbc_encrypt(encryptedData, sessionEncKey, DES_DECRYPT);
        } else if (encAlgorithm == AES256) {
            throw std::runtime_error("AES256 currently not supported");
        }

        decryptedData = removePadding2(decryptedData);

        return decryptedData;
    }
    return decryptedData;
}

byte_vector SecureMessagingObject::readFile(const pcsc_cpp::SmartCard& card, const byte_vector& fileName) {
    auto length = readDataLengthFromAsn1(card, fileName);
    return readBinary(card, length, 0x32);
}

size_t SecureMessagingObject::readDataLengthFromAsn1(const pcsc_cpp::SmartCard& card, const byte_vector& fileName)
{
    // Selecting file
    send(
        card,
        pcsc_cpp::CommandApdu(0x00, 0xA4, 0x02, 0x0C, fileName, 0x00)
    );

    // Reading first 4 bytes
    byte_vector responseData = send(
        card,
        pcsc_cpp::CommandApdu{0x00, 0xB0, 0x00, 0x00, byte_vector(0), 0x04}
    );

    int prefixLength = responseData[1] > 128 ? 4 : 2;

    int contentLength = asn1_value_length(responseData);

    return prefixLength + contentLength;
}

byte_vector SecureMessagingObject::readBinary(const pcsc_cpp::SmartCard& card, const size_t length, const size_t blockLength)
{
    size_t blockLengthVar = blockLength;
    auto lengthCounter = length;
    auto resultBytes = byte_vector {};
    auto readBinary = pcsc_cpp::CommandApdu {0x00, 0xb0, 0x00, 0x00};

    for (size_t offset = 0; lengthCounter != 0;
         offset += blockLengthVar, lengthCounter -= blockLengthVar) {

        if (blockLengthVar > lengthCounter) {
            blockLengthVar = lengthCounter;
        }

        readBinary.p1 = static_cast<unsigned char>((offset >> 8) & 0xff);
        readBinary.p2 = static_cast<unsigned char>(offset & 0xff);
        readBinary.le = static_cast<unsigned char>(blockLengthVar);

        byte_vector responseData = send(card, readBinary);

        resultBytes.insert(resultBytes.end(), responseData.cbegin(), responseData.cend());
    }

    if (resultBytes.size() != length) {
        throw std::runtime_error("SMO.readBinary(): Invalid length");
    }

    return resultBytes;
}
