#ifndef WEB_EID_APP_CRYPTOUTILS_H
#define WEB_EID_APP_CRYPTOUTILS_H

#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <vector>
#include "asn1utils.hpp"

using byte_vector = std::vector<unsigned char>;
using namespace electronic_id;

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
    if (alg == DES) {
        byte_vector k1(key.begin(), key.begin() + 8);
        byte_vector k2(key.end() - 8, key.end());

        return iso9797_alg3_mac(data, k1, k2);
    } else {
        throw std::runtime_error("Unsupported MAC algorithm. Only DES supported for now.");
    }
}

#endif // WEB_EID_APP_CRYPTOUTILS_H
