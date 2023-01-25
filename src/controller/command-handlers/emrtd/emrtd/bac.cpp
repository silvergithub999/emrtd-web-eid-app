//
// Created by silver on 22.4.7.
//

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <array>
#include <openssl/ossl_typ.h>
#include <openssl/des.h>
#include <random>
#include <algorithm>
#include <functional>
#include "bac.hpp"

using random_bytes_engine = std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char>;

using namespace electronic_id;

BasicAccessControl::BasicAccessControl() {

}

SecureMessagingObject BasicAccessControl::establishBacSessionKeys(
    const byte_vector& secret,
    const pcsc_cpp::SmartCard& card
) {
    byte_vector secretDigest = calculateDigest(HashAlgorithm::SHA1, secret);

    byte_vector baKeySeed(secretDigest.begin(), secretDigest.begin() + 16);

    // Computing basic access keys

    const byte_vector encKey = computeKey(baKeySeed, KeyType::ENC, DEFAULT_ALG);
    const byte_vector macKey = computeKey(baKeySeed, KeyType::MAC, DEFAULT_ALG);

    // Establishing session keys

    byte_vector e(0);
    const auto rnd_ic =
        sendApduAndValidate(card, pcsc_cpp::CommandApdu(0x00, 0x84, 0x00, 0x00, e, 0x08));

    byte_vector rnd_ifd = getRandomBytes(8);
    byte_vector k_ifd = getRandomBytes(16);

    // s = rnd_ifd + rnd_ic + k_ifd
    byte_vector s = combineByteVectors({rnd_ifd, rnd_ic, k_ifd});

    byte_vector e_ifd = des_ede3_cbc_encrypt(s, encKey, DES_ENCRYPT);
    byte_vector e_ifd_padded = paddingMethod2(e_ifd);

    byte_vector m_ifd = computeMac(macKey, e_ifd_padded, DEFAULT_MAC_ALG);

    // cmd_data = e_ifd + m_ifd
    byte_vector cmd_data = combineByteVectors({e_ifd, m_ifd});

    // https://www.etsi.org/deliver/etsi_ts/102200_102299/102221/04.00.00_60/ts_102221v040000p.pdf - page 61
    const byte_vector resp_data_enc =
        sendApduAndValidate(card, pcsc_cpp::CommandApdu(0x00, 0x82, 0x00, 0x00, cmd_data, 0x28));

    byte_vector resp_data_enc_pad = paddingMethod2(byte_vector(resp_data_enc.begin(), resp_data_enc.end() - 8));

    byte_vector m_ic = computeMac(macKey, resp_data_enc_pad, DEFAULT_MAC_ALG);

    if (m_ic != byte_vector(resp_data_enc.end() - 8, resp_data_enc.end())) {
        throw std::runtime_error("Encrypted message MAC is not correct");
    }

    byte_vector respData = des_ede3_cbc_encrypt(
        byte_vector(resp_data_enc.begin(), resp_data_enc.end() - 8), encKey, DES_DECRYPT);

    if (rnd_ic != byte_vector (respData.begin(), respData.begin() + 8) ) {
        throw std::runtime_error("Received RND.IC DOES NOT match with the earlier RND.IC");
    }

    if (rnd_ifd != byte_vector (respData.begin() + 8, respData.begin() + 16)) {
        throw std::runtime_error("Received RND.IFD DOES NOT match with the generated RND.IFD");
    }

    byte_vector k_ic(respData.begin() + 16, respData.end());

    // const byte_vector ses_key_seed = byteVectorXor(k_ifd, k_ic);
    byte_vector ses_key_seed = xorByteVectors(&k_ifd, &k_ic);

    // Computing session keys
    const byte_vector ks_enc = computeKey(ses_key_seed, KeyType::ENC, DEFAULT_ALG);
    const byte_vector ks_mac = computeKey(ses_key_seed, KeyType::MAC, DEFAULT_ALG);

    const byte_vector ssc = combineByteVectors({
        byte_vector(rnd_ic.end() - 4, rnd_ic.end()),
        byte_vector(rnd_ifd.end() - 4, rnd_ifd.end())
    });

    return SecureMessagingObject(
        ssc,
        DEFAULT_ALG,
        DEFAULT_MAC_ALG,
        8,
        ks_enc,
        ks_mac
        );
}

byte_vector BasicAccessControl::computeKey(const byte_vector& keySeed, const KeyType keyType, const Alg alg) {
    byte_vector c;
    if (keyType == ENC) {
        c = {0x00, 0x00, 0x00, 0x01};
    } else {
        c = {0x00, 0x00, 0x00, 0x02};
    }

    // D = keySeed + c
    byte_vector D = combineByteVectors({keySeed, c});

    if (alg == AES256) {
        return calculateDigest(HashAlgorithm::SHA256, D);
    } else if (alg == DES3) {
        // TODO: no idea if this block is correct
        // hash_of_D = hashlib.sha1(D).digest()
        // key_a = hash_of_D[:8]
        // key_b = hash_of_D[8:16]
        // return DES3.adjust_key_parity(key_a + key_b)  # set parity bits

        const byte_vector hashD = calculateDigest(HashAlgorithm::SHA1, D);
        byte_vector r(hashD.begin(), hashD.end() + 16);
        DES_cblock keyA;
        DES_cblock keyB;

        for (int i = 0; i < 8; i++) {
            keyA[i] = r[i];
            keyB[i] = r[8 + i];
        }

        DES_set_odd_parity(&keyA);
        DES_set_odd_parity(&keyB);

        byte_vector result;
        result.insert(result.end(), std::begin(keyA), std::end(keyA));
        result.insert(result.end(), std::begin(keyB), std::end(keyB));

        return result;
    } else {
        throw std::runtime_error("Unknown encryption algorithm");
    }
}

byte_vector BasicAccessControl::getRandomBytes(int n) {
    // TODO: not really random currently
    std::mt19937 random;

    byte_vector vec(n);
    std::generate(vec.begin(), vec.end(), std::ref(random));
    return vec;
}
