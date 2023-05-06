#ifndef WEB_EID_APP_BAC_H
#define WEB_EID_APP_BAC_H

#include <vector>
#include "../securemessagingobject.hpp"

using byte_vector = std::vector<unsigned char>;

class SecureMessagingObject;

class BasicAccessControl {
public:
    static SecureMessagingObject establishBacSessionKeys(
        const byte_vector& secret,
        const pcsc_cpp::SmartCard& card
    );

private:
    BasicAccessControl();

    static const Alg DEFAULT_ALG = DES3;
    static const MacAlg DEFAULT_MAC_ALG = DES;

    static byte_vector computeKey(const byte_vector& keySeed, const KeyType keyType, const Alg alg);

    static byte_vector getRandomBytes(int n);

    static byte_vector calculateSha1Digest(const pcsc_cpp::byte_vector& data);
};

#endif // WEB_EID_APP_BAC_H
