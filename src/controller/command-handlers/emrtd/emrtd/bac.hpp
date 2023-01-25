//
// Created by silver on 22.4.7.
//

#ifndef WEB_EID_APP_BAC_H
#define WEB_EID_APP_BAC_H

#include <vector>
#include "../../../../../lib/libelectronic-id/include/electronic-id/enums.hpp"
#include "../../../../../lib/libelectronic-id/lib/libpcsc-cpp/include/pcsc-cpp/pcsc-cpp.hpp"
#include "securemessagingobject.hpp"

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

    // TODO: should have only one value to configure this
    static const Alg DEFAULT_ALG = DES3;
    static const MacAlg DEFAULT_MAC_ALG = DES;

    static byte_vector computeKey(const byte_vector& keySeed, const KeyType keyType, const Alg alg);

    static byte_vector getRandomBytes(int n);
};

#endif // WEB_EID_APP_BAC_H
