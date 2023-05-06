#ifndef WEB_EID_APP_SECUREMESSAGINGOBJECT_HPP
#define WEB_EID_APP_SECUREMESSAGINGOBJECT_HPP

#include <vector>
#include "utils/emrtdutils.hpp"
#include "utils/cryptoutils.hpp"

using byte_vector = std::vector<unsigned char>;

/**
 * TODO: add card object to the constructor
 */
class SecureMessagingObject {

public:
    SecureMessagingObject(
        byte_vector ssc_counter,
        Alg encAlgorithm,
        MacAlg macAlgorithm,
        int paddingLen,
        const byte_vector& sessionEncKey,
        const byte_vector& sessionMacKey
        );

    byte_vector send(const pcsc_cpp::SmartCard& card, const pcsc_cpp::CommandApdu& apdu);

    byte_vector readFile(const pcsc_cpp::SmartCard& card, const byte_vector& fileName);

private:
    byte_vector ssc_counter;

    Alg encAlgorithm;
    MacAlg macAlgorithm;

    int paddingLen;

    // Session keys
    byte_vector sessionEncKey;
    byte_vector sessionMacKey;

    void incrementSsc();
    byte_vector getSscBytes();

    pcsc_cpp::CommandApdu secureMessaging(const pcsc_cpp::CommandApdu& apdu);
    byte_vector processResponseData(const byte_vector& responseData);

    size_t readDataLengthFromAsn1(const pcsc_cpp::SmartCard& card, const byte_vector& fileName);

    byte_vector readBinary(const pcsc_cpp::SmartCard& card, const size_t length, const size_t blockLength);
};

#endif // WEB_EID_APP_SECUREMESSAGINGOBJECT_HPP
