#ifndef EMRTD_WEB_EID_APP_IDUTILS_H
#define EMRTD_WEB_EID_APP_IDUTILS_H

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

using byte_vector = std::vector<unsigned char>;
using namespace electronic_id;

// copied from lib/libelectronic-id/lib/libpcsc-cpp/src/utils.cpp
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
    // TODO: add transaction guard
    //  The transaction guard is not available here.
    //  Some of eMRTD code from the web eid project should be moved to
    //  libelectronic-id so the transaction guard could be used.
    // auto transactionGuard = cardInfo.eid().smartcard()->beginTransaction();

    const auto response = card.transmit(apdu);
    if (response.sw1 != 0x90 || response.sw2 != 0x00) {
        throw std::runtime_error(
            "The APDU response is" + bytes2hexstr2({response.sw1, response.sw2}) + " not [0x90 0x00]");
    }
    return response.data;
}

#endif // EMRTD_WEB_EID_APP_IDUTILS_H
