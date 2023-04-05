#ifndef ASN1_UTILS_H
#define ASN1_UTILS_H

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <iostream>
#include "emrtdutils.hpp"

using byte_vector = std::vector<unsigned char>;

inline int byteVectorToInt(const byte_vector& bytes) {
    int l = 0;
    for (unsigned char byte : bytes) {
        l = l << 8;
        l |= byte;
    }
    return l;
}

/**
 * DER is: type-length-value
 * This function finds len(type+length).
 *
 * asn1_prefix_length(der) + asn1_value_length(der) = len(der)
 */
inline int asn1_prefix_length(const byte_vector& der) {
    if (der.empty()) {
        return 0;
    }

    if ((der[1] & 128) == 128) {
        return 2 + ((int) der[1]) - 128;
    }
    return 2;
}

/**
 * DER is: type-length-value
 * This function return the length as integer.
 *
 * asn1_prefix_length(der) + asn1_value_length(der) = len(der)
 */
inline int asn1_value_length(const byte_vector& der) {
    if (der[1] > 128) {
        return byteVectorToInt({der.begin() + 2, der.begin() + 2 + ((int) der[1]) - 128});
    }
    return (int) der[1];
}

/**
 * DER is: type-length-value
 *
 * This function converts a number into the length bytes of der.
 */
inline byte_vector asn1_len(size_t length) {
    byte_vector result;
    if (length < 0x80) {
        // Short form: length is encoded in one byte
        result.push_back(static_cast<unsigned char>(length));
    } else {
        // Long form: length is encoded in multiple bytes
        byte_vector length_bytes;
        while (length > 0) {
            length_bytes.push_back(length & 0xFF);
            length >>= 8;
        }

        // The first byte is the number of subsequent bytes, with the high-order
        // bit set to indicate the long form.
        result.push_back(static_cast<unsigned char>(0x80 | length_bytes.size()));
        result.insert(result.end(), length_bytes.rbegin(), length_bytes.rend());
    }

    return result;
}

/**
 * DER is: type-length-value
 *
 * This function returns the DER value.
 */
inline byte_vector asn1_get_value(const byte_vector& der) {
    return {der.begin() + asn1_prefix_length(der), der.end()};
}

inline std::vector<byte_vector> parse_asn1_sequence(const byte_vector& der) {
    // Expects der elements to be in sequence
    byte_vector next(der.begin(), der.end());

    int obj_pl = asn1_prefix_length(next);
    int obj_vl = asn1_value_length(next);

    std::vector<byte_vector> objs(0);
    while (true) {
        objs.push_back({next.begin(), next.begin() + obj_pl + obj_vl});

        next = {next.begin() + obj_pl + obj_vl, next.end()};

        if (next.empty()) {
            break;
        }

        obj_pl = asn1_prefix_length(next);
        obj_vl = asn1_value_length(next);
    }

    return objs;
}

#endif
