#ifndef EMRTD_ENUMS_H
#define EMRTD_ENUMS_H

enum Alg {
    AES256,
    DES3
};

enum KeyType {
    ENC,
    MAC,
    PACE
};

enum MacAlg {
    DES,
    AES_CMAC
};

#endif
