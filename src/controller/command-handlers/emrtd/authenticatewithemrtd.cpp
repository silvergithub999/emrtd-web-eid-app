/*
* Copyright (c) 2020-2021 Estonian Information System Authority
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
 */

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "authenticatewithemrtd.hpp"

#include "../signauthutils.hpp"

#include "../../../../lib/libelectronic-id/lib/libpcsc-cpp/include/pcsc-cpp/pcsc-cpp.hpp"
#include "../../../../lib/libelectronic-id/include/electronic-id/enums.hpp"

#include <QApplication>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QDir>

#include "../signauthutils.hpp"

#include <map>

#include <openssl/x509.h>
#include <openssl/err.h>

#include <openssl/asn1.h>

#include <map>
#include <qt5/QtCore/QVariantMap>
#include <qt5/QtCore/QCryptographicHash>
#include <qt5/QtCore/QByteArray>

// Use common base64-encoding defaults.
constexpr auto BASE64_OPTIONS = QByteArray::Base64Encoding | QByteArray::KeepTrailingEquals;

using namespace electronic_id;

AuthenticateWithEmrtd::AuthenticateWithEmrtd(const CommandWithArguments& cmd) : EmrtdCertificateReader(cmd)
{
    const auto arguments = cmd.second;
    requireArgumentsAndOptionalLang({"challengeNonce", "origin"}, arguments,
                                    "\"challengeNonce\": \"<challenge nonce>\", "
                                    "\"origin\": \"<origin URL>\"");

    challengeNonce = validateAndGetArgument<QString>(QStringLiteral("challengeNonce"), arguments);
    // nonce must contain at least 256 bits of entropy and is usually Base64-encoded, so the
    // required byte length is 44, the length of 32 Base64-encoded bytes.
    if (challengeNonce.length() < 44) {
        THROW(CommandHandlerInputDataError,
              "Challenge nonce argument 'challengeNonce' must be at least 44 characters long");
    }
    if (challengeNonce.length() > 128) {
        THROW(CommandHandlerInputDataError,
              "Challenge nonce argument 'challengeNonce' cannot be longer than 128 characters");
    }
    validateAndStoreOrigin(arguments);
}

QVariantMap createAuthenticationToken(
    const QByteArray& signature,
    const QByteArray& mrzEmrtd,
    const QByteArray& publicKeyInfo,
    const QByteArray& photo,
    const QByteArray& documentSecurityObject,
    const QString& signatureAlgorithm
) {
    return QVariantMap {
        {"unverifiedPublicKeyInfo", publicKeyInfo},
        {"unverifiedPhoto", photo},
        {"unverifiedMrz", mrzEmrtd},
        {"unverifiedDocumentSecurityObject", documentSecurityObject},
        {"algorithm", signatureAlgorithm},
        {"signature", signature},
        {"format", QStringLiteral("web-eid:1.0-emrtd")},
        {"appVersion",
         QStringLiteral("https://web-eid.eu/web-eid-app/releases/%1-emrtd")
             .arg(qApp->applicationVersion())},
    };
}

QVariantMap AuthenticateWithEmrtd::onConfirm(
    EmrtdUI* window,
    const electronic_id::CardInfo& cardInfo
) {
    // TODO: add transaction guard
    // auto transactionGuard = cardInfo.eid().smartcard()->beginTransaction();

    byte_vector secret = readInfoFromIdAppletAndGetSecret(cardInfo.eid().smartcard());

    selectEmrtdApplet(cardInfo.eid().smartcard());

    SecureMessagingObject smo =
        BasicAccessControl::establishBacSessionKeys(secret, cardInfo.eid().smartcard());

    const auto mrzEmrtd = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x01});
    const auto photo = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x02});
    const auto publicKeyInfo = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x0f});
    const auto documentSecurityObject = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x1d});

    const auto signature = createSignature(challengeNonce, origin.url(), smo, cardInfo.eid().smartcard());

    return createAuthenticationToken(
        signature,
        mrzEmrtd,
        publicKeyInfo,
        photo,
        documentSecurityObject,
        // TODO: check what type of key and what typo of hashing alg - no hardcoding
        "ES256"
        );
}

QByteArray AuthenticateWithEmrtd::readFileAndConvertToBase64(
    SecureMessagingObject& smo,
    const pcsc_cpp::SmartCard& card,
    byte_vector fileName
)
{
    byte_vector fileData = smo.readFile(card, fileName);
    return QByteArray::fromRawData(reinterpret_cast<const char*>(fileData.data()),
                                   int(fileData.size()))
        .toBase64(BASE64_OPTIONS);
}

void AuthenticateWithEmrtd::connectSignals(const EmrtdUI* window) {
    EmrtdCertificateReader::connectSignals(window);
}

QByteArray AuthenticateWithEmrtd::createSignature(
    const QString& challengeNonce,
    const QString& origin,
    SecureMessagingObject& smo,
    const pcsc_cpp::SmartCard& card
) {
    auto hashAlgo = QCryptographicHash::Sha256;

    const auto originHash = QCryptographicHash::hash(origin.toUtf8(), hashAlgo);
    const auto challengeNonceHash = QCryptographicHash::hash(challengeNonce.toUtf8(), hashAlgo);

    const auto hashToBeSignedQBytearray =
        QCryptographicHash::hash(originHash + challengeNonceHash, hashAlgo);

    const byte_vector hashToBeSigned(hashToBeSignedQBytearray.cbegin(), hashToBeSignedQBytearray.cend());

    // Card can sign only 8 bytes
    byte_vector shortenedUnsignedToken(hashToBeSigned.begin(), hashToBeSigned.begin() + 8);

    byte_vector signature = smo.send(card,
        pcsc_cpp::CommandApdu(0x00, 0x88, 0x00, 0x00, shortenedUnsignedToken, 0x00)
    );

    return QByteArray::fromRawData(reinterpret_cast<const char*>(signature.data()),
                                   int(signature.size()))
        .toBase64(BASE64_OPTIONS);
}