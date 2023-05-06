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

#include "authenticatewithemrtd.hpp"

#include "../signauthutils.hpp"

#include <QApplication>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QDir>

// Use common base64-encoding defaults.
constexpr auto BASE64_OPTIONS = QByteArray::Base64Encoding | QByteArray::KeepTrailingEquals;

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
    const QString& hashAlgorithm
) {
    // TODO: maybe rename algorithm to hashAlgorithm
    return QVariantMap {
        {"unverifiedPublicKeyInfo", publicKeyInfo},
        {"unverifiedPhoto", photo},
        {"unverifiedMrz", mrzEmrtd},
        {"unverifiedDocumentSecurityObject", documentSecurityObject},
        {"algorithm", hashAlgorithm},
        {"signature", signature},
        {"format", QStringLiteral("web-eid:1.0-emrtd")},
        {"appVersion",
         QStringLiteral("https://web-eid.eu/web-eid-app/releases/%1-emrtd")
             .arg(qApp->applicationVersion())},
    };
}

QVariantMap AuthenticateWithEmrtd::onConfirm(
    EmrtdUI* window,
    const electronic_id::CardInfo& cardInfo,
    const std::map<byte_vector, byte_vector> readFiles
) {
    // Getting the larger files off the chip will take time.
    window->showWaitingForTokenPage();

    byte_vector secret = readInfoFromIdAppletAndGetSecret(cardInfo.eid().smartcard());

    selectEmrtdApplet(cardInfo.eid().smartcard());

    SecureMessagingObject smo =
        BasicAccessControl::establishBacSessionKeys(secret, cardInfo.eid().smartcard());

    const auto mrzEmrtd = convertToBase64(readFiles.at({0x01, 0x01}));
    const auto photo = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x02});
    const auto publicKeyInfo = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x0f});
    const auto documentSecurityObject = readFileAndConvertToBase64(smo, cardInfo.eid().smartcard(), {0x01, 0x1d});

    byte_vector dg14 = smo.secureReadFile(cardInfo.eid().smartcard(), {0x01, 0x0E});
    const auto hashAlgorithmName = getHashAlgorithmName(dg14);

    const auto signature = createSignature(challengeNonce, origin.url(), hashAlgorithmName, smo, cardInfo.eid().smartcard());

    return createAuthenticationToken(
        signature,
        mrzEmrtd,
        publicKeyInfo,
        photo,
        documentSecurityObject,
        hashAlgorithmName
    );
}

QByteArray AuthenticateWithEmrtd::convertToBase64(const byte_vector data) {
    return QByteArray::fromRawData(reinterpret_cast<const char*>(data.data()),
                                   int(data.size()))
        .toBase64(BASE64_OPTIONS);
}

QByteArray AuthenticateWithEmrtd::readFileAndConvertToBase64(
    SecureMessagingObject& smo,
    const pcsc_cpp::SmartCard& card,
    byte_vector fileName
) {
    byte_vector fileData = smo.secureReadFile(card, fileName);
    return convertToBase64(fileData);
}

void AuthenticateWithEmrtd::connectSignals(const EmrtdUI* window) {
    EmrtdCertificateReader::connectSignals(window);
}

QByteArray AuthenticateWithEmrtd::createSignature(
    const QString& challengeNonce,
    const QString& origin,
    const QString& hashAlgorithmName,
    SecureMessagingObject& smo,
    const pcsc_cpp::SmartCard& card
) {
    // TODO: can be done with one action
    QCryptographicHash::Algorithm hashAlgo;
    if (hashAlgorithmName == "SHA224") {
        hashAlgo = QCryptographicHash::Sha224;
    } else if (hashAlgorithmName == "SHA256") {
        hashAlgo = QCryptographicHash::Sha256;
    } else if (hashAlgorithmName == "SHA384") {
        hashAlgo = QCryptographicHash::Sha384;
    } else if (hashAlgorithmName == "SHA512") {
        hashAlgo = QCryptographicHash::Sha512;
    }

    const auto originHash = QCryptographicHash::hash(origin.toUtf8(), hashAlgo);
    const auto challengeNonceHash = QCryptographicHash::hash(challengeNonce.toUtf8(), hashAlgo);

    const auto hashToBeSignedQBytearray =
        QCryptographicHash::hash(originHash + challengeNonceHash, hashAlgo);

    const byte_vector hashToBeSigned(hashToBeSignedQBytearray.cbegin(), hashToBeSignedQBytearray.cend());

    // Card can sign only 8 bytes
    byte_vector shortenedUnsignedToken(hashToBeSigned.begin(), hashToBeSigned.begin() + 8);

    byte_vector signature = smo.secureSend(card,
        pcsc_cpp::CommandApdu(0x00, 0x88, 0x00, 0x00, shortenedUnsignedToken, 0x00)
    );

    return QByteArray::fromRawData(reinterpret_cast<const char*>(signature.data()),
                                   int(signature.size()))
        .toBase64(BASE64_OPTIONS);
}

QString AuthenticateWithEmrtd::getHashAlgorithmName(
    byte_vector dg14
) {
    const auto rootValue = asn1_get_value(dg14);
    // This is all the securityinfo SEQUENCE objects from the SET
    std::vector<byte_vector> vecs = parse_asn1_sequence(rootValue);

    // 2.23.136.1.1.5
    byte_vector hashAlgorithmOid = {0x67, 0x81, 0x08, 0x01, 0x01, 0x05};
    for (const auto& vec : vecs) {
        const auto securityInfos = parse_asn1_sequence(asn1_get_value(vec));
        for (const auto& securityInfo : securityInfos) {
            const auto securityInfoElements = parse_asn1_sequence(asn1_get_value(securityInfo));
            const byte_vector oid = asn1_get_value(securityInfoElements.at(0)); // oid is first
            if (oid == hashAlgorithmOid) {
                const auto value = asn1_get_value(securityInfoElements.at(2));
                if (value == byte_vector{0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x02}) {
                    return QString::fromStdString("SHA224");
                } else if (value == byte_vector{0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x03}) {
                    return QString::fromStdString("SHA256");
                } else if (value == byte_vector{0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x04}) {
                    return QString::fromStdString("SHA384");
                } else if (value == byte_vector{0x04, 0x00, 0x7f, 0x00, 0x07, 0x01, 0x01, 0x04, 0x01, 0x05}) {
                    return QString::fromStdString("SHA512");
                }
            }
        }
    }
    throw std::runtime_error("Could not find the signature hash algorithm from SecurityInfos");
}


