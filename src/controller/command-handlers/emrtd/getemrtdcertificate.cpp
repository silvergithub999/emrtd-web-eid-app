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

// TODO

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"

#include <stdexcept>
#include "getemrtdcertificate.hpp"

#include <QApplication>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QDir>

#include "../signauthutils.hpp"

using namespace electronic_id;

namespace
{

constexpr auto BASE64_OPTIONS = QByteArray::Base64Encoding | QByteArray::KeepTrailingEquals;

QVariantList supportedSigningAlgos(const ElectronicID& eid)
{
   QVariantList algos;
   for (const SignatureAlgorithm& signAlgo : eid.supportedSigningAlgorithms()) {
       algos.push_back(signatureAlgoToVariantMap(signAlgo));
   }
   return algos;
}

} // namespace

GetEmrtdCertificate::GetEmrtdCertificate(const CommandWithArguments& cmd) : EmrtdCertificateReader(cmd)
{
   const auto arguments = cmd.second;
   requireArgumentsAndOptionalLang({"origin"}, arguments, "\"origin\": \"<origin URL>\"");
}

QVariantMap GetEmrtdCertificate::onConfirm(EmrtdUI* /* window */,
                                           const electronic_id::CardInfo& cardInfo)
{
    // auto transactionGuard = cardInfo.eid().smartcard()->beginTransaction();

    byte_vector mrz = readInfoFromIdAppletAndGetMrz(cardInfo.eid().smartcard());

    selectEmrtdApplet(cardInfo.eid().smartcard());

    SecureMessagingObject smo =
        BasicAccessControl::establishBacSessionKeys(mrz, cardInfo.eid().smartcard());

    const auto dg15 = readDG15(smo, cardInfo.eid().smartcard());

    return QVariantMap {
        {"certificate", dg15},
    };
}

QByteArray GetEmrtdCertificate::readDG15(
    SecureMessagingObject& smo,
    const pcsc_cpp::SmartCard& card
)
{
    // TODO: same code as in authenticatewithemrtd.cpp/hpp
    byte_vector dg15 = smo.readFile(card, {0x01, 0x0f});
    return QByteArray::fromRawData(reinterpret_cast<const char*>(dg15.data()),
                                   int(dg15.size()))
        .toBase64(BASE64_OPTIONS);
}
