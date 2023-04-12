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

#pragma once

#include "emrtdcertificatereader.hpp"
#include "../../../../lib/libelectronic-id/lib/libpcsc-cpp/include/pcsc-cpp/pcsc-cpp.hpp"
#include "securemessagingobject.hpp"
#include "../../commandhandler.hpp" // TODO: errors used
#include "../emrtd/utils/bac.hpp"
#include "../../certandpininfo.hpp"

using byte_vector = std::vector<unsigned char>;

class AuthenticateWithEmrtd : public EmrtdCertificateReader
{
   Q_OBJECT

public:
   explicit AuthenticateWithEmrtd(const CommandWithArguments& cmd);

   void connectSignals(const EmrtdUI* window) override;
   QVariantMap onConfirm(EmrtdUI* window, const electronic_id::CardInfo& cardInfo) override;

private:
   QString challengeNonce;

   QByteArray createSignature(
       const QString& challengeNonce,
       const QString& origin,
       const QString& hashAlgorithmName,
       SecureMessagingObject& smo,
       const pcsc_cpp::SmartCard& card
   );

   QByteArray readFileAndConvertToBase64(
       SecureMessagingObject& smo,
       const pcsc_cpp::SmartCard& card,
       byte_vector fileName
   );

   QString getHashAlgorithmName(byte_vector dg14);
};
