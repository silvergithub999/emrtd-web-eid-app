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

#include "controllerchildthread.hpp"

class CommandHandlerConfirmThreadEmrtd : public ControllerChildThread
{
   Q_OBJECT

public:
    CommandHandlerConfirmThreadEmrtd(QObject* parent, CommandHandlerEmrtd& handler, EmrtdUI* w,
                               const electronic_id::CardInfo& cardInfo,
                               const std::map<pcsc_cpp::byte_vector, pcsc_cpp::byte_vector> readFiles) :
       ControllerChildThread(parent),
       commandHandler(handler), cmdType(commandHandler.commandType()), window(w),
       cardInfo(cardInfo), readFiles(readFiles)
   {
   }

signals:
   void completed(const QVariantMap& result);

private:
   void doRun() override
   {
       const auto result = commandHandler.onConfirm(window, cardInfo, readFiles);
       emit completed(result);
   }

   const std::string& commandType() const override { return cmdType; }

   CommandHandlerEmrtd& commandHandler;
   const std::string cmdType;
   EmrtdUI* window;
   electronic_id::CardInfo cardInfo;
   const std::map<pcsc_cpp::byte_vector, pcsc_cpp::byte_vector> readFiles;
};
