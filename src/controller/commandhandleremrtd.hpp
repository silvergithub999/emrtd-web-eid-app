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

#include "ui.hpp"

/** Interface for command handlers that implement the actual work the application does, like get
 * certificate, authenticate and sign. */
class CommandHandlerEmrtd : public QObject
{
    Q_OBJECT

public:
    using ptr = std::unique_ptr<CommandHandlerEmrtd>;

    virtual void run(const std::vector<electronic_id::CardInfo::ptr>& cards) = 0;
    virtual void connectSignals(const WebEidUI* window) = 0;
    virtual QVariantMap onConfirm(WebEidUI* window,
                                  const electronic_id::CardInfo& cardInfo) = 0;

    CommandType commandType() const { return command.first; }

signals:
    void retry(const RetriableError error);

    // TODO: rename
    void onEmrtdCommand(const QUrl& origin, electronic_id::CardInfo::ptr cardInfo);

protected:
    CommandHandlerEmrtd(const CommandWithArguments& cmd) : command(cmd) {}
    CommandWithArguments command;
};

CommandHandlerEmrtd::ptr getCommandHandlerEmrtd(const CommandWithArguments& cmd);
