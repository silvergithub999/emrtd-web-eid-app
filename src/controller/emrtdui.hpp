/*
 * Copyright (c) 2020-2022 Estonian Information System Authority
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

#include "commands.hpp"
#include "certandpininfo.hpp"
#include "retriableerror.hpp"

#include "observer_ptr.hpp"

#include "command-handlers/emrtd/securemessagingobject.hpp"

#include <QDialog>

/**
 * The UI interface implemented in the ui and mock-ui projects.
 */
class EmrtdUI : public QDialog
{
    Q_OBJECT

public:
    explicit EmrtdUI(QWidget* parent = nullptr) : QDialog(parent) {}

    // Factory function that creates and shows the dialog that implements this interface.
    static observer_ptr<EmrtdUI> createAndShowDialog(const CommandType command);

    static void showAboutPage();
    static void showFatalError();

    virtual void showWaitingForCardPage(const CommandType commandType) = 0;

    virtual void showWaitingForTokenPage() = 0;

signals:
    void accepted(
        const electronic_id::CardInfo::ptr cardInfo,
        const std::map<pcsc_cpp::byte_vector, pcsc_cpp::byte_vector> readFiles,
        const SecureMessagingObject& smo
        );
    void retry();
    void failure(const QString& error);

public: // slots
    virtual void quit() = 0;
    virtual void onSmartCardStatusUpdate(const RetriableError status) = 0;
    virtual void onRetry(const RetriableError error) = 0;
    virtual void onAuthenticateWithEmrtd(const QUrl& origin,
                                const electronic_id::CardInfo::ptr cardInfo) = 0;
};
