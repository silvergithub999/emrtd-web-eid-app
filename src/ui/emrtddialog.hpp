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

#include "emrtdui.hpp"

#include <QCloseEvent>
#include <QListWidget>
#include <map>
#include <string>

class EmrtdDialog final : public EmrtdUI
{
    Q_OBJECT

public:
    enum class Page { WAITING, ALERT, AUTHENTICATE_WITH_EMRTD, ABOUT };

    explicit EmrtdDialog(QWidget* parent = nullptr);
    ~EmrtdDialog() final;

    void showWaitingForCardPage(const CommandType commandType) final;

    void showWaitingForTokenPage() final;

    static void showAboutPage();
    static void showFatalErrorPage();

    // slots
    void onSmartCardStatusUpdate(const RetriableError status) final;

    void onRetry(const RetriableError error) final;

    void quit() final
    {
        closeUnconditionally = true;
        close();
    }

    void onAuthenticateWithEmrtd(const QUrl& origin, const electronic_id::CardInfo::ptr cardInfo);

signals:
    void languageChange();

private:
    bool event(QEvent* event) final;
    void reject() final;

    void closeEvent(QCloseEvent* event) final
    {
        if (closeUnconditionally) {
            event->accept();
        } else {
            EmrtdUI::closeEvent(event);
        }
    }

    void onRetryImpl(const std::function<QString()>& text);

    void setTrText(QWidget* label, const std::function<QString()>& text);

    void setupOK(const std::function<void()>& func, const std::function<QString()>& text = {},
                 bool enabled = true);

    void resizeHeight();

    void insertItemToQListWidget(QListWidget* list, const QString& key, const QString& value);

    Q_DISABLE_COPY(EmrtdDialog)
    EmrtdDialog(EmrtdDialog&&) = delete;
    EmrtdDialog& operator=(EmrtdDialog&&) = delete;

    QPixmap pixmap(QLatin1String name) const;
    std::tuple<QString, QString, QPixmap> retriableErrorToTextTitleAndIcon(RetriableError error);

    std::map<std::string, std::string> parseMrz(pcsc_cpp::byte_vector dg01);

    class Private;
    Private* ui;

    CommandType currentCommand = CommandType::NONE;
    bool closeUnconditionally = false;
};
