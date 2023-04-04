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

// TODO: origin parameter in emrtd function
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "webeiddialog.hpp"
#include "application.hpp"
#include "punycode.hpp"

#include "emrtddialog.hpp"

// TODO: replace with new ui
#include "ui_autogen/include/emrtdui_dialog.h"

#include <QButtonGroup>
#include <QDesktopServices>
#include <QFile>
#include <QMenu>
#include <QMessageBox>
#include <QMutexLocker>
#include <QRegularExpressionValidator>
#include <QSettings>
#include <QStyle>
#include <QTimeLine>
#include <QUrl>
#include <application.hpp>

#ifdef Q_OS_LINUX
#include <stdio.h>
#include <unistd.h>
#endif

#if QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
constexpr inline QLatin1String operator"" _L1(const char* str, size_t size) noexcept
{
    return QLatin1String(str, int(size));
}
#else
using namespace Qt::Literals::StringLiterals;
#endif

using namespace electronic_id;

class EmrtdDialog::Private : public Ui::EmrtdDialog
{
public:
    // Non-owning observer pointers.
    QRegularExpressionValidator* pinInputValidator;
    QTimeLine* pinTimeoutTimer;
    QButtonGroup* selectionGroup;
};

EmrtdDialog::EmrtdDialog(QWidget* parent) : EmrtdUI(parent), ui(new Private)
{
    ui->setupUi(this);
    if (qApp->isDarkTheme()) {
        QFile f(QStringLiteral(":dark.qss"));
        if (f.open(QFile::ReadOnly | QFile::Text)) {
            setStyleSheet(styleSheet() + QTextStream(&f).readAll());
            ui->authenticationOriginLabel->setPixmap(pixmap("origin"_L1));
            ui->cardChipIcon->setPixmap(pixmap("no-id-card"_L1));
            ui->fatalErrorIcon->setPixmap(pixmap("fatal"_L1));
            ui->aboutIcon->setPixmap(pixmap("fatal"_L1));
            ui->helpButton->setIcon(QIcon(QStringLiteral(":/images/help_dark.svg")));
        }
    }
    setWindowFlag(Qt::CustomizeWindowHint);
    setWindowFlag(Qt::WindowTitleHint);
    setWindowTitle(qApp->applicationDisplayName());
    setTrText(ui->aboutVersion, [] { return tr("Version: %1").arg(qApp->applicationVersion()); });
    QMenu* langMenu = new QMenu(ui->langButton);
    langMenu->addAction(QStringLiteral("EN"));
    langMenu->addAction(QStringLiteral("ET"));
    langMenu->addAction(QStringLiteral("FI"));
    langMenu->addAction(QStringLiteral("HR"));
    langMenu->addAction(QStringLiteral("RU"));
    connect(langMenu, &QMenu::triggered, qApp, [this](QAction* action) {
        QSettings().setValue(QStringLiteral("lang"), action->text().toLower());
        ui->langButton->setText(action->text());
        qApp->loadTranslations();
    });
#ifdef Q_OS_LINUX
    setStyleSheet(styleSheet() + QStringLiteral("#langButton {padding-right: 15px;}"));
    connect(ui->langButton, &QToolButton::clicked, this, [this, langMenu] {
        langMenu->exec(mapToGlobal(ui->langButton->geometry().bottomLeft()));
    });
#else
    ui->langButton->setMenu(langMenu);
#endif
    ui->langButton->setText(
        QSettings().value(QStringLiteral("lang"), ui->langButton->text()).toString().toUpper());

    ui->waitingSpinner->load(QStringLiteral(":/images/wait.svg"));

    ui->selectionGroup = new QButtonGroup(this);
    ui->fatalError->hide();
    ui->fatalHelp->hide();

    connect(ui->pageStack, &QStackedWidget::currentChanged, this, &EmrtdDialog::resizeHeight);
    connect(ui->selectionGroup, qOverload<QAbstractButton*>(&QButtonGroup::buttonClicked), this,
            [this] { ui->okButton->setEnabled(true); });
    connect(ui->cancelButton, &QPushButton::clicked, this, &EmrtdDialog::reject);
    connect(ui->helpButton, &QPushButton::clicked, this, [this] {
        ui->helpButton->setDown(false);
#ifdef Q_OS_LINUX
        // Launching Chrome in Linux causes the message "Opening in existing browser session." to be
        // printed to stdout, which ruins the browser-app communication channel. Redirect stdout to
        // pipe before launching the browser and restore it after to avoid this.
        int unusedPipe[2];
        int pipeFailed = pipe(unusedPipe);
        int savedStdout;
        if (!pipeFailed) {
            savedStdout = dup(1); // Save the original stdout.
            dup2(unusedPipe[1], 1); // Redirect stdout to pipe.
        }
#endif
        QDesktopServices::openUrl(
            tr("https://www.id.ee/en/article/how-to-check-that-your-id-card-reader-is-working/"));
#ifdef Q_OS_LINUX
        if (!pipeFailed) {
            fflush(stdout);
            dup2(savedStdout, 1); // Restore the original stdout.
            ::close(unusedPipe[1]);
            ::close(unusedPipe[0]);
        }
#endif
    });
}

EmrtdDialog::~EmrtdDialog()
{
    delete ui;
}

void EmrtdDialog::showAboutPage()
{
    EmrtdDialog* d = new EmrtdDialog();
    d->setAttribute(Qt::WA_DeleteOnClose);
    d->ui->helpButton->hide();
    d->ui->aboutAlert->hide();
    auto app = static_cast<Application*>(QCoreApplication::instance());
    if (app->isSafariExtensionContainingApp()) {
        d->setupOK([app] { app->showSafariSettings(); },
                   [] { return tr("Open Safari settings..."); }, true);
        connect(app, &Application::safariExtensionEnabled, d, [d](bool value) {
            d->ui->aboutAlert->setHidden(value);
            d->resizeHeight();
        });
        app->requestSafariExtensionState();
    } else {
        d->ui->okButton->hide();
    }
    d->ui->pageStack->setCurrentIndex(int(Page::ABOUT));
    d->resizeHeight();
    d->open();
    connect(d, &EmrtdDialog::finished, qApp, &QApplication::quit);
}

void EmrtdDialog::showFatalErrorPage()
{
    EmrtdDialog* d = new EmrtdDialog();
    d->setAttribute(Qt::WA_DeleteOnClose);
    d->setTrText(d->ui->messagePageTitleLabel, [] { return tr("Operation failed"); });
    d->ui->fatalError->show();
    d->ui->fatalHelp->show();
    d->ui->connectCardLabel->hide();
    d->ui->cardChipIcon->hide();
    d->ui->helpButton->show();
    d->ui->cancelButton->show();
    d->ui->okButton->hide();
    d->ui->pageStack->setCurrentIndex(int(Page::ALERT));
    d->resizeHeight();
    d->exec();
}

void EmrtdDialog::showWaitingForCardPage(const CommandType commandType)
{
    currentCommand = commandType;

    // Don't show OK button while waiting for card operation or connect card.
    ui->okButton->hide();

    ui->pageStack->setCurrentIndex(int(Page::WAITING));
}

void EmrtdDialog::showWaitingForTokenPage()
{
    // TODO: Reusing the waiting for card page logic.
    //  Should probably have separate page.
    setTrText(ui->waitingPageTitleLabel, [] { return tr("Authenticating"); });

    ui->okButton->hide();

    ui->pageStack->setCurrentIndex(int(Page::WAITING));
}

void EmrtdDialog::onSmartCardStatusUpdate(const RetriableError status)
{
    currentCommand = CommandType::INSERT_CARD;

    setTrText(ui->connectCardLabel,
              [this, status] { return std::get<0>(retriableErrorToTextTitleAndIcon(status)); });
    setTrText(ui->messagePageTitleLabel,
              [this, status] { return std::get<1>(retriableErrorToTextTitleAndIcon(status)); });
    ui->cardChipIcon->setPixmap(std::get<2>(retriableErrorToTextTitleAndIcon(status)));

    // In case the insert card page is not shown, switch back to it.
    ui->helpButton->show();
    ui->cancelButton->show();
    ui->okButton->hide();
    ui->pageStack->setCurrentIndex(int(Page::ALERT));
}

void EmrtdDialog::onRetry(const RetriableError error)
{
    onRetryImpl([this, error] { return std::get<0>(retriableErrorToTextTitleAndIcon(error)); });
}

void EmrtdDialog::reject()
{
    EmrtdUI::reject();
}

bool EmrtdDialog::event(QEvent* event)
{
    if (event->type() == QEvent::LanguageChange) {
        ui->retranslateUi(this);
        emit languageChange();
        resizeHeight();
    }
    return EmrtdUI::event(event);
}

void EmrtdDialog::onRetryImpl(const std::function<QString()>& text)
{
    setTrText(ui->connectCardLabel, text);
    setTrText(ui->messagePageTitleLabel, [] { return tr("Operation failed"); });
    ui->cardChipIcon->setPixmap(pixmap("no-id-card"_L1));
    setupOK([this] { emit retry(); }, [] { return tr("Try again"); }, true);
    ui->pageStack->setCurrentIndex(int(Page::ALERT));
}

void EmrtdDialog::setTrText(QWidget* label, const std::function<QString()>& text)
{
    disconnect(this, &EmrtdDialog::languageChange, label, nullptr);
    label->setProperty("text", text());
    connect(this, &EmrtdDialog::languageChange, label,
            [label, text] { label->setProperty("text", text()); });
}

void EmrtdDialog::setupOK(const std::function<void()>& func, const std::function<QString()>& text,
                           bool enabled)
{
    ui->okButton->disconnect();
    connect(ui->okButton, &QPushButton::clicked, this, func);
    ui->okButton->show();
    ui->okButton->setEnabled(enabled);
    setTrText(
        ui->okButton, text ? text : [] { return tr("Confirm"); });
    ui->cancelButton->show();
    ui->cancelButton->setEnabled(true);
    ui->helpButton->hide();
}

void EmrtdDialog::resizeHeight()
{
    ui->pageStack->setFixedHeight(ui->pageStack->currentWidget()->sizeHint().height());
    adjustSize();
}

QPixmap EmrtdDialog::pixmap(QLatin1String name) const
{
    return {QStringLiteral(":/images/%1%2.svg")
                .arg(name, qApp->isDarkTheme() ? "_dark"_L1 : QLatin1String())};
}

std::tuple<QString, QString, QPixmap>
EmrtdDialog::retriableErrorToTextTitleAndIcon(const RetriableError error)
{
    switch (error) {
    case RetriableError::SMART_CARD_SERVICE_IS_NOT_RUNNING:
        return {tr("The smart card service required to use the ID-card is not running. Please "
                   "start the smart card service and try again."),
                tr("Launch the Smart Card service"), pixmap("cardreader"_L1)};
    case RetriableError::NO_SMART_CARD_READERS_FOUND:
        return {tr("<b>Card reader not connected.</b> Please connect the card reader to "
                   "the computer."),
                tr("Connect the card reader"), pixmap("cardreader"_L1)};

    case RetriableError::NO_SMART_CARDS_FOUND:
    case RetriableError::PKCS11_TOKEN_NOT_PRESENT:
        return {tr("<b>ID-card not found.</b> Please insert the ID-card into the reader."),
                tr("Insert the ID-card"), pixmap("no-id-card"_L1)};
    case RetriableError::SMART_CARD_WAS_REMOVED:
    case RetriableError::PKCS11_TOKEN_REMOVED:
        return {tr("The ID-card was removed from the reader. Please insert the ID-card into the "
                   "reader."),
                tr("Insert the ID-card"), pixmap("no-id-card"_L1)};

    case RetriableError::SMART_CARD_TRANSACTION_FAILED:
        return {tr("Operation failed. Make sure that the ID-card and the card reader are connected "
                   "correctly."),
                tr("Check the ID-card and the reader connection"), pixmap("no-id-card"_L1)};
    case RetriableError::FAILED_TO_COMMUNICATE_WITH_CARD_OR_READER:
        return {tr("Connection to the ID-card or reader failed. Make sure that the ID-card and the "
                   "card reader are connected correctly."),
                tr("Check the ID-card and the reader connection"), pixmap("no-id-card"_L1)};

    case RetriableError::SMART_CARD_CHANGE_REQUIRED:
        return {tr("The desired operation cannot be performed with the inserted ID-card. Make sure "
                   "that the ID-card is supported by the Web eID application."),
                tr("Operation not supported"), pixmap("no-id-card"_L1)};

    case RetriableError::SMART_CARD_COMMAND_ERROR:
        return {tr("Error communicating with the card."), tr("Operation failed"),
                pixmap("no-id-card"_L1)};
        // TODO: what action should the user take? Should this be fatal?
    case RetriableError::PKCS11_ERROR:
        return {tr("Card driver error. Please try again."), tr("Card driver error"),
                pixmap("no-id-card"_L1)};
        // TODO: what action should the user take? Should this be fatal?
    case RetriableError::SCARD_ERROR:
        return {tr("An error occurred in the Smart Card service required to use the ID-card. Make "
                   "sure that the ID-card and the card reader are connected correctly or relaunch "
                   "the Smart Card service."),
                tr("Operation failed"), pixmap("no-id-card"_L1)};

    case RetriableError::UNSUPPORTED_CARD:
        return {tr("The card in the reader is not supported. Make sure that the entered ID-card is "
                   "supported by the Web eID application."),
                tr("Operation not supported"), pixmap("no-id-card"_L1)};

    case RetriableError::NO_VALID_CERTIFICATE_AVAILABLE:
        return {tr("The inserted ID-card does not contain a certificate for the requested "
                   "operation. Please insert an ID-card that supports the requested operation."),
                tr("Operation not supported"), pixmap("no-id-card"_L1)};

    case RetriableError::PIN_VERIFY_DISABLED:
        return {
            tr("Operation failed. Make sure that the driver of the corresponding card reader is "
               "used. Read more <a "
               "href=\"https://www.id.ee/en/article/using-pinpad-card-reader-drivers/\">here</"
               "a>."),
            tr("Card driver error"), QStringLiteral(":/images/cardreader.svg")};

    case RetriableError::UNKNOWN_ERROR:
        return {tr("Unknown error"), tr("Unknown error"), pixmap("no-id-card"_L1)};
    }
    return {tr("Unknown error"), tr("Unknown error"), pixmap("no-id-card"_L1)};
}

// TODO: probably needs a similar thing like web eid code has: onMultipleCertificatesReady
void EmrtdDialog::onAuthenticateWithEmrtd(const QUrl& origin, const electronic_id::CardInfo::ptr cardInfo)
{
    ui->authenticationOriginLabel->setText(fromPunycode(origin));

    ui->pageStack->setCurrentIndex(int(Page::WAITING));

    switch (currentCommand) {
    case CommandType::GET_EMRTD_SIGNING_CERTIFICATE:
        emit accepted(cardInfo);
        break;
    case CommandType::AUTHENTICATE_WITH_EMRTD:
        setTrText(ui->authenticationPageTitleLabel, [] { return tr("Authenticate with EMRTD"); });
        setTrText(ui->authenticationDescriptionLabel, [] {
            return tr("By authenticating, I agree to the transfer the following data to the service provider:");
        });

        setupOK([this, cardInfo] { emit accepted(cardInfo); });
        insertItemToQListWidget(ui->authenticationItemList, "Name");
        insertItemToQListWidget(ui->authenticationItemList, "ID code");
        insertItemToQListWidget(ui->authenticationItemList, "Document number");
        insertItemToQListWidget(ui->authenticationItemList, "Birthday");
        insertItemToQListWidget(ui->authenticationItemList, "Birthplace");
        insertItemToQListWidget(ui->authenticationItemList, "Photo");
        break;
    default:
        emit failure(QStringLiteral("Only AUTHENTICATE_WITH_EMRTD, GET_EMRTD_SIGNING_CERTIFICATE allowed"));
        return;
    }

    ui->pageStack->setCurrentIndex(int(Page::AUTHENTICATE_WITH_EMRTD));
}

void EmrtdDialog::insertItemToQListWidget(
    QListWidget* list,
    const QString& text)
{
    QListWidgetItem* item = new QListWidgetItem(text);
    // Removing the selectable flag from the list item
    item->setFlags(item->flags() & ~Qt::ItemIsSelectable);

    list->insertItem(4, item);
}


