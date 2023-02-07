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

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "controlleremrtd.hpp"

#include "threads/cardeventmonitorthread.hpp"
#include "threads/commandhandlerconfirmthreademrtd.hpp"
#include "threads/commandhandlerrunthreademrtd.hpp"
#include "threads/waitforcardthread.hpp"

#include "utils.hpp"
#include "inputoutputmode.hpp"
#include "writeresponse.hpp"

#include <QApplication>

using namespace pcsc_cpp;
using namespace electronic_id;

namespace
{

// TODO: Should we use more detailed error codes? E.g. report input data error back to the website
// etc.
const QString RESP_TECH_ERROR = QStringLiteral("ERR_WEBEID_NATIVE_FATAL");
const QString RESP_USER_CANCEL = QStringLiteral("ERR_WEBEID_USER_CANCELLED");

QVariantMap makeErrorObject(const QString& errorCode, const QString& errorMessage)
{
    const auto errorBody = QVariantMap {
        {QStringLiteral("code"), errorCode},
        {QStringLiteral("message"), errorMessage},
    };
    return {{QStringLiteral("error"), errorBody}};
}

void interruptThread(QThread* thread)
{
    qDebug() << "Interrupting thread" << uintptr_t(thread);
    thread->requestInterruption();
    ControllerChildThread::waitForControllerNotify.wakeAll();
}

} // namespace

void ControllerEmrtd::run()
{
    // If a command is passed, the application is in command-line mode, else in stdin/stdout mode.
    const bool isInCommandLineMode = bool(command);
    isInStdinMode = !isInCommandLineMode;

    qInfo() << qApp->applicationName() << "app" << qApp->applicationVersion() << "running in"
            << (isInStdinMode ? "stdin/stdout" : "command-line") << "mode";

    try {
        // TODO: cut out stdin mode separate class to avoid bugs in safari mode
        if (isInStdinMode) {
            // In stdin/stdout mode we first output the version as required by the WebExtension
            // and then wait for the actual command.
            writeResponseToStdOut(isInStdinMode,
                                  {{QStringLiteral("version"), qApp->applicationVersion()}},
                                  "get-version");

            command = readCommandFromStdin();
        }

        REQUIRE_NON_NULL(command)
        // If quit is requested, respond with empty JSON object and quit immediately.
        switch (command->first) {
        case CommandType::ABOUT:
            EmrtdUI::showAboutPage();
            return;
        case CommandType::QUIT:
            qInfo() << "Quit requested, exiting";
            writeResponseToStdOut(true, {}, "quit");
            emit quit();
            return;
        default:
            break;
        }

        commandHandler = getCommandHandlerEmrtd(*command);

        startCommandExecution();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void ControllerEmrtd::startCommandExecution()
{
    REQUIRE_NON_NULL(commandHandler)


    // Reader monitor thread setup.
    WaitForCardThread* waitForCardThread = new WaitForCardThread(this);
    connect(waitForCardThread, &WaitForCardThread::statusUpdate, this, &ControllerEmrtd::statusUpdate);
    connect(waitForCardThread, &WaitForCardThread::cardsAvailable, this,
            &ControllerEmrtd::onCardsAvailable);
    saveChildThreadPtrAndConnectFailureFinish(waitForCardThread);

    // UI setup.
    window = EmrtdUI::createAndShowDialog(commandHandler->commandType());

    connect(this, &ControllerEmrtd::statusUpdate, window, &EmrtdUI::onSmartCardStatusUpdate);

    // TODO: here should take the MRZ info
    connectOkCancelWaitingForMrz();

    // Finally, start the thread to wait for card insertion after everything is wired up.
    waitForCardThread->start();
}

void ControllerEmrtd::saveChildThreadPtrAndConnectFailureFinish(ControllerChildThread* childThread)
{
    REQUIRE_NON_NULL(childThread)
    // Save the thread pointer in child thread tracking map to request interruption and wait for
    // it to quit in waitForChildThreads().
    childThreads[uintptr_t(childThread)] = childThread;

    connect(childThread, &ControllerChildThread::failure, this, &ControllerEmrtd::onCriticalFailure);

    // When the thread is finished, remove the pointer from the tracking map and call deleteLater()
    // on it to free the thread object. Although the thread objects are freed through the Qt object
    // tree ownership system anyway, it is better to delete them immediately when they finish.
    connect(childThread, &ControllerChildThread::finished, this, [this, childThread]() {
        QScopedPointer<ControllerChildThread, QScopedPointerDeleteLater> deleteLater {childThread};

        const auto threadPtrAddress = uintptr_t(childThread);
        if (childThreads.count(threadPtrAddress) && childThreads[threadPtrAddress]) {
            childThreads[threadPtrAddress] = nullptr;
            childThread->wait();
            qDebug() << "Thread" << threadPtrAddress << "finished";
        } else {
            qWarning() << "Controller child thread" << childThread
                       << "is missing or null in finish slot";
        }
    });
}

void ControllerEmrtd::connectOkCancelWaitingForMrz()
{
    REQUIRE_NON_NULL(window)

    // TODO: wrong type is accepted here
    connect(window, &EmrtdUI::accepted, this, &ControllerEmrtd::onDialogOK);
    connect(window, &EmrtdUI::rejected, this, &ControllerEmrtd::onDialogCancel);
    connect(window, &EmrtdUI::failure, this, &ControllerEmrtd::onCriticalFailure);
    connect(window, &EmrtdUI::runEmrtd, this, &ControllerEmrtd::onConfirmCommandHandler);
}

void ControllerEmrtd::onCardsAvailable(const std::vector<electronic_id::CardInfo::ptr>& availableCards)
{
    try {
        REQUIRE_NON_NULL(commandHandler)

        REQUIRE_NON_NULL(window)
        REQUIRE_NOT_EMPTY_CONTAINS_NON_NULL_PTRS(availableCards)

        for (const auto& card : availableCards) {
            const auto protocol =
                card->eid().smartcard().protocol() == SmartCard::Protocol::T0 ? "T=0" : "T=1";
            qInfo() << "Card" << card->eid().name() << "in reader" << card->reader().name
                    << "using protocol" << protocol;
        }

        window->showWaitingForCardPage(commandHandler->commandType());

        commandHandler->connectSignals(window);

        runCommandHandler(availableCards);

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void ControllerEmrtd::runCommandHandler(const std::vector<electronic_id::CardInfo::ptr>& availableCards)
{
    try {
        CommandHandlerRunThreadEmrtd* commandHandlerRunThread =
            new CommandHandlerRunThreadEmrtd(this, *commandHandler, availableCards);
        saveChildThreadPtrAndConnectFailureFinish(commandHandlerRunThread);
        connectRetry(commandHandlerRunThread);

        // When the command handler run thread retrieves certificates successfully, call
        // onCertificatesLoaded() that starts card event monitoring while user enters the PIN.
        // TODO: onCertificatesLoaded is wrong - rename
        connect(commandHandler.get(), &CommandHandlerEmrtd::onAuthenticateWithEmrtd, this,
                &ControllerEmrtd::onCertificatesLoaded);

        commandHandlerRunThread->start();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void ControllerEmrtd::onCertificatesLoaded()
{
    CardEventMonitorThread* cardEventMonitorThread =
        new CardEventMonitorThread(this, std::string(commandType()));
    saveChildThreadPtrAndConnectFailureFinish(cardEventMonitorThread);
    cardEventMonitorThreadKey = uintptr_t(cardEventMonitorThread);
    connect(cardEventMonitorThread, &CardEventMonitorThread::cardEvent, this, &ControllerEmrtd::onRetry);
    cardEventMonitorThread->start();
}

void ControllerEmrtd::stopCardEventMonitorThread()
{
    if (cardEventMonitorThreadKey) {
        try {
            auto cardEventMonitorThread = childThreads.at(cardEventMonitorThreadKey);
            cardEventMonitorThreadKey = 0;
            if (cardEventMonitorThread) {
                interruptThread(cardEventMonitorThread);
            }
        } catch (const std::out_of_range&) {
            qWarning() << "Card event monitor thread" << cardEventMonitorThreadKey
                       << "is missing from childThreads map in stopCardEventMonitorThread()";
            cardEventMonitorThreadKey = 0;
        }
    }
}

void ControllerEmrtd::disposeUI()
{
    if (window) {
        window->disconnect();
        // As the Qt::WA_DeleteOnClose flag is set, the dialog is deleted automatically.
        window->close();
        window = nullptr;
    }
}

void ControllerEmrtd::onConfirmCommandHandler(const electronic_id::CardInfo::ptr cardInfo)
{
    stopCardEventMonitorThread();

    try {
        CommandHandlerConfirmThreadEmrtd* commandHandlerConfirmThread =
            new CommandHandlerConfirmThreadEmrtd(this, *commandHandler, window, *cardInfo);
        connect(commandHandlerConfirmThread, &CommandHandlerConfirmThreadEmrtd::completed, this,
                &ControllerEmrtd::onCommandHandlerConfirmCompleted);
        saveChildThreadPtrAndConnectFailureFinish(commandHandlerConfirmThread);
        connectRetry(commandHandlerConfirmThread);

        commandHandlerConfirmThread->start();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void ControllerEmrtd::onCommandHandlerConfirmCompleted(const QVariantMap& res)
{
    try {
        _result = res;
        writeResponseToStdOut(isInStdinMode, res, commandHandler->commandType());
    } catch (const std::exception& error) {
        qCritical() << "Command" << std::string(commandType())
                    << "fatal error while writing response to stdout:" << error;
    }
    exit();
}

void ControllerEmrtd::onRetry()
{
    try {
        // Dispose the UI, it will be re-created during next execution.
        disposeUI();
        // Command handler signals are still connected, disconnect them so that they can be
        // reconnected during next execution.
        commandHandler->disconnect();
        // Before restarting, wait until child threads finish.
        waitForChildThreads();

        startCommandExecution();

    } catch (const std::exception& error) {
        onCriticalFailure(error.what());
    }
}

void ControllerEmrtd::connectRetry(const ControllerChildThread* childThread)
{
    REQUIRE_NON_NULL(childThread)
    REQUIRE_NON_NULL(window)

    disconnect(window, &EmrtdUI::retry, nullptr, nullptr);

    connect(childThread, &ControllerChildThread::retry, window, &EmrtdUI::onRetry);
    // This connection handles cancel events from PIN pad.
    connect(childThread, &ControllerChildThread::cancel, this, &ControllerEmrtd::onDialogCancel);
    connect(window, &EmrtdUI::retry, this, &ControllerEmrtd::onRetry);
}

void ControllerEmrtd::onDialogOK(const electronic_id::CardInfo::ptr cardInfo)
{
    if (commandHandler) {
        onConfirmCommandHandler(cardInfo);
    } else {
        // This should not happen, and when it does, OK should be equivalent to cancel.
        onDialogCancel();
    }
}

void ControllerEmrtd::onDialogCancel()
{
    qDebug() << "User cancelled";
    _result = makeErrorObject(RESP_USER_CANCEL, QStringLiteral("User cancelled"));
    writeResponseToStdOut(isInStdinMode, _result, commandType());
    disposeUI();
    exit();
}

void ControllerEmrtd::onCriticalFailure(const QString& error)
{
    qCritical() << "Exiting due to command" << std::string(commandType())
                << "fatal error:" << error;
    _result = makeErrorObject(RESP_TECH_ERROR, error);
    writeResponseToStdOut(isInStdinMode, _result, commandType());
    disposeUI();
    EmrtdUI::showFatalError();
    exit();
}

void ControllerEmrtd::exit()
{
    waitForChildThreads();
    emit quit();
}

void ControllerEmrtd::waitForChildThreads()
{
    // Waiting for child threads must not happen in destructor.
    // See https://tombarta.wordpress.com/2008/07/10/gcc-pure-virtual-method-called/ for details.
    for (const auto& childThread : childThreads) {
        auto thread = childThread.second;
        if (thread) {
            interruptThread(thread);
            // Waiting for PIN input on PIN pad may take a long time, call processEvents() so that
            // the UI doesn't freeze.
            while (thread->isRunning()) {
                thread->wait(100); // in milliseconds
                QCoreApplication::processEvents();
            }
        }
    }
}

CommandType ControllerEmrtd::commandType()
{
    return commandHandler ? commandHandler->commandType() : CommandType(CommandType::INSERT_CARD);
}
