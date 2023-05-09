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

#include "application.hpp"
#include "controller.hpp"
#include "controlleremrtd.hpp"
#include "commands.hpp"
#include "logging.hpp"
#include "commands.hpp"

#include <QTimer>
#include <iostream>

#include "../controller/inputoutputmode.hpp"
#include "../controller/writeresponse.hpp"

CommandWithArgumentsPtr getCommand(CommandWithArgumentsPtr command, bool isInStdinMode);

int main(int argc, char* argv[])
{
   Q_INIT_RESOURCE(web_eid_resources);
   Q_INIT_RESOURCE(translations);

   Application app(argc, argv, QStringLiteral("web-eid"));
   CommandWithArgumentsPtr cmdWithArgsPtrStart = app.parseArgs();

   // If a command is passed, the application is in command-line mode, else in stdin/stdout mode.
   const bool isInStdinMode = !bool(cmdWithArgsPtrStart);

   CommandWithArgumentsPtr cmdWithArgsPtr = getCommand(std::move(cmdWithArgsPtrStart), isInStdinMode);


   if (cmdWithArgsPtr->first.getCommandTypeEnum() == CommandType::CommandTypeEnum::AUTHENTICATE_WITH_EMRTD) {
       try {
           ControllerEmrtd controller(std::move(cmdWithArgsPtr), isInStdinMode);

           QObject::connect(&controller, &ControllerEmrtd::quit, &app, &QApplication::quit);
           // Pass control to Controller::run() when the event loop starts.
           QTimer::singleShot(0, &controller, &ControllerEmrtd::run);

           return QApplication::exec();

       } catch (const ArgumentError& error) {
           // This error must go directly to cerr to avoid extra info from the logging system.
           std::cerr << error.what() << std::endl;
       } catch (const std::exception& error) {
           qCritical() << error;
       }
   } else {
       try {
           Controller controller(std::move(cmdWithArgsPtr), isInStdinMode);

           QObject::connect(&controller, &Controller::quit, &app, &QApplication::quit);
           // Pass control to Controller::run() when the event loop starts.
           QTimer::singleShot(0, &controller, &Controller::run);

           return QApplication::exec();

       } catch (const ArgumentError& error) {
           // This error must go directly to cerr to avoid extra info from the logging system.
           std::cerr << error.what() << std::endl;
       } catch (const std::exception& error) {
           qCritical() << error;
       }
   }

   return -1;
}

CommandWithArgumentsPtr getCommand(CommandWithArgumentsPtr command, bool isInStdinMode) {
    qInfo() << qApp->applicationName() << "app" << qApp->applicationVersion() << "running in"
            << (isInStdinMode ? "stdin/stdout" : "command-line") << "mode";

    // TODO: cut out stdin mode separate class to avoid bugs in safari mode
    if (isInStdinMode) {
        // In stdin/stdout mode we first output the version as required by the WebExtension
        // and then wait for the actual command.
        writeResponseToStdOut(isInStdinMode,
                              {{QStringLiteral("version"), qApp->applicationVersion()}},
                              "get-version");

        return readCommandFromStdin();
    }
    return command;
}
