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

#include "../controller/commandhandleremrtd.hpp"

#include "../controller/command-handlers/emrtd/getemrtdcertificate.hpp"
#include "../controller/command-handlers/emrtd/authenticatewithemrtd.hpp"

// TODO:
// getCommandHandler() has to be defined in the app project so that a different
// mock implementation can be provided in the tests project.

CommandHandlerEmrtd::ptr getCommandHandlerEmrtd(const CommandWithArguments& cmd)
{
    auto cmdType = cmd.first;
    auto cmdCopy = CommandWithArguments {cmdType, cmd.second};

    switch (cmdType) {
    case CommandType::GET_EMRTD_SIGNING_CERTIFICATE:
        return std::make_unique<GetEmrtdCertificate>(cmdCopy);
    case CommandType::AUTHENTICATE_WITH_EMRTD:
        return std::make_unique<AuthenticateWithEmrtd>(cmdCopy);
    default:
        throw std::invalid_argument("Unknown command '" + std::string(cmdType)
                                    + "' in getCommandHandlerEmrtd()");
    }
}
