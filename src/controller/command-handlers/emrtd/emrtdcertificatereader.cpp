#include "emrtdcertificatereader.hpp"
#include "command-handlers/signauthutils.hpp"
#include "commandhandler.hpp" // TODO: using just for errors

// TODO: should probably read and verifiy cert as well.

EmrtdCertificateReader::EmrtdCertificateReader(const CommandWithArguments& cmd) : CommandHandlerEmrtd(cmd)
{
    validateAndStoreOrigin(cmd.second);
    if (Application* app = qobject_cast<Application*>(qApp)) {
        app->loadTranslations(cmd.second.value(QStringLiteral("lang")).toString());
    }
}

void EmrtdCertificateReader::run(const std::vector<CardInfo::ptr>& cards)
{
    REQUIRE_NOT_EMPTY_CONTAINS_NON_NULL_PTRS(cards);

    emit onEmrtdCommand(origin, cards[0]);
}

void EmrtdCertificateReader::connectSignals(const WebEidUI* window)
{
    window->disconnect(this);
    connect(this, &EmrtdCertificateReader::onEmrtdCommand, window,
            &WebEidUI::onEmrtdCommand);
}

void EmrtdCertificateReader::validateAndStoreOrigin(const QVariantMap& arguments)
{
    const auto originStr = validateAndGetArgument<QString>(QStringLiteral("origin"), arguments);
    if (originStr.size() > 255) {
        THROW(CommandHandlerInputDataError, "origin length cannot exceed 255 characters");
    }

    origin = QUrl(originStr, QUrl::ParsingMode::StrictMode);

    if (!origin.isValid()) {
        THROW(CommandHandlerInputDataError, "origin is not a valid URL");
    }
    if (origin.isRelative() || !origin.path().isEmpty() || origin.hasQuery()
        || origin.hasFragment()) {
        THROW(CommandHandlerInputDataError, "origin is not in <scheme>://<host>[:<port>] format");
    }
    /*
    if (origin.scheme() != QStringLiteral("https") && origin.scheme() != QStringLiteral("wss")) {
        THROW(CommandHandlerInputDataError, "origin scheme has to be https or wss");
    }
     */
}
