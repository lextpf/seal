#ifdef USE_QT_UI

#include "StagingController.hpp"

#include "AutoStagePolicy.hpp"
#include "CredentialWorkspace.hpp"
#include "Diagnostics.hpp"
#include "FillController.hpp"
#include "IUiFeedback.hpp"
#include "Logging.hpp"
#include "UrlBinding.hpp"

#include <QtCore/QSettings>
#include <QtCore/QString>

namespace seal
{

namespace
{

constexpr int kNavPollIntervalMs = 100;

constexpr char kKeyAutoStage[] = "bridge/autostage";
constexpr char kKeyPerSite[] = "bridge/navAutostagePerSite";
}  // namespace

StagingController::StagingController(CredentialWorkspace& workspace,
                                     FillController& engine,
                                     IUiFeedback& ui,
                                     QObject* parent)
    : QObject(parent),
      m_Workspace(workspace),
      m_Engine(engine),
      m_Ui(ui)
{
    // BridgeViewModel persists this setting; staging only reads it.
    const QSettings settings;
    m_Enabled = settings.value(QString::fromLatin1(kKeyAutoStage), false).toBool();

    m_NavPoll.setInterval(kNavPollIntervalMs);
    connect(&m_NavPoll, &QTimer::timeout, this, &StagingController::onNavPollTick);

    // spend the visit only for an owned auto fill; manual completion shares this signal.
    connect(&m_Engine,
            &FillController::fillCompleted,
            this,
            [this](const QString&)
            {
                if (m_AutoArmed)
                {
                    m_Tracker.notePasswordFilled(m_ArmedVisit);
                }
                dropArmOwnership();
            });
    connect(&m_Engine, &FillController::fillCancelled, this, [this] { dropArmOwnership(); });
    connect(&m_Engine,
            &FillController::fillError,
            this,
            [this](const QString&) { dropArmOwnership(); });

    if (m_Enabled)
    {
        m_NavPoll.start();
    }
}

StagingController::~StagingController() = default;

bool StagingController::isEnabled() const
{
    return m_Enabled;
}

void StagingController::setEnabled(bool enabled)
{
    if (m_Enabled == enabled)
    {
        return;
    }
    m_Enabled = enabled;
    if (m_Enabled)
    {
        m_NavPoll.start();
    }
    else
    {
        m_NavPoll.stop();
        cancelActive();
    }
    qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=fill.autostage.toggle", seal::diag::kv("enabled", m_Enabled ? 1 : 0)}));
}

void StagingController::cancelActive()
{
    if (m_AutoArmed && m_Engine.state() == FillController::State::AutoArmed)
    {
        m_Engine.cancel();
    }
    dropArmOwnership();
}

void StagingController::dropArmOwnership()
{
    m_AutoArmed = false;
    m_ArmedVisit.clear();
    m_ArmedIndex = -1;
}

bool StagingController::perSiteEnabled() const
{
    const QSettings settings;
    return settings.value(QString::fromLatin1(kKeyPerSite), false).toBool();
}

bool StagingController::siteAllowed(const std::string& hostKey) const
{
    if (hostKey.empty())
    {
        return false;
    }
    const QSettings settings;
    const QString key = QStringLiteral("bridge/navAllow/") + QString::fromStdString(hostKey);
    return settings.value(key, false).toBool();
}

void StagingController::onNavPollTick()
{
    if (!m_Enabled)
    {
        return;
    }
    // skip locked vaults without prompting; auto-lock bounds staging exposure.
    if (!m_Workspace.isPasswordSet())
    {
        return;
    }
    if (m_Ui.isBusy())
    {
        return;
    }

    if (!m_Engine.isBridgeEnabled())
    {
        cancelActive();
        return;
    }

    if (m_Engine.isArmed() && !m_AutoArmed)
    {
        return;
    }

    const auto nav = m_Engine.takeNavSince(m_LastSeenSeq);
    if (!nav.has_value())
    {
        return;  // nothing new since last poll.
    }

    if (!nav->m_Secure || (!nav->m_HasPasswordForm && !nav->m_HasUsernameField))
    {
        cancelActive();
        return;
    }

    if (perSiteEnabled() && !siteAllowed(seal::url::extractHost(nav->m_Host)))
    {
        cancelActive();
        return;
    }

    const StageResolution res = resolveStageRecord(m_Workspace.records(), nav->m_Host);

    // log host length only. result=none may indicate bare labels that cannot bind domains.
    const char* outcome = res.m_Kind == StageResolution::Kind::Single     ? "single"
                          : res.m_Kind == StageResolution::Kind::Multiple ? "multiple"
                                                                          : "none";
    std::size_t nonDeleted = 0;
    for (const auto& r : m_Workspace.records())
    {
        if (!r.deleted)
        {
            ++nonDeleted;
        }
    }
    qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=fill.autostage.match",
         seal::diag::kv("result", std::string_view(outcome)),
         seal::diag::kv("host_len", static_cast<unsigned int>(nav->m_Host.size())),
         seal::diag::kv("records", static_cast<unsigned int>(nonDeleted))}));

    switch (res.m_Kind)
    {
        case StageResolution::Kind::Single:
        {
            const int idx = res.m_Index;

            if (m_Tracker.passwordDone(nav->m_Visit))
            {
                qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.stage",
                     "result=skip",
                     seal::diag::kv("reason",
                                    std::string_view(nav->m_Visit.empty() ? "visit_missing"
                                                                          : "visit_done"))}));
                cancelActive();
                break;
            }
            // identifier-only pages inject usernames without installing password-click hooks.
            if (nav->m_HasPasswordForm)
            {
                const bool alreadyStaged = m_AutoArmed &&
                                           m_Engine.state() == FillController::State::AutoArmed &&
                                           m_ArmedVisit == nav->m_Visit && m_ArmedIndex == idx;
                if (!alreadyStaged)
                {
                    const bool armed = m_Engine.armAuto(idx,
                                                        m_Workspace.records(),
                                                        m_Workspace.session(),
                                                        m_Workspace.generation());
                    if (armed)
                    {
                        m_AutoArmed = true;
                        m_ArmedVisit = nav->m_Visit;
                        m_ArmedIndex = idx;
                        emit autoArmedForRecord(
                            idx, QString::fromUtf8(m_Workspace.records()[idx].platform.c_str()));
                    }
                }
            }
            // latch only after a successful push so failed sends can retry.
            if (navShouldInjectUsername(nav->m_HasUsernameField, nav->m_HasPasswordForm) &&
                !m_Tracker.usernameDone(nav->m_Visit))
            {
                if (m_Engine.injectUsername(idx,
                                            m_Workspace.records(),
                                            m_Workspace.session(),
                                            nav->m_Host,
                                            nav->m_Visit,
                                            nav->m_BrowserPid))
                {
                    m_Tracker.noteUsernameInjected(nav->m_Visit);
                }
            }
            break;
        }
        case StageResolution::Kind::Multiple:

            cancelActive();
            m_Ui.setStatus(QStringLiteral("Multiple saved records match this site"));
            break;
        case StageResolution::Kind::None:

            cancelActive();
            break;
    }
}

}  // namespace seal

#endif  // USE_QT_UI
