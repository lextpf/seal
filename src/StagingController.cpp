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
// GUI-thread poll interval. Fast enough to arm before a human clicks (the
// release gesture is hundreds of ms to seconds away), cheap enough to run
// continuously (takeNavSince is a short mutex + sequence compare).
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
    // Initial state from the persisted master switch (default false).
    // BridgeViewModel owns the key; this constructor only reads it.
    const QSettings settings;
    m_Enabled = settings.value(QString::fromLatin1(kKeyAutoStage), false).toBool();

    m_NavPoll.setInterval(kNavPollIntervalMs);
    connect(&m_NavPoll, &QTimer::timeout, this, &StagingController::onNavPollTick);

    // Leaving an armed state (fill done / cancelled / error) drops the ownership
    // flag, so a later manual arm is not mistaken for this one. A completed fill
    // that this controller armed is by construction the password, so it latches the
    // visit inert. A manual Ctrl+Click fill also completes here and must not spend
    // the visit.
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
    // Only cancel an arm this controller placed; never disturb a manual arm.
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
    // Never trigger a master-password prompt from a background poll: a locked
    // vault does not stage. Auto-lock therefore bounds the exposure window.
    if (!m_Workspace.isPasswordSet())
    {
        return;
    }
    if (m_Ui.isBusy())
    {
        return;
    }
    // If the bridge was panic-disabled (M8), drop any active auto-arm and stop.
    if (!m_Engine.isBridgeEnabled())
    {
        cancelActive();
        return;
    }
    // Never override a manual Ctrl+Click arm; only re-stage over an own auto-arm.
    if (m_Engine.isArmed() && !m_AutoArmed)
    {
        return;
    }

    const auto nav = m_Engine.takeNavSince(m_LastSeenSeq);
    if (!nav.has_value())
    {
        return;  // Nothing new since last poll.
    }

    // A login page has a visible password field or a login identifier field
    // (the email-first / multi-step first screen). A navigation to a non-login
    // or insecure page drops any auto-arm this controller holds.
    if (!nav->m_Secure || (!nav->m_HasPasswordForm && !nav->m_HasUsernameField))
    {
        cancelActive();
        return;
    }

    // Per-site allow-list (optional stricter posture). When enabled, only
    // sites the user explicitly trusted may auto-stage.
    if (perSiteEnabled() && !siteAllowed(seal::url::extractHost(nav->m_Host)))
    {
        cancelActive();
        return;
    }

    const StageResolution res = resolveStageRecord(m_Workspace.records(), nav->m_Host);

    // One diagnostic line per consumed navigation, so a page that does not arm
    // stays explainable. The host is logged as a length only, per the bridge's
    // privacy convention. result=none with records>0 means no record platform is a
    // domain matching this host ("PayPal" does not match "paypal.com").
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
            // Once-per-visit gate: a visit whose password was click-filled is inert
            // and an empty token fails closed. StageVisitTracker defines what counts
            // as one visit.
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
            // Arm the password click-fill path only when a password field is present
            // (password screen or combined form). An email-first first screen has
            // nothing to click-fill yet: no hooks are installed, only the username is
            // injected. A re-report of the already staged visit and record is a no-op.
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
            // Zero-click username fill, once per visit, on any page that
            // navShouldInjectUsername accepts. content.js fills nothing when it finds
            // no username field. FillController decrypts just-in-time, so this path
            // stays decrypt-free.
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
            // Ambiguous: do not guess. Drop any prior auto-arm and hint.
            cancelActive();
            m_Ui.setStatus(QStringLiteral("Multiple saved records match this site"));
            break;
        case StageResolution::Kind::None:
            // Navigated away from the staged site (or no match): drop the arm.
            cancelActive();
            break;
    }
}

}  // namespace seal

#endif  // USE_QT_UI
