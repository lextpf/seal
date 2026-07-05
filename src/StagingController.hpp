#pragma once

#ifdef USE_QT_UI

#include "AutoStagePolicy.hpp"

#include <QObject>
#include <QString>
#include <QTimer>

#include <cstdint>
#include <string>

namespace seal
{

class CredentialWorkspace;
class FillController;
class IUiFeedback;

/**
 * @class StagingController
 * @brief Zero-gesture staged auto-fill: arm a record on matching navigation.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Owned collaborator (the AutoLockController pattern) - NOT a QML context
 * property. Polls the bridge's latest navigation snapshot on the GUI thread;
 * when the navigated host uniquely matches a vault record (fail-closed
 * @ref resolveStageRecord), it auto-arms that record via
 * @ref FillController::armAuto. A later plain click into a bridge-classified
 * login field completes the fill through the fail-closed auto gates in
 * FillController. The secret never crosses the bridge.
 *
 * Staging is **once per page visit** (@ref StageVisitTracker): per document
 * lifetime the username is injected at most once and the password click-fill
 * happens at most once; after the password fill the visit is inert - no nav
 * re-report (SPA churn, DOM mutation) stages anything again until the page
 * is reloaded or reopened (which mints a fresh visit token in content.js).
 *
 * Holds **no secret material**: it reads only cleartext record platform
 * labels and the non-secret navigation host. The vault must be unlocked for
 * staging to occur (checked via CredentialWorkspace::isPasswordSet); a locked
 * session is skipped silently and never triggers a master-password prompt.
 *
 * @verbatim
 *  Per page visit (one document lifetime; content.js mints the visit token):
 *
 *    nav report --> onNavPollTick (~100 ms, fail-closed)
 *                        |
 *                        v
 *                 resolveStageRecord(host)
 *                   None / Multiple --> do nothing (drop any prior auto-arm)
 *                   Single(idx) --+--> injectUsername(idx)  [DOM push, >=1 field]
 *                                 |        once per visit --> noteUsernameInjected
 *                                 +--> armAuto(idx)         [only if password field]
 *                                          |
 *                                 user makes a plain click on the password field
 *                                          |
 *                                          v
 *                            FillController types the password locally
 *                                          |
 *                                          v
 *                        notePasswordFilled --> visit INERT
 *                        (no re-arm / re-inject until the next page load)
 * @endverbatim
 *
 * @see FillController, AutoStagePolicy.hpp, AutoLockController
 */
class StagingController : public QObject
{
    Q_OBJECT

public:
    /**
     * @param workspace Owns records/session/generation (must outlive this).
     * @param engine    Fill engine that owns the bridge and does the arming.
     * @param ui        Status sink for non-secret hints.
     * @param parent    Owning QObject.
     */
    StagingController(CredentialWorkspace& workspace,
                      FillController& engine,
                      IUiFeedback& ui,
                      QObject* parent = nullptr);

    ~StagingController() override;

    /**
     * @brief Enable/disable the feature (master switch). Starts/stops the
     *        poll; disabling also drops any active auto-arm. Does not persist
     *        (BridgeViewModel owns the QSettings key).
     */
    void setEnabled(bool enabled);

    /// @brief Whether the feature is currently enabled.
    bool isEnabled() const;

    /**
     * @brief Drop an active auto-arm if this controller placed it (e.g. on M8
     *        bridge-disable or navigating away). No-op for a manual arm.
     */
    void cancelActive();

signals:
    /**
     * @brief A record was just auto-armed; @p recordIndex should be
     *        highlighted and @p platform surfaced as a non-secret hint.
     */
    void autoArmedForRecord(int recordIndex, const QString& platform);

private slots:
    /**
     * @brief ~100 ms poll: consume a fresh nav snapshot and run the staging
     *        state machine (all fail-closed).
     */
    void onNavPollTick();

private:
    /**
     * @brief Whether the optional per-site allow-list posture is on (the
     *        "bridge/navAutostagePerSite" QSettings toggle).
     */
    bool perSiteEnabled() const;

    /**
     * @brief Whether @p hostKey is on the user's per-site allow-list. Always
     *        false for an empty key.
     */
    bool siteAllowed(const std::string& hostKey) const;

    /**
     * @brief Forget which visit/record the live auto-arm belonged to (fill
     *        finished, cancelled, errored, or ownership dropped).
     */
    void dropArmOwnership();

    CredentialWorkspace& m_Workspace;  ///< Borrowed; owns records/session.
    FillController& m_Engine;          ///< Borrowed; owns the bridge + hooks.
    IUiFeedback& m_Ui;                 ///< Borrowed status sink.

    QTimer m_NavPoll;                 ///< GUI-thread poll (~100 ms). Never singleShot.
    std::uint64_t m_LastSeenSeq = 0;  ///< Cursor into the bridge's nav sequence.
    bool m_Enabled = false;           ///< Master switch (mirrors bridge/autostage).
    bool m_AutoArmed = false;         ///< True while THIS controller holds an auto-arm.

    StageVisitTracker m_Tracker;  ///< Once-per-visit latches (Qt-free, unit-tested).
    std::string m_ArmedVisit;     ///< Visit token the live auto-arm belongs to.
    int m_ArmedIndex = -1;        ///< Record index of the live auto-arm.
};

}  // namespace seal

#endif  // USE_QT_UI
