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
 * Owned collaborator, not a QML context property. Polls the bridge's latest
 * navigation snapshot on the GUI thread. When the navigated host uniquely
 * matches a vault record (@ref resolveStageRecord, fail closed), it auto-arms
 * that record through @ref FillController::armAuto. A later plain click into a
 * bridge-classified login field completes the fill through FillController's own
 * auto gates.
 *
 * @par Once per page visit
 * @ref StageVisitTracker bounds one document lifetime: the username is injected
 * at most once, the password click-filled at most once. After the password fill
 * the visit is inert until a reload or reopen mints a fresh token in content.js.
 *
 * @par Secrets
 * This class holds none. It reads cleartext platform labels and the non-secret
 * navigation host; every decrypt belongs to FillController. The password is
 * typed locally with SendInput and never crosses the bridge. The username is
 * pushed to the extension as a just-in-time decrypted directive
 * (@ref FillController::injectUsername), which is why that half is strictly
 * host-bound.
 *
 * @par Locked vault
 * Staging needs an unlocked vault (CredentialWorkspace::isPasswordSet). A
 * locked session is skipped silently and never raises a master-password prompt.
 *
 * @par Threading and lifetime
 * GUI thread only. The poll, the engine calls and the visit tracker are
 * single-threaded and not reentrant. `workspace`, `engine` and `ui` are
 * borrowed and must outlive this object; QmlMain declares them first.
 *
 * @par Staging flow
 * @verbatim
 *  Per page visit (one document lifetime; content.js mints the visit token):
 *
 *    nav report --> onNavPollTick (100 ms, fail-closed gate ladder)
 *                        |
 *                        v
 *                 resolveStageRecord(host)
 *                   None     --> drop any prior auto-arm
 *                   Multiple --> drop the arm, hint in the status bar
 *                   Single(idx) --+--> armAuto(idx)        [only if password field]
 *                                 |        |
 *                                 |        v
 *                                 |  user plain-clicks the password field
 *                                 |        |
 *                                 |        v
 *                                 |  FillController types the password locally
 *                                 |        |
 *                                 |        v
 *                                 |  notePasswordFilled --> visit inert
 *                                 |  (no re-arm / re-inject until next page load)
 *                                 |
 *                                 +--> injectUsername(idx) [once per visit, then
 *                                                          noteUsernameInjected]
 * @endverbatim
 *
 * @see FillController, AutoStagePolicy.hpp, AutoLockController
 */
class StagingController : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Read the master switch, then wire the poll and the engine's fill
     *        signals.
     *
     * Reads `bridge/autostage` (default false) once and starts the 100 ms poll
     * when it is set, so staging is live before QML loads. fillCompleted,
     * fillCancelled and fillError all drop arm ownership. fillCompleted also
     * latches the visit inert, but only while this controller owns the arm: an
     * auto fill is by construction the password, while a manual Ctrl+Click fill
     * must not spend the visit.
     *
     * @param workspace Records, session and generation; must outlive this object.
     * @param engine    Fill engine that owns the bridge and does the arming.
     * @param ui        Status sink for non-secret hints.
     * @param parent    Owning QObject, or nullptr for a stack-owned instance
     *                  (QmlMain uses the stack).
     */
    StagingController(CredentialWorkspace& workspace,
                      FillController& engine,
                      IUiFeedback& ui,
                      QObject* parent = nullptr);

    ~StagingController() override;

    /**
     * @brief Enable or disable the feature (master switch).
     *
     * A no-op when the value is unchanged. The setter persists nothing:
     * BridgeViewModel writes the `bridge/autostage` key and QmlMain relays its
     * change signal here.
     *
     * Enabling replays nothing, because the nav cursor only moves forward. An
     * already-open page stages only while its report is unconsumed and inside
     * the bridge's 10 s freshness window; otherwise staging resumes on the next
     * navigation.
     *
     * @param enabled true starts the poll; false stops it and drops an auto-arm
     *                this controller placed.
     */
    void setEnabled(bool enabled);

    /// @brief Whether the feature is currently enabled.
    bool isEnabled() const;

    /**
     * @brief Drop an auto-arm this controller placed.
     *
     * The engine is cancelled only when this controller owns the arm and the
     * engine is still in FillController::State::AutoArmed, so a manual
     * Ctrl+Click arm is never disturbed. Arm ownership (visit token and record
     * index) is cleared in every case. Called on M8 bridge-disable, on
     * navigating away, on an ambiguous match, on a spent visit, and when the
     * master switch goes off.
     */
    void cancelActive();

signals:
    /**
     * @brief A record was just auto-armed; @p recordIndex should be
     *        highlighted and @p platform surfaced as a non-secret hint.
     *
     * Emitted only when FillController::armAuto succeeded, so a page without a
     * password field (an email-first screen) injects the username without
     * emitting anything. A re-report of the already staged visit and record
     * emits nothing either.
     *
     * @param recordIndex Index into the vault record vector, not a QML list
     *                    row; AppViewModel maps it to a row before selecting.
     * @param platform    Stored cleartext platform label, not a secret, so the
     *                    status bar may show it.
     */
    void autoArmedForRecord(int recordIndex, const QString& platform);

private slots:
    /**
     * @brief 100 ms poll: consume a fresh nav snapshot and run the staging
     *        state machine (all gates fail closed).
     *
     * Every gate is a silent skip, not an error. Gates 1 to 5 return before the
     * snapshot is consumed, so a report that arrives while the vault is locked
     * or the UI is busy still stages on a later tick, as long as it stays inside
     * the bridge's 10 s nav freshness window.
     *
     * @verbatim
     *   1 enabled?            no  -> return        master switch off
     *   2 vault unlocked?     no  -> return        never prompts for a password
     *   3 UI idle?            no  -> return        IUiFeedback::isBusy
     *   4 bridge enabled?     no  -> cancelActive  M8 panic disable
     *   5 manual arm live?    yes -> return        never disturb Ctrl+Click
     *   6 new nav snapshot?   no  -> return        takeNavSince cursor
     *   7 secure login page?  no  -> cancelActive  https and (password or user)
     *   8 site allowed?       no  -> cancelActive  only when the posture is on
     *   9 unique record?      no  -> cancelActive  None, or Multiple plus hint
     *  10 visit still live?   no  -> cancelActive  spent or empty visit token
     *  11 password field?     yes -> armAuto       skipped on an email-first screen
     *  12 username not done?  yes -> injectUsername
     * @endverbatim
     *
     * @par Gate notes
     * - Gate 5 reads FillController::isArmed, which is false in
     *   FillController::State::Diagnose, so gate 11 tears a running diagnose
     *   session down. Only a manual Ctrl+Click arm is protected.
     * - Gate 11 is skipped when the same visit and record are already armed, so
     *   a re-report installs no hooks again.
     * - Gate 12 also evaluates @ref navShouldInjectUsername, which gate 7 has
     *   already satisfied; the predicate stays as defense in depth.
     */
    void onNavPollTick();

private:
    /**
     * @brief Whether the optional per-site allow-list posture is on (the
     *        `bridge/navAutostagePerSite` QSettings toggle, default false).
     *
     * Nothing in the app writes this key; it is a hand-set hardening posture,
     * re-read for each consumed navigation, so an edit takes effect without a
     * restart.
     *
     * @return true when the allow-list must authorize the host before staging.
     */
    bool perSiteEnabled() const;

    /**
     * @brief Whether @p hostKey is on the user's per-site allow-list.
     *
     * Reads the QSettings key `bridge/navAllow/<hostKey>`, default false. An
     * entry authorizes one exact host ("accounts.google.com"), not a
     * registrable domain and not its subdomains. Nothing writes these keys
     * either, so turning the posture on without hand-adding entries stops
     * staging completely.
     *
     * @param hostKey Normalised host from @ref seal::url::extractHost.
     * @return true when the key exists and is true; false for an empty
     *         @p hostKey and for a host with no entry.
     */
    bool siteAllowed(const std::string& hostKey) const;

    /**
     * @brief Forget which visit and record the live auto-arm belonged to (fill
     *        finished, cancelled, errored, or ownership dropped).
     *
     * Bookkeeping only: it never touches the engine. A caller that must also
     * tear the arm down goes through @ref cancelActive.
     */
    void dropArmOwnership();

    CredentialWorkspace& m_Workspace;  ///< Borrowed; owns records/session.
    FillController& m_Engine;          ///< Borrowed; owns the bridge + hooks.
    IUiFeedback& m_Ui;                 ///< Borrowed status sink.

    QTimer m_NavPoll;  ///< GUI-thread poll (100 ms, repeating).
    /// Cursor into the bridge's global nav sequence; only ever moves forward,
    /// so a consumed report is never delivered twice.
    std::uint64_t m_LastSeenSeq = 0;
    bool m_Enabled = false;    ///< Master switch (mirrors bridge/autostage).
    bool m_AutoArmed = false;  ///< True while this controller holds an auto-arm.

    StageVisitTracker m_Tracker;  ///< Once-per-visit latches (Qt-free, unit-tested).
    std::string m_ArmedVisit;     ///< Visit token of the live auto-arm; empty when none.
    int m_ArmedIndex = -1;        ///< Record index of the live auto-arm; -1 when none.
};

}  // namespace seal

#endif  // USE_QT_UI
