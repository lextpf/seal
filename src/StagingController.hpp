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
 * @brief Auto-arm a unique host-bound record from navigation reports.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * GUI thread only; not reentrant. Workspace, engine, and ui are borrowed and must
 * outlive this controller. Locked vaults are skipped without password prompts.
 * This controller holds no secrets; FillController owns decrypt and release.
 *
 * StageVisitTracker permits one username injection and one password fill per
 * remembered document, then leaves the visit inactive. Its bounded history can evict
 * old tokens; see `StageVisitTracker` for the retry and eviction rules.
 *
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
 *                                 |  (while its token remains in the tracker)
 *                                 |
 *                                 +--> injectUsername(idx) [once per visit, then
 *                                                          noteUsernameInjected]
 * @endverbatim
 */
class StagingController : public QObject
{
    Q_OBJECT

public:
    /**
     * @fn StagingController(CredentialWorkspace& workspace, FillController& engine, IUiFeedback&
     *     ui, QObject* parent = nullptr)
     * @brief Load the master switch and connect polling and fill completion.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The `bridge/autostage` setting defaults to false; enabling starts a 100 ms poll.
     * Completion latches a visit only while this controller owns the arm.
     * Completion, cancellation, and errors clear ownership.
     *
     * @param workspace Must outlive this controller.
     * @param engine Must outlive this controller.
     * @param ui Must outlive this controller.
     * @param parent Nullable for stack ownership.
     */
    StagingController(CredentialWorkspace& workspace,
                      FillController& engine,
                      IUiFeedback& ui,
                      QObject* parent = nullptr);

    /**
     * @fn ~StagingController()
     * @brief Stop polling and disconnect callbacks.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Destruction does not cancel the shared engine. Call `cancelActive()` first if
     * the engine will remain alive and its staged fill must end.
     */
    ~StagingController() override;

    /**
     * @fn void setEnabled(bool enabled)
     * @brief Start or stop polling and cancel owned auto-arms when disabled.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op if unchanged. Does not persist settings. Enabling can consume only an
     * unseen report within the 10 s bridge TTL; consumed reports are never replayed.
     */
    void setEnabled(bool enabled);

    /**
     * @fn bool isEnabled() const
     * @brief Whether the feature is currently enabled.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isEnabled() const;

    /**
     * @fn void cancelActive()
     * @brief Clear arm ownership and cancel only an owned AutoArmed session.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Manual arms remain active. Arm ownership clears in every case; completed-visit
     * latches and the navigation cursor remain, so cancellation does not replay a visit.
     */
    void cancelActive();

signals:
    /**
     * @fn void autoArmedForRecord(int recordIndex, const QString& platform)
     * @brief Notify a successful new auto-arm for account highlighting.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Username-only pages and duplicate reports emit nothing.
     *
     * @param recordIndex Vault-vector index; the UI must map it to a list row.
     * @param platform Cleartext display label suitable for status hints.
     */
    void autoArmedForRecord(int recordIndex, const QString& platform);

private slots:
    /**
     * @fn void onNavPollTick()
     * @brief Consume a fresh navigation and apply fail-closed staging gates.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Gates 1-5 leave the report unconsumed for a later poll within its 10 s TTL.
     * Only manual arms are protected; Diagnose may be cancelled by staging.
     * An already-armed visit/record does not reinstall hooks. Username injection also
     * checks navShouldInjectUsername.
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
     */
    void onNavPollTick();

private:
    /**
     * @fn bool perSiteEnabled() const
     * @brief Read bridge/navAutostagePerSite for each consumed navigation.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Defaults to false. The app provides no writer for this optional setting.
     */
    bool perSiteEnabled() const;

    /**
     * @fn bool siteAllowed(const std::string& hostKey) const
     * @brief Read bridge/navAllow/<hostKey> for one normalized host.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Default false. Entries authorize exact hosts, never subdomains. Enabling the
     * posture without manually adding entries prevents all staging.
     */
    bool siteAllowed(const std::string& hostKey) const;

    /**
     * @fn void dropArmOwnership()
     * @brief Clear visit and record bookkeeping without changing the engine.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @see cancelActive
     */
    void dropArmOwnership();

    CredentialWorkspace& m_Workspace;  ///< Borrowed; owns records/session.
    FillController& m_Engine;          ///< Borrowed; owns the bridge + hooks.
    IUiFeedback& m_Ui;                 ///< Borrowed status sink.

    QTimer m_NavPoll;  ///< GUI-thread poll (100 ms, repeating).
    /**
     * Cursor into the bridge's global nav sequence; only ever moves forward,
     * so a consumed report is never delivered twice.
     */
    std::uint64_t m_LastSeenSeq = 0;
    bool m_Enabled = false;    ///< Master switch (mirrors bridge/autostage).
    bool m_AutoArmed = false;  ///< True while this controller holds an auto-arm.

    StageVisitTracker m_Tracker;  ///< Once-per-visit latches (Qt-free, unit-tested).
    std::string m_ArmedVisit;     ///< Visit token of the live auto-arm; empty when none.
    int m_ArmedIndex = -1;        ///< Record index of the live auto-arm; -1 when none.
};

}  // namespace seal

#endif  // USE_QT_UI
