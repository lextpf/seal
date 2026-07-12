#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
std::string readSourceFile(const std::string& relativePath)
{
    const std::filesystem::path path = std::filesystem::path(SEAL_SOURCE_DIR) / relativePath;
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("failed to open " + path.string());
    }

    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

bool sourceFileExists(const std::string& relativePath)
{
    return std::filesystem::exists(std::filesystem::path(SEAL_SOURCE_DIR) / relativePath);
}

void expectAbsent(const std::string& haystack, const std::string& needle)
{
    EXPECT_EQ(haystack.find(needle), std::string::npos)
        << "Forbidden UI secret boundary: " << needle;
}

void expectPresent(const std::string& haystack, const std::string& needle)
{
    EXPECT_NE(haystack.find(needle), std::string::npos)
        << "Expected MVVM naming boundary: " << needle;
}
}  // namespace

TEST(UiSecretBoundaryTest, EditFlowDoesNotExposeStoredPasswordsToQml)
{
    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string appViewModelCpp = readSourceFile("src/AppViewModel.cpp");
    const std::string mainQml = readSourceFile("qml/Main.qml");
    const std::string accountDialog = readSourceFile("qml/AccountDialog.qml");

    expectAbsent(appViewModelHeader, "decryptAccountForEdit");
    expectAbsent(appViewModelCpp, "decryptAccountForEdit");
    expectAbsent(appViewModelCpp, "result[\"password\"]");
    expectAbsent(appViewModelCpp, "data[\"password\"]");
    expectAbsent(mainQml, "data.password");
    expectAbsent(accountDialog, "property string initialPassword");
    expectAbsent(accountDialog, "text: root.initialPassword");
}

TEST(UiSecretBoundaryTest, EmbeddedCliDoesNotPersistGeneratedOrDecodedSecretsInOutput)
{
    const std::string cliHandler = readSourceFile("src/CliHandler.cpp");
    const std::string cliPanel = readSourceFile("qml/CliPanel.qml");

    expectAbsent(cliHandler, "QString::fromUtf8(password.data()");
    expectAbsent(cliHandler, "QString::fromStdString(hex)");
    expectAbsent(cliHandler, "QString::fromStdString(text)");
    expectAbsent(cliPanel, "\"seal> \" + inputField.text");
}

TEST(UiSecretBoundaryTest, ClipboardRawWritesAreNotPublicApi)
{
    const std::string clipboardHeader = readSourceFile("src/Clipboard.hpp");

    const std::size_t publicPos = clipboardHeader.find("public:");
    const std::size_t privatePos = clipboardHeader.find("private:");
    const std::size_t setTextPos = clipboardHeader.find("static bool setText(");

    ASSERT_NE(publicPos, std::string::npos);
    ASSERT_NE(privatePos, std::string::npos);
    ASSERT_NE(setTextPos, std::string::npos);
    EXPECT_GT(setTextPos, privatePos);
}

TEST(MvvmNamingTest, QmlFacingSurfaceIsNamedAppViewModel)
{
    EXPECT_TRUE(sourceFileExists("src/AppViewModel.hpp"));
    EXPECT_TRUE(sourceFileExists("src/AppViewModel.cpp"));
    EXPECT_FALSE(sourceFileExists("src/Backend.hpp"));
    EXPECT_FALSE(sourceFileExists("src/Backend.cpp"));

    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string appViewModelCpp = readSourceFile("src/AppViewModel.cpp");
    const std::string qmlMain = readSourceFile("src/QmlMain.cpp");
    const std::string cmake = readSourceFile("CMakeLists.txt");

    expectPresent(appViewModelHeader, "class AppViewModel");
    expectPresent(appViewModelCpp, "AppViewModel::AppViewModel");
    expectPresent(qmlMain, "setContextProperty(\"AppViewModel\"");
    expectPresent(cmake, "src/AppViewModel.cpp");

    expectAbsent(appViewModelHeader, "class Backend");
    expectAbsent(appViewModelCpp, "Backend::");
    expectAbsent(qmlMain, "setContextProperty(\"Backend\"");
    expectAbsent(cmake, "src/Backend.cpp");
}

TEST(MvvmNamingTest, BridgeCollaboratorUsesViewModelNaming)
{
    EXPECT_TRUE(sourceFileExists("src/BridgeViewModel.hpp"));
    EXPECT_TRUE(sourceFileExists("src/BridgeViewModel.cpp"));
    EXPECT_FALSE(sourceFileExists("src/BridgePresenter.hpp"));
    EXPECT_FALSE(sourceFileExists("src/BridgePresenter.cpp"));

    const std::string bridgeHeader = readSourceFile("src/BridgeViewModel.hpp");
    const std::string bridgeCpp = readSourceFile("src/BridgeViewModel.cpp");
    const std::string cmake = readSourceFile("CMakeLists.txt");

    expectPresent(bridgeHeader, "class BridgeViewModel");
    expectPresent(bridgeCpp, "BridgeViewModel::BridgeViewModel");
    expectPresent(cmake, "src/BridgeViewModel.cpp");

    expectAbsent(bridgeHeader, "BridgePresenter");
    expectAbsent(bridgeCpp, "BridgePresenter");
    expectAbsent(cmake, "src/BridgePresenter.cpp");
}

TEST(MvvmCommandRoutingTest, CliEchoClassificationLivesInCliHandler)
{
    const std::string cliHandlerHeader = readSourceFile("src/CliHandler.hpp");
    const std::string cliHandlerCpp = readSourceFile("src/CliHandler.cpp");

    expectPresent(cliHandlerHeader, "QString CliEchoLine(const QString& command)");
    expectPresent(cliHandlerCpp, "QString CliEchoLine(const QString& command)");
}

TEST(MvvmCommandRoutingTest, CliTranscriptIsOwnedByTheCliPanelViewModel)
{
    // The CLI transcript moved to CliPanelViewModel (the "Cli" context
    // property); the view binds Cli.cliOutputText, not AppViewModel's.
    const std::string cliHeader = readSourceFile("src/CliPanelViewModel.hpp");
    const std::string cliCpp = readSourceFile("src/CliPanelViewModel.cpp");
    const std::string cliPanel = readSourceFile("qml/CliPanel.qml");

    expectPresent(cliHeader, "QString cliOutputText");
    expectPresent(cliCpp, "appendCliOutput(seal::CliEchoLine(trimmed))");
    expectPresent(cliPanel, "Cli.cliOutputText");

    expectAbsent(cliHeader, "cliOutputReady");
    expectAbsent(cliHeader, "cliOutputCleared");
    expectAbsent(cliPanel, "commandEcho");
    expectAbsent(cliPanel, "_appendOutput");
    expectAbsent(cliPanel, "_maxLines");
}

TEST(MvvmCommandRoutingTest, QrResultRoutingIsDecidedByTheViewModel)
{
    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string mainQml = readSourceFile("qml/Main.qml");

    expectAbsent(appViewModelHeader, "Q_INVOKABLE void handleQrResultForCli");
    expectAbsent(mainQml, "handleQrResultForCli");
}

TEST(MvvmCommandRoutingTest, ViewModelOwnsRowResolutionAndDomainGestures)
{
    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string appViewModelCpp = readSourceFile("src/AppViewModel.cpp");
    const std::string mainQml = readSourceFile("qml/Main.qml");

    expectPresent(appViewModelHeader, "Q_INVOKABLE void armFillForRow(int row)");
    expectPresent(appViewModelHeader, "Q_INVOKABLE void armFillForSelection()");
    expectPresent(appViewModelHeader, "Q_INVOKABLE void requestEditSelected()");
    expectPresent(appViewModelHeader, "Q_INVOKABLE void requestDeleteSelected()");
    expectPresent(appViewModelCpp, "emit confirmDeleteRequested(");
    expectPresent(appViewModelCpp, "emit editAccountRequested(");

    expectAbsent(mainQml, "recordIndexForRow");
    expectAbsent(mainQml, "accountMetadataForEdit");
    expectAbsent(appViewModelHeader, "accountMetadataForEdit");
    expectAbsent(appViewModelHeader, "Q_INVOKABLE void armFill(int index)");
}

TEST(MvvmCommandRoutingTest, SortModeFlowsThroughTheViewModel)
{
    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string vaultModelHeader = readSourceFile("src/VaultModel.hpp");
    const std::string accountsGrid = readSourceFile("qml/AccountsGrid.qml");
    const std::string mainQml = readSourceFile("qml/Main.qml");

    expectPresent(appViewModelHeader, "int sortMode READ sortMode WRITE setSortMode");
    expectPresent(mainQml, "property: \"sortMode\"");

    expectAbsent(accountsGrid, "setSortMode");
    expectAbsent(vaultModelHeader, "Q_INVOKABLE");
}

TEST(MvvmCommandRoutingTest, QmlViewsNeverResolveRowsMutateModelsOrUseDeadSignals)
{
    const std::filesystem::path qmlDir = std::filesystem::path(SEAL_SOURCE_DIR) / "qml";
    for (const auto& entry : std::filesystem::directory_iterator(qmlDir))
    {
        if (!entry.is_regular_file() || entry.path().extension() != ".qml")
        {
            continue;
        }

        const std::string contents =
            readSourceFile((std::filesystem::path("qml") / entry.path().filename()).string());
        expectAbsent(contents, "recordIndexForRow");
        expectAbsent(contents, "setSortMode");
        expectAbsent(contents, "commandEcho");
        expectAbsent(contents, "handleQrResultForCli");
        expectAbsent(contents, "accountMetadataForEdit");
    }

    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    expectAbsent(appViewModelHeader, "addAccountRetryRequired");
}

TEST(MvvmNamingTest, QmlUsesAppViewModelAndDoesNotBindControllersDirectly)
{
    const std::filesystem::path qmlDir = std::filesystem::path(SEAL_SOURCE_DIR) / "qml";
    for (const auto& entry : std::filesystem::directory_iterator(qmlDir))
    {
        if (!entry.is_regular_file() || entry.path().extension() != ".qml")
            continue;

        const std::string contents =
            readSourceFile((std::filesystem::path("qml") / entry.path().filename()).string());
        expectAbsent(contents, "Backend.");
        expectAbsent(contents, "target: Backend");
    }

    const std::string qmlMain = readSourceFile("src/QmlMain.cpp");
    expectAbsent(qmlMain, "setContextProperty(\"FillController\"");
    expectAbsent(qmlMain, "setContextProperty(\"WindowController\"");
}

TEST(Top5FeaturesTest, RekeyFlowIsViewModelMediatedAndSecretSafe)
{
    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string appViewModelCpp = readSourceFile("src/AppViewModel.cpp");
    const std::string rekeyDialog = readSourceFile("qml/RekeyDialog.qml");
    const std::string headerBar = readSourceFile("qml/HeaderBar.qml");

    expectPresent(appViewModelHeader,
                  "Q_INVOKABLE void rekeyVault(QString currentPassword, QString newPassword)");
    expectPresent(appViewModelHeader, "void rekeyFinished(bool success, const QString& message)");
    expectPresent(appViewModelCpp, "seal::rekeyVault(");
    expectPresent(rekeyDialog, "AppViewModel.rekeyVault(");
    expectPresent(headerBar, "rekeyClicked");

    // The dialog must clear its fields after submission and never bind
    // password text to anything but the two invocation arguments.
    expectPresent(rekeyDialog, "function clearFields()");
    expectAbsent(rekeyDialog, "vaultModel");
}

TEST(Top5FeaturesTest, AutoLockIsViewModelOwnedAndInvisibleToQml)
{
    const std::string appViewModelCpp = readSourceFile("src/AppViewModel.cpp");
    expectPresent(appViewModelCpp, "AutoLockController");

    const std::filesystem::path qmlDir = std::filesystem::path(SEAL_SOURCE_DIR) / "qml";
    for (const auto& entry : std::filesystem::directory_iterator(qmlDir))
    {
        if (!entry.is_regular_file() || entry.path().extension() != ".qml")
        {
            continue;
        }
        const std::string contents =
            readSourceFile((std::filesystem::path("qml") / entry.path().filename()).string());
        expectAbsent(contents, "AutoLockController");
        expectAbsent(contents, "autoLockSecs");
    }
}

TEST(SecretOwnership, AppViewModelOwnsKeyOnlyViaCredentialWorkspace)
{
    const std::string src = readSourceFile("src/AppViewModel.cpp");
    const std::string hdr = readSourceFile("src/AppViewModel.hpp");
    // The trio members are gone; ownership lives in CredentialWorkspace, which
    // in turn owns the CredentialSession.
    EXPECT_EQ(hdr.find("m_DPAPIGuard"), std::string::npos);
    EXPECT_EQ(hdr.find("m_PasswordSet"), std::string::npos);
    EXPECT_NE(hdr.find("CredentialWorkspace& m_Workspace"), std::string::npos);
    // No direct DPAPI/trio mutation remains in the .cpp.
    EXPECT_EQ(src.find("m_DPAPIGuard"), std::string::npos);
    EXPECT_EQ(src.find("m_PasswordSet"), std::string::npos);
    EXPECT_EQ(src.find("ScopedDpapiUnprotect"),
              std::string::npos);  // replaced by m_Workspace.session().unlock()
}

TEST(PendingAction, SingleAssignerNoLastWriterWins)
{
    const std::string src = readSourceFile("src/AppViewModel.cpp");
    const std::string hdr = readSourceFile("src/AppViewModel.hpp");
    // The single overwrite-able slot is gone; a FIFO queue replaces it.
    EXPECT_EQ(hdr.find("std::function<void()> m_PendingAction"), std::string::npos);
    EXPECT_NE(hdr.find("std::deque<std::function<void()>> m_PendingActions"), std::string::npos);
    // No site assigns the continuation directly; they all route via ensurePassword.
    EXPECT_EQ(src.find("m_PendingAction ="), std::string::npos);
    EXPECT_NE(src.find("ensurePassword("), std::string::npos);
}

TEST(FillPlaintextWindow, NarrowedToDecryptInstant)
{
    const std::string fcH = readSourceFile("src/FillController.hpp");
    const std::string fcSrc = readSourceFile("src/FillController.cpp");
    const std::string vmSrc = readSourceFile("src/AppViewModel.cpp");
    const std::string tcSrc = readSourceFile("src/TypeController.cpp");

    // FillController borrows the session, not a pre-unprotected buffer: the
    // legacy const-ref master-password member/parameter is gone.
    EXPECT_NE(fcH.find("CredentialSession"), std::string::npos);
    EXPECT_NE(fcH.find("CredentialSession* m_Session"), std::string::npos);
    EXPECT_EQ(fcH.find("m_MasterPw"), std::string::npos);
    EXPECT_EQ(fcSrc.find("m_MasterPw"), std::string::npos);

    // performType opens a scoped unlock() so the key is plaintext only for the
    // decrypt; the very next call hands access.password() to the decrypt.
    EXPECT_NE(fcSrc.find("m_Session->unlock()"), std::string::npos);
    EXPECT_NE(fcSrc.find("decryptCredentialOnDemand(record, access.password())"),
              std::string::npos);

    // Arming no longer pre-unprotects the key for the whole armed window: the
    // session is handed straight to arm() rather than access.password(). After
    // Task 8 the arm site lives in TypeController and pulls records/session/
    // generation from the injected CredentialWorkspace.
    EXPECT_NE(tcSrc.find("m_Engine.arm(index, m_Workspace.records(), "
                         "m_Workspace.session(), m_Workspace.generation())"),
              std::string::npos);
    // AppViewModel no longer references the fill engine directly.
    EXPECT_EQ(vmSrc.find("m_FillController"), std::string::npos);

    // The 60s fill reprotect safety net is gone. Neither AppViewModel.cpp nor
    // TypeController.cpp uses QTimer::singleShot; an absent (not merely
    // "unique") singleShot is the robust signal - re-introducing the timer
    // would re-add a singleShot and fail this assertion.
    EXPECT_EQ(vmSrc.find("singleShot"), std::string::npos);
    EXPECT_EQ(tcSrc.find("singleShot"), std::string::npos);
}

TEST(StagedAutofillBoundary, StagingNeverDecryptsAndReleaseFailsClosed)
{
    const std::string scSrc = readSourceFile("src/StagingController.cpp");
    const std::string fcSrc = readSourceFile("src/FillController.cpp");
    const std::string bvmSrc = readSourceFile("src/BridgeViewModel.cpp");
    const std::string clipboardSrc = readSourceFile("src/Clipboard.cpp");
    const std::string qm = readSourceFile("src/QmlMain.cpp");

    // Staging only selects + arms; it never decrypts, unlocks, or prompts for
    // the master password. The plaintext window stays at the click-time
    // decrypt in FillController, so these must be absent from the poll.
    expectAbsent(scSrc, "decryptCredentialOnDemand");
    expectAbsent(scSrc, "unlock()");
    expectAbsent(scSrc, "ensurePassword");
    // The nav poll is a repeating timer, never a one-shot reprotect net.
    expectAbsent(scSrc, "singleShot");

    // The auto-fill release path is hardened: injected clicks are rejected,
    // the fused verdict must be on-disk corroborated (decideDetailed), and the
    // classification / host / foreground gates fail closed.
    expectPresent(fcSrc, "LLMHF_INJECTED");
    expectPresent(fcSrc, "decideDetailed");
    expectPresent(fcSrc, "reason=no_bridge_entry");
    expectPresent(fcSrc, "reason=host_mismatch");
    expectPresent(fcSrc, "reason=foreground_pid_mismatch");
    // Nav-mode host binding goes through the shared secret-release matcher:
    // only records storing a real domain/URL can release browser credentials.
    expectPresent(fcSrc, "url::platformMatchesHostForSecretRelease(record.platform, pageHost)");
    // Manual Ctrl+Click uses the same strict domain-aware matcher and refuses
    // browser fills when no fresh bridge URL exists.
    expectPresent(fcSrc, "reason=no_bridge_entry_manual");
    expectPresent(fcSrc, "reason=manual_foreground_pid_mismatch");
    expectPresent(fcSrc, "url::platformMatchesHostForSecretRelease(record.platform,");
    expectPresent(fcSrc, "manualPageHost))");
    expectAbsent(fcSrc, "keysMatch(recordKey, pageKey)");
    // armAuto is a distinct entry (keeps the manual arm() call string intact).
    expectPresent(fcSrc, "armAuto");

    // Staged auto-fill is opt-in: the master switch defaults to false.
    expectPresent(bvmSrc, "\"bridge/autostage\", false");

    // StagingController is an owned collaborator, NOT a 6th context property.
    expectAbsent(qm, "setContextProperty(\"Staging\"");

    // --- Zero-click username injection (reverse channel) invariants ---

    const std::string bbSrc = readSourceFile("src/BrowserBridge.cpp");
    const std::string contentJs = readSourceFile("extensions/browser/content.js");

    // The username decrypt+send lives in FillController (JIT), NOT in the
    // decrypt-free StagingController.
    expectAbsent(scSrc, "sendFillUsername");
    expectPresent(fcSrc, "injectUsername");
    // Username injection uses the same strict browser secret-release matcher
    // as the password gate.
    expectPresent(fcSrc, "platformMatchesHostForSecretRelease(record.platform, host)");
    expectPresent(fcSrc, "decryptUsernameOnDemand(record, access.password())");
    // Only the USERNAME crosses the reverse channel; the password is never sent
    // to the browser (no such method exists).
    expectPresent(fcSrc, "sendFillUsername");
    expectAbsent(fcSrc, "sendFillPassword");
    expectAbsent(bbSrc, "sendFillPassword");
    // The bridge wipes the plaintext username wire buffer after sending.
    expectPresent(bbSrc, "SecureZeroMemory(json.data()");
    // The content script re-verifies its own host and per-document visit token
    // before injecting, so a stale or same-host different-document route fails closed.
    expectPresent(contentJs, "msg.url_host !== location.host");
    expectPresent(contentJs, "msg.visit !== VISIT_TOKEN");

    // typeSecret must report SendInput failure instead of marking fills complete.
    expectPresent(clipboardSrc, "if (sent != 1)");
}

TEST(BrowserExtensionBoundary, ClicksAreSecureAndUsernameRoutesByVisit)
{
    const std::string contentJs = readSourceFile("extensions/browser/content.js");
    const std::string backgroundJs = readSourceFile("extensions/browser/background.js");
    const std::string bridgeSrc = readSourceFile("src/BrowserBridge.cpp");

    expectPresent(contentJs, "const DEBUG_LOGS = false");
    expectPresent(backgroundJs, "const DEBUG_LOGS = false");
    expectAbsent(contentJs, "const DEBUG_LOGS = true");
    expectAbsent(backgroundJs, "const DEBUG_LOGS = true");
    expectAbsent(contentJs, "JSON.stringify(payload)");
    expectAbsent(backgroundJs, "content -> bg:\", msg");

    expectPresent(contentJs, "reason=insecure_click");
    expectPresent(contentJs, "url_host: location.host");
    expectPresent(contentJs, "secure: 1");
    expectPresent(contentJs, "visit: VISIT_TOKEN");
    expectPresent(contentJs, "msg.visit !== VISIT_TOKEN");
    expectPresent(backgroundJs, "secure: msg.secure ? 1 : 0");
    expectPresent(backgroundJs, "rememberNavRoute(navPayload.url_host, navPayload.visit");
    expectPresent(backgroundJs, "navRoutes.set(routeKey(host, visit)");
    expectPresent(backgroundJs, "routeKey(host, visit)");
    expectPresent(backgroundJs, "visit: visit");
    expectPresent(bridgeSrc, "reason=insecure_click");
    expectPresent(bridgeSrc, "visit\\\":\\\"");
}

TEST(BrowserBridgeBoundary, ShellHopsRequireTrustedShellImages)
{
    const std::string bridgeSrc = readSourceFile("src/BrowserBridge.cpp");
    const std::string signerHpp = readSourceFile("src/SignerUtils.hpp");

    expectPresent(bridgeSrc, "isTrustedShellImage(curPath)");
    expectAbsent(bridgeSrc, "if (!seal::signer::isShellImage(curPath))");

    expectPresent(signerHpp, "inline bool isTrustedShellImage");
    expectPresent(signerHpp, "shellPublisherMatches");
    expectPresent(signerHpp, "isShellPathAllowed");
    expectPresent(signerHpp, "winVerifyTrustOk(imagePath)");
}

TEST(BrowserExtensionBoundary, VisibleFieldGateUsesRenderedViewportAndClippingChecks)
{
    const std::string contentJs = readSourceFile("extensions/browser/content.js");

    expectPresent(contentJs, "function visibleViewportRect");
    expectPresent(contentJs, "function intersectRects");
    expectPresent(contentJs, "function clipsOverflow");
    expectPresent(contentJs, "viewport_intersection_empty");
    expectPresent(contentJs, "ancestor opacity=");
    expectPresent(contentJs, "document.elementsFromPoint");
    expectPresent(contentJs, "hit_test_blocked");
    expectPresent(contentJs, "transform_invalid");
    expectPresent(contentJs, "isUserVisible(e.target, { x: e.clientX, y: e.clientY })");
}

TEST(Phase2aBoundaryTest, AppViewModelImplementsSeams)
{
    const std::string hpp = readSourceFile("src/AppViewModel.hpp");
    expectPresent(hpp, "public IUiFeedback");
    expectPresent(hpp, "public IPasswordGate");
}

TEST(WorkPoolDeadlockGuard, ProcessDirectoryDoesNotSubmitDirectoryTasks)
{
    const std::string src = readSourceFile("src/FileOperations.cpp");
    // The directory branch must recurse INLINE, never submit a recursive
    // processDirectory call to the pool (the H1 same-pool blocking deadlock).
    EXPECT_EQ(src.find("Submit(\n                    [full, &password]() -> bool\n"
                       "                    { return FileOperations::processDirectory"),
              std::string::npos);
    EXPECT_NE(src.find("processDirectory(full, password, true)"), std::string::npos);
    // Worker-count floor present.
    EXPECT_NE(src.find("std::max(1u, std::min(std::thread::hardware_concurrency(), 8u))"),
              std::string::npos);
}

TEST(Phase2aBoundaryTest, AppViewModelOwnsNoRawRecordsOrSession)
{
    const std::string cpp = readSourceFile("src/AppViewModel.cpp");
    const std::string hpp = readSourceFile("src/AppViewModel.hpp");
    // State now lives in the workspace; AppViewModel reaches it via m_Workspace.
    expectAbsent(hpp, "std::vector<seal::VaultRecord> m_Records");
    expectAbsent(hpp, "seal::CredentialSession m_Session");
    expectPresent(hpp, "CredentialWorkspace& m_Workspace");
    expectPresent(cpp, "m_Workspace.");
}

TEST(WorkerLifetime, AllWorkersDrainedAndCompletionsGuarded)
{
    const std::string src = readSourceFile("src/AppViewModel.cpp");

    // The load and rekey worker completions guard against a destroyed receiver
    // via AsyncRunner: its per-call QFutureWatcher is bound to the receiver, so
    // a mid-flight scrypt's onDone is auto-skipped once the AppViewModel dies.
    // (m_Workers/drainWorkers removed in Phase 2b Task 7 - superseded by
    // AsyncRunner teardown; see Phase2bBoundaryTest.NoHandRolledWorkersOrTerminate)
    EXPECT_NE(src.find("m_Async.run("), std::string::npos);
}

TEST(Phase2bBoundaryTest, NoHandRolledWorkersOrTerminate)
{
    const std::string avm = readSourceFile("src/AppViewModel.cpp");
    const std::string tc = readSourceFile("src/TypeController.cpp");
    for (const std::string& src : {avm, tc})
    {
        expectAbsent(src, "QThread::create");
        expectAbsent(src, "m_Workers");
        expectAbsent(src, "drainWorkers");
        expectAbsent(src, "terminate(");
    }
    expectPresent(avm, "m_Async");
    expectPresent(tc, "m_Async");
    expectPresent(readSourceFile("src/AsyncRunner.cpp"), "waitForDone(");
}

TEST(Phase2aBoundaryTest, TypeControllerIsDecoupledFromAppViewModel)
{
    const std::string cpp = readSourceFile("src/TypeController.cpp");
    const std::string hpp = readSourceFile("src/TypeController.hpp");
    expectAbsent(cpp, "#include \"AppViewModel.hpp\"");
    expectAbsent(hpp, "AppViewModel");
    expectPresent(hpp, "IFillControl");
    expectAbsent(readSourceFile("src/AppViewModel.cpp"), "doTypeLogin");
}

TEST(Phase2aBoundaryTest, CliPanelViewModelIsDecoupledFromAppViewModel)
{
    expectAbsent(readSourceFile("src/CliPanelViewModel.cpp"), "#include \"AppViewModel.hpp\"");
    const std::string avm = readSourceFile("src/AppViewModel.cpp");
    expectAbsent(avm, "executeCliCommand");
    expectAbsent(avm, "kCliMaxLines");
}

TEST(Phase2aBoundaryTest, QmlMainRegistersFiveContextProperties)
{
    const std::string qm = readSourceFile("src/QmlMain.cpp");
    expectPresent(qm, "setContextProperty(\"AppViewModel\"");
    expectPresent(qm, "setContextProperty(\"Cli\"");
    expectPresent(qm, "setContextProperty(\"Fill\"");
    expectPresent(qm, "setContextProperty(\"Bridge\"");
    expectPresent(qm, "setContextProperty(\"WindowVM\"");
}

TEST(Phase2aBoundaryTest, SubViewModelsDoNotIncludeAppViewModel)
{
    expectAbsent(readSourceFile("src/CliPanelViewModel.cpp"), "#include \"AppViewModel.hpp\"");
    expectAbsent(readSourceFile("src/TypeController.cpp"), "#include \"AppViewModel.hpp\"");
    expectAbsent(readSourceFile("src/CredentialWorkspace.hpp"), "#include <Q");  // Qt-free core
}
