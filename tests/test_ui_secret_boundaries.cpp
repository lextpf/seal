#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <regex>
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

TEST(MvvmCommandRoutingTest, EveryBridgeInvokableHasAQmlCaller)
{
    const std::string bridgeHeader = readSourceFile("src/BridgeViewModel.hpp");
    std::string allQml;
    const std::filesystem::path qmlDir = std::filesystem::path(SEAL_SOURCE_DIR) / "qml";
    for (const auto& entry : std::filesystem::directory_iterator(qmlDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".qml")
        {
            allQml +=
                readSourceFile((std::filesystem::path("qml") / entry.path().filename()).string());
        }
    }

    const std::regex invokablePattern(R"(Q_INVOKABLE\s+[^(;\r\n]+\s+(\w+)\s*\()");
    std::size_t count = 0;
    for (std::sregex_iterator match(bridgeHeader.begin(), bridgeHeader.end(), invokablePattern),
         end;
         match != end;
         ++match)
    {
        ++count;
        const std::string method = (*match)[1].str();
        expectPresent(allQml, "Bridge." + method + "(");
    }
    EXPECT_GT(count, 0U);
}

TEST(MvvmCommandRoutingTest, BrowserSetupActionLivesInHeaderRow)
{
    const std::string headerBar = readSourceFile("qml/HeaderBar.qml");
    const std::string bridgeSettings = readSourceFile("qml/BridgeSettings.qml");

    expectPresent(headerBar, "text: \"Setup\"");
    expectPresent(headerBar, "Bridge.runInstallBrowserExtension()");
    expectPresent(headerBar, "Bridge.runUninstallBrowserExtension()");
    expectAbsent(bridgeSettings, "text: \"Setup\"");
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

    // clear transient password fields after submission.
    expectPresent(rekeyDialog, "function clearFields()");
    expectAbsent(rekeyDialog, "vaultModel");
}

TEST(ProtectedFolderWiringTest, TogglePreflightAndHeldCloseStayViewModelMediated)
{
    const std::string appViewModelHeader = readSourceFile("src/AppViewModel.hpp");
    const std::string appViewModelCpp = readSourceFile("src/AppViewModel.cpp");
    const std::string headerBar = readSourceFile("qml/HeaderBar.qml");
    const std::string mainQml = readSourceFile("qml/Main.qml");
    const std::string dialog = readSourceFile("qml/ProtectFolderDialog.qml");
    const std::string cmake = readSourceFile("CMakeLists.txt");

    expectPresent(appViewModelHeader, "protectFolderEnabled");
    expectPresent(appViewModelHeader, "Q_INVOKABLE void requestProtectFolderEnabled(bool enabled)");
    expectPresent(appViewModelHeader,
                  "confirmProtectFolderEnabled(QString password, QString confirmation)");
    expectPresent(appViewModelCpp, "security/protectFolder/");
    expectPresent(appViewModelCpp, "m_AutoEncryptDirectory =");
    expectPresent(appViewModelCpp, "looksLikeVault(");
    expectPresent(appViewModelCpp, "verifyProtectedFolderProfile(");
    expectPresent(appViewModelCpp, "createProtectedFolderProfile(");

    expectPresent(headerBar, "signal protectFolderToggled(bool enabled)");
    expectPresent(headerBar, "property bool protectFolderEnabled");
    expectPresent(mainQml, "protectFolderEnabled: AppViewModel.protectFolderEnabled");
    expectPresent(mainQml, "ProtectFolderDialog {");
    expectPresent(mainQml, "close.accepted = false");
    expectPresent(mainQml, "AppViewModel.cleanup()");
    expectPresent(mainQml, "onCleanupFinished");

    expectPresent(dialog, "property var encryptFiles");
    expectPresent(dialog, "property var skippedFiles");
    expectPresent(dialog, "property int passwordMode");
    expectPresent(dialog, "function clearPasswordFields()");
    expectPresent(dialog, "Irreversible warning:");
    expectPresent(dialog, ".seal-folder-profile");
    expectPresent(cmake, "qml/ProtectFolderDialog.qml");
    expectPresent(cmake, "src/ProtectedFolderProfile.cpp");
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
    // CredentialWorkspace owns CredentialSession.
    EXPECT_EQ(hdr.find("m_DPAPIGuard"), std::string::npos);
    EXPECT_EQ(hdr.find("m_PasswordSet"), std::string::npos);
    EXPECT_NE(hdr.find("CredentialWorkspace& m_Workspace"), std::string::npos);

    EXPECT_EQ(src.find("m_DPAPIGuard"), std::string::npos);
    EXPECT_EQ(src.find("m_PasswordSet"), std::string::npos);
    EXPECT_EQ(src.find("ScopedDpapiUnprotect"),
              std::string::npos);  // replaced by m_Workspace.session().unlock()
}

TEST(PendingAction, SingleAssignerNoLastWriterWins)
{
    const std::string src = readSourceFile("src/AppViewModel.cpp");
    const std::string hdr = readSourceFile("src/AppViewModel.hpp");
    // password continuations must preserve FIFO order.
    EXPECT_EQ(hdr.find("std::function<void()> m_PendingAction"), std::string::npos);
    EXPECT_NE(hdr.find("std::deque<std::function<void()>> m_PendingActions"), std::string::npos);

    EXPECT_EQ(src.find("m_PendingAction ="), std::string::npos);
    EXPECT_NE(src.find("ensurePassword("), std::string::npos);
}

TEST(FillPlaintextWindow, NarrowedToDecryptInstant)
{
    const std::string fcH = readSourceFile("src/FillController.hpp");
    const std::string fcSrc = readSourceFile("src/FillController.cpp");
    const std::string vmSrc = readSourceFile("src/AppViewModel.cpp");
    const std::string tcSrc = readSourceFile("src/TypeController.cpp");

    // FillController borrows the session; plaintext access is scoped to decryption.
    EXPECT_NE(fcH.find("CredentialSession"), std::string::npos);
    EXPECT_NE(fcH.find("CredentialSession* m_Session"), std::string::npos);
    EXPECT_EQ(fcH.find("m_MasterPw"), std::string::npos);
    EXPECT_EQ(fcSrc.find("m_MasterPw"), std::string::npos);

    EXPECT_NE(fcSrc.find("m_Session->unlock()"), std::string::npos);
    EXPECT_NE(fcSrc.find("decryptCredentialOnDemand(record, access.password())"),
              std::string::npos);

    // arming borrows workspace records and session without unlocking the password.
    EXPECT_NE(tcSrc.find("m_Engine.arm(index, m_Workspace.records(), "
                         "m_Workspace.session(), m_Workspace.generation())"),
              std::string::npos);

    EXPECT_EQ(vmSrc.find("m_FillController"), std::string::npos);

    // plaintext protection must follow scope exit rather than a delayed timer.
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

    // staging selects and arms; plaintext access belongs to FillController at click time.
    expectAbsent(scSrc, "decryptCredentialOnDemand");
    expectAbsent(scSrc, "unlock()");
    expectAbsent(scSrc, "ensurePassword");

    expectAbsent(scSrc, "singleShot");

    // auto-fill requires native-probe corroboration and fail-closed host/foreground gates.
    expectPresent(fcSrc, "LLMHF_INJECTED");
    expectPresent(fcSrc, "decideDetailed");
    expectPresent(fcSrc, "reason=no_bridge_entry");
    expectPresent(fcSrc, "reason=host_mismatch");
    expectPresent(fcSrc, "reason=foreground_pid_mismatch");
    expectPresent(fcSrc, "reason=visit_mismatch");
    expectPresent(fcSrc, "reason=weak_fusion");
    expectPresent(fcSrc, "outcome.m_Tier1ShortCircuit && outcome.m_BridgeCorroborated");
    // only domain-bound records can release browser credentials.
    expectPresent(fcSrc, "url::platformMatchesHostForSecretRelease(record.platform, pageHost)");
    expectAbsent(fcSrc, "keysMatch(recordKey, pageKey)");

    expectPresent(fcSrc, "armAuto");

    expectPresent(bvmSrc, "\"bridge/autostage\", false");

    expectAbsent(qm, "setContextProperty(\"Staging\"");

    const std::string bbSrc = readSourceFile("src/BrowserBridge.cpp");
    const std::string contentJs = readSourceFile("extensions/browser/content.js");

    expectAbsent(scSrc, "sendFillUsername");
    expectPresent(fcSrc, "injectUsername");

    expectPresent(fcSrc, "platformMatchesHostForSecretRelease(record.platform, host)");
    expectPresent(fcSrc, "decryptUsernameOnDemand(record, access.password())");
    // the reverse channel carries usernames only.
    expectPresent(fcSrc, "sendFillUsername");
    expectAbsent(fcSrc, "sendFillPassword");
    expectAbsent(bbSrc, "sendFillPassword");

    expectPresent(bbSrc, "SecureZeroMemory(json.data()");
    // recheck the host and visit token in the receiving document.
    expectPresent(contentJs, "msg.url_host !== location.host");
    expectPresent(contentJs, "msg.visit !== VISIT_TOKEN");

    // a partial SendInput pair must fail the fill.
    expectPresent(clipboardSrc, "if (sent != 2)");
}

// Ctrl+Click fill is authorized by the record selection and the physical click. The browser
// extension never gates it; only the OS focus check and the fused probe verdict apply.
TEST(ManualFillBoundary, CtrlClickReleaseIsOsGatedAndExtensionIndependent)
{
    const std::string fcSrc = readSourceFile("src/FillController.cpp");

    // the focused window must still own the clicked window when typing starts.
    expectPresent(fcSrc, "reason=manual_foreground_pid_mismatch");
    // the fused verdict still selects the field for an Auto target.
    expectPresent(fcSrc, "runProbeRegistry(m_ClickX.load(), m_ClickY.load())");
    // one success line, and it carries no host.
    expectPresent(fcSrc, "\"event=fill.manual.release\", \"result=ok\"");

    // no bridge entry, host, visit, or corroboration check may block a manual fill.
    expectAbsent(fcSrc, "event=fill.url_mismatch_block");
    expectAbsent(fcSrc, "reason=no_bridge_entry_manual");
    expectAbsent(fcSrc, "reason=visit_mismatch_manual");
    expectAbsent(fcSrc, "reason=weak_fusion_manual");
    expectAbsent(fcSrc, "manualPageHost");
    expectAbsent(fcSrc, "isKnownBrowserImage");
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

    // inbox shells use catalog signatures. SignerFamilyTest tests trust behavior;
    // this scan keeps the catalog verification path present.
    expectPresent(signerHpp, "detail::catalogTrustOk(imagePath, catalogPublisher)");
    expectPresent(signerHpp, "WTD_CHOICE_CATALOG");
}

// the host is outside seal_tests, so this invariant needs a source scan.
// pipe loss must close the native port even while stdin blocks, or the extension cannot reconnect.
TEST(BrowserHostBoundary, HostExitsWhenItsBridgePipeDies)
{
    const std::string hostMain = readSourceFile("host/browser/main.cpp");

    expectPresent(hostMain, "emitExitDiag(0, \"bridge_pipe_closed\")");
    expectPresent(hostMain, "ExitProcess(0)");
    // orderly shutdown lets the main loop log and exit; only unexpected pipe loss exits here.
    expectPresent(hostMain, "WaitForSingleObject(shutdownEvent, 0) != WAIT_OBJECT_0");
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
    // recurse on the current worker to avoid waiting on the same pool.
    EXPECT_EQ(src.find("Submit(\n                    [full, &password]() -> bool\n"
                       "                    { return FileOperations::processDirectory"),
              std::string::npos);
    EXPECT_NE(src.find("processDirectory(full, password, true)"), std::string::npos);

    EXPECT_NE(src.find("std::max(1u, std::min(std::thread::hardware_concurrency(), 8u))"),
              std::string::npos);
}

TEST(Phase2aBoundaryTest, AppViewModelOwnsNoRawRecordsOrSession)
{
    const std::string cpp = readSourceFile("src/AppViewModel.cpp");
    const std::string hpp = readSourceFile("src/AppViewModel.hpp");

    expectAbsent(hpp, "std::vector<seal::VaultRecord> m_Records");
    expectAbsent(hpp, "seal::CredentialSession m_Session");
    expectPresent(hpp, "CredentialWorkspace& m_Workspace");
    expectPresent(cpp, "m_Workspace.");
}

TEST(WorkerLifetime, AllWorkersDrainedAndCompletionsGuarded)
{
    const std::string src = readSourceFile("src/AppViewModel.cpp");

    // AsyncRunner binds completion to the receiver; destroyed receivers must not receive results.
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

TEST(SecureDesktopUnlockBoundary, CapturedPasswordStaysInLockedMemory)
{
    const std::string hpp = readSourceFile("src/AppViewModel.hpp");
    const std::string cpp = readSourceFile("src/AppViewModel.cpp");

    expectPresent(hpp, "Q_INVOKABLE void requestSecureDesktopUnlock()");
    expectPresent(hpp, "void secureCaptureFinished(bool");

    // CredUI output must move directly into adopt/verify without a QString or field prefill.
    expectPresent(cpp, "#include \"Console.hpp\"");
    expectPresent(cpp, "readPasswordSecureDesktop(");
    expectPresent(cpp, "adoptPasswordAndDrain(std::move(");
}

TEST(SecureDesktopUnlockBoundary, ButtonIsWiredThroughTheViewModel)
{
    const std::string pwDialog = readSourceFile("qml/PasswordDialog.qml");
    const std::string mainQml = readSourceFile("qml/Main.qml");

    // the parent handles the dialog signal; the dialog must not call a controller.
    expectPresent(pwDialog, "signal secureScreenRequested()");
    expectPresent(mainQml, "AppViewModel.requestSecureDesktopUnlock()");

    expectPresent(mainQml, "onSecureCaptureFinished");
}
