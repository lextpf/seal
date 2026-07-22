#include <gtest/gtest.h>

#include "src/ProtectedFolderPolicy.hpp"

#include <algorithm>
#include <filesystem>
#include <string_view>
#include <vector>

namespace
{

namespace fs = std::filesystem;
namespace policy = seal::protected_folder;

policy::Entry file(std::string_view path,
                   std::uintmax_t size = 1,
                   bool symlink = false,
                   bool vault = false)
{
    return {fs::path(path), size, symlink, vault};
}

const policy::SkipReason* reasonFor(const policy::FolderPlan& plan, std::string_view path)
{
    const auto found = std::find_if(plan.skipped.begin(),
                                    plan.skipped.end(),
                                    [path](const auto& item)
                                    { return item.first.relativePath == fs::path(path); });
    return found == plan.skipped.end() ? nullptr : &found->second;
}

bool actsOn(const policy::FolderPlan& plan, std::string_view path)
{
    return std::ranges::any_of(plan.act,
                               [path](const policy::Entry& entry)
                               { return entry.relativePath == fs::path(path); });
}

}  // namespace

TEST(ProtectedFolderPolicyTest, StableSkipTokensAreAppendOnlyContract)
{
    using enum policy::SkipReason;
    EXPECT_EQ(policy::skipReasonToken(AppRuntime), "app_runtime");
    EXPECT_EQ(policy::skipReasonToken(QtDeployDir), "qt_deploy_dir");
    EXPECT_EQ(policy::skipReasonToken(NativeMessagingManifest), "native_messaging_manifest");
    EXPECT_EQ(policy::skipReasonToken(CredentialVault), "credential_vault");
    EXPECT_EQ(policy::skipReasonToken(AlreadyEncrypted), "already_encrypted");
    EXPECT_EQ(policy::skipReasonToken(Symlink), "symlink");
    EXPECT_EQ(policy::skipReasonToken(Lockfile), "lockfile");
}

TEST(ProtectedFolderPolicyTest, EncryptPlanProtectsRuntimeAndActsOnNestedPayloads)
{
    const std::vector<policy::Entry> entries{
        file("seal.exe", 100),
        file("seal-browser.exe", 80),
        file("Qt6Gui.dll", 70),
        file("seal.pdb", 60),
        file("qt.conf", 10),
        file("qml/QtQuick/Controls/plugin.qmltypes", 20),
        file("platforms/qwindows.dll", 30),
        file("docs/private/notes.txt", 40),
        file("docs/private/already.seal", 50),
        file("com.seal.fill.json", 5),
        file("com.seal.fill.brave.json", 6),
        file("session.zombielock", 0),
        file("linked", 0, true),
        file("vault.seal", 90, false, true),
    };

    const policy::FolderPlan plan = policy::planEncrypt(entries, {});
    ASSERT_TRUE(actsOn(plan, "docs/private/notes.txt"));
    EXPECT_EQ(plan.totalBytes(), 40u);

    ASSERT_NE(reasonFor(plan, "seal.exe"), nullptr);
    EXPECT_EQ(*reasonFor(plan, "seal.exe"), policy::SkipReason::AppRuntime);
    EXPECT_EQ(*reasonFor(plan, "qml/QtQuick/Controls/plugin.qmltypes"),
              policy::SkipReason::QtDeployDir);
    EXPECT_EQ(*reasonFor(plan, "platforms/qwindows.dll"), policy::SkipReason::QtDeployDir);
    EXPECT_EQ(*reasonFor(plan, "docs/private/already.seal"), policy::SkipReason::AlreadyEncrypted);
    EXPECT_EQ(*reasonFor(plan, "com.seal.fill.json"), policy::SkipReason::NativeMessagingManifest);
    EXPECT_EQ(*reasonFor(plan, "session.zombielock"), policy::SkipReason::Lockfile);
    EXPECT_EQ(*reasonFor(plan, "linked"), policy::SkipReason::Symlink);
    EXPECT_EQ(*reasonFor(plan, "vault.seal"), policy::SkipReason::CredentialVault);
}

TEST(ProtectedFolderPolicyTest, QtDirectoryRuleOnlyProtectsTopLevelDeploymentDirectories)
{
    const std::vector<policy::Entry> entries{
        file("qml/user.qml"),
        file("documents/qml/user-data.txt"),
        file("translations/seal_de.qm"),
        file("archive/translations/notes.txt"),
    };

    const policy::FolderPlan plan = policy::planEncrypt(entries, {});
    EXPECT_EQ(*reasonFor(plan, "qml/user.qml"), policy::SkipReason::QtDeployDir);
    EXPECT_EQ(*reasonFor(plan, "translations/seal_de.qm"), policy::SkipReason::QtDeployDir);
    EXPECT_TRUE(actsOn(plan, "documents/qml/user-data.txt"));
    EXPECT_TRUE(actsOn(plan, "archive/translations/notes.txt"));
}

TEST(ProtectedFolderPolicyTest, DecryptPlanNeverConsumesCredentialVault)
{
    const std::vector<policy::Entry> entries{
        file("vault.seal", 90, false, true),
        file("notes.txt.seal", 50),
        file("notes.txt", 40),
        file("qml/cache.seal", 30),
        file("linked.seal", 0, true),
    };

    const policy::FolderPlan plan = policy::planDecrypt(entries, {});
    ASSERT_EQ(plan.act.size(), 1u);
    EXPECT_TRUE(actsOn(plan, "notes.txt.seal"));
    EXPECT_EQ(*reasonFor(plan, "vault.seal"), policy::SkipReason::CredentialVault);
    EXPECT_EQ(*reasonFor(plan, "qml/cache.seal"), policy::SkipReason::QtDeployDir);
    EXPECT_EQ(*reasonFor(plan, "linked.seal"), policy::SkipReason::Symlink);
    EXPECT_EQ(reasonFor(plan, "notes.txt"), nullptr);
}

TEST(ProtectedFolderPolicyTest, DeploymentPreflightRejectsOnlyInterleavedQtCore)
{
    const policy::PolicyContext context;
    const std::vector<policy::Entry> dynamicLayout{
        file("seal.exe"),
        file("Qt6Core.dll"),
        file("documents/report.txt"),
    };
    const std::vector<policy::Entry> staticLayout{
        file("seal.exe"),
        file("documents/report.txt"),
        file("backup/Qt6Core.dll"),
    };
    const std::vector<policy::Entry> linkedDynamicLayout{
        file("seal.exe"),
        file("Qt6Core.dll", 0, true),
    };

    EXPECT_FALSE(policy::deploymentPreflightPasses(dynamicLayout, context));
    EXPECT_FALSE(policy::deploymentPreflightPasses(linkedDynamicLayout, context));
    EXPECT_TRUE(policy::deploymentPreflightPasses(staticLayout, context));
}

TEST(ProtectedFolderPolicyTest, EncryptOutputAndTemporaryCollisionsBlockArming)
{
    const std::vector<policy::Entry> entries{
        file("vault"),
        file("VAULT.SEAL", 90, false, true),
        file("report.txt"),
        file("report.txt.seal.tmp"),
        file("safe.txt"),
    };

    const std::vector<policy::OutputConflict> conflicts =
        policy::findEncryptOutputConflicts(entries, {});
    ASSERT_EQ(conflicts.size(), 2u);
    EXPECT_EQ(conflicts[0].source.relativePath, fs::path("vault"));
    EXPECT_EQ(conflicts[0].occupied.relativePath, fs::path("VAULT.SEAL"));
    EXPECT_EQ(conflicts[1].source.relativePath, fs::path("report.txt"));
    EXPECT_EQ(conflicts[1].occupied.relativePath, fs::path("report.txt.seal.tmp"));
}

TEST(ProtectedFolderPolicyTest, ContextMarkerIsAlwaysProtected)
{
    policy::PolicyContext context;
    context.markerRelativePath = "state/plaintext.marker";
    context.profileRelativePath = "state/folder.profile";
    const std::vector<policy::Entry> entries{
        file("state/plaintext.marker"),
        file("state/folder.profile"),
        file("state/folder.profile.tmp"),
        file(".seal-folder-unprotected"),
        file(".seal-folder-profile"),
    };

    const policy::FolderPlan plan = policy::planEncrypt(entries, context);
    EXPECT_EQ(*reasonFor(plan, "state/plaintext.marker"), policy::SkipReason::AppRuntime);
    EXPECT_EQ(*reasonFor(plan, "state/folder.profile"), policy::SkipReason::AppRuntime);
    EXPECT_EQ(*reasonFor(plan, "state/folder.profile.tmp"), policy::SkipReason::AppRuntime);
    EXPECT_TRUE(actsOn(plan, ".seal-folder-unprotected"));
    EXPECT_TRUE(actsOn(plan, ".seal-folder-profile"));

    const policy::FolderPlan decryptPlan = policy::planDecrypt(entries, context);
    EXPECT_EQ(*reasonFor(decryptPlan, "state/folder.profile"), policy::SkipReason::AppRuntime);
    EXPECT_EQ(*reasonFor(decryptPlan, "state/folder.profile.tmp"), policy::SkipReason::AppRuntime);
}
