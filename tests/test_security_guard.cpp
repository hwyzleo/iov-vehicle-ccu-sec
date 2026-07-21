#include <gtest/gtest.h>
#include "security_guard.h"
#include "software_se_hsm.h"
#include "se_hsm_factory.h"
#include "constants.h"
#include "error_codes.h"

using namespace cgw_sec;

class SecurityGuardTest : public ::testing::Test {
protected:
    void SetUp() override {
        SeHsmConfig config;
        config.type = "software";
        config.storagePath = "/tmp/test_security_guard";
        hsm = std::shared_ptr<SeHsmInterface>(SeHsmFactory::create(config).release());
        guard = std::make_unique<SecurityGuard>(hsm);
    }

    std::shared_ptr<SeHsmInterface> hsm;
    std::unique_ptr<SecurityGuard> guard;
};

TEST_F(SecurityGuardTest, VerifyPermissionSuccess) {
    auto result = guard->verifyPermission(SECURITY_LEVEL_1, "get_seed");
    EXPECT_EQ(result, CgwSecErrorCode::SUCCESS);
}

TEST_F(SecurityGuardTest, VerifyPermissionFailureUnknownOperation) {
    auto result = guard->verifyPermission(SECURITY_LEVEL_1, "unknown_op");
    EXPECT_EQ(result, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, VerifyPermissionFailureInsufficientLevel) {
    auto result = guard->verifyPermission(0x00, "get_seed");
    EXPECT_EQ(result, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, VerifyPermissionAllOperations) {
    EXPECT_EQ(guard->verifyPermission(SECURITY_LEVEL_1, "get_seed"),
              CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->verifyPermission(SECURITY_LEVEL_1, "verify_key"),
              CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->verifyPermission(SECURITY_LEVEL_1, "derive_ota_session"),
              CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->verifyPermission(SECURITY_LEVEL_1, "derive_by_uid"),
              CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->verifyPermission(SECURITY_LEVEL_1, "wrap_by_uid"),
              CgwSecErrorCode::SUCCESS);
}

TEST_F(SecurityGuardTest, CheckSecureSessionSuccess) {
    guard->registerSecureSession(1001);
    auto result = guard->checkSecureSession(1001);
    EXPECT_EQ(result, CgwSecErrorCode::SUCCESS);
}

TEST_F(SecurityGuardTest, CheckSecureSessionFailureNotRegistered) {
    auto result = guard->checkSecureSession(9999);
    EXPECT_EQ(result, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, RemoveSecureSession) {
    guard->registerSecureSession(1002);
    EXPECT_EQ(guard->checkSecureSession(1002), CgwSecErrorCode::SUCCESS);

    guard->removeSecureSession(1002);
    EXPECT_EQ(guard->checkSecureSession(1002), CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, AuthorizeRequestSuccess) {
    guard->registerSecureSession(2001);
    auto result = guard->authorizeRequest(SECURITY_LEVEL_1, "get_seed", 2001);
    EXPECT_EQ(result, CgwSecErrorCode::SUCCESS);
}

TEST_F(SecurityGuardTest, AuthorizeRequestFailureNoSession) {
    auto result = guard->authorizeRequest(SECURITY_LEVEL_1, "get_seed", 9999);
    EXPECT_EQ(result, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, AuthorizeRequestFailureBadPermission) {
    guard->registerSecureSession(2002);
    auto result = guard->authorizeRequest(0x00, "get_seed", 2002);
    EXPECT_EQ(result, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, AuthorizeRequestFailureUnknownOp) {
    guard->registerSecureSession(2003);
    auto result = guard->authorizeRequest(SECURITY_LEVEL_1, "bad_op", 2003);
    EXPECT_EQ(result, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecurityGuardTest, MultipleSessions) {
    guard->registerSecureSession(3001);
    guard->registerSecureSession(3002);
    guard->registerSecureSession(3003);

    EXPECT_EQ(guard->checkSecureSession(3001), CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->checkSecureSession(3002), CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->checkSecureSession(3003), CgwSecErrorCode::SUCCESS);

    guard->removeSecureSession(3002);
    EXPECT_EQ(guard->checkSecureSession(3001), CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(guard->checkSecureSession(3002), CgwSecErrorCode::UNAUTHORIZED_REQUEST);
    EXPECT_EQ(guard->checkSecureSession(3003), CgwSecErrorCode::SUCCESS);
}

TEST_F(SecurityGuardTest, RegisterDuplicateSession) {
    guard->registerSecureSession(4001);
    guard->registerSecureSession(4001);
    EXPECT_EQ(guard->checkSecureSession(4001), CgwSecErrorCode::SUCCESS);
}

TEST_F(SecurityGuardTest, RemoveNonexistentSession) {
    guard->removeSecureSession(5001);
    EXPECT_EQ(guard->checkSecureSession(5001), CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}
