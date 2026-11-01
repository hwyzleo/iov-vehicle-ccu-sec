#include <gtest/gtest.h>
#include "error_codes.h"

using namespace ccu_sec;

TEST(CcuSecErrorCodeTest, SuccessCode) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::SUCCESS), "SUCCESS");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::SUCCESS), "Operation completed successfully");
}

TEST(CcuSecErrorCodeTest, SeedGenerationFailed) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::SEED_GENERATION_FAILED), "SEED_GENERATION_FAILED");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::SEED_GENERATION_FAILED), "Seed generation failed");
}

TEST(CcuSecErrorCodeTest, KeyVerificationFailed) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::KEY_VERIFICATION_FAILED), "KEY_VERIFICATION_FAILED");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::KEY_VERIFICATION_FAILED), "Key verification failed");
}

TEST(CcuSecErrorCodeTest, OtaRootMissing) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::OTA_ROOT_MISSING), "OTA_ROOT_MISSING");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::OTA_ROOT_MISSING), "OTA vehicle root not injected");
}

TEST(CcuSecErrorCodeTest, SessionKeyDerivationFailed) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED), "SESSION_KEY_DERIVATION_FAILED");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED), "Session key derivation failed");
}

TEST(CcuSecErrorCodeTest, DeviceRootMissing) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::DEVICE_ROOT_MISSING), "DEVICE_ROOT_MISSING");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::DEVICE_ROOT_MISSING), "CCU device root not provisioned");
}

TEST(CcuSecErrorCodeTest, SeHsmAccessFailed) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::SE_HSM_ACCESS_FAILED), "SE_HSM_ACCESS_FAILED");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::SE_HSM_ACCESS_FAILED), "SE/HSM access failed (fail-closed)");
}

TEST(CcuSecErrorCodeTest, UnauthorizedRequest) {
    EXPECT_EQ(errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST), "UNAUTHORIZED_REQUEST");
    EXPECT_EQ(errorCodeDescription(CcuSecErrorCode::UNAUTHORIZED_REQUEST), "Request unauthorized or session not authenticated");
}

TEST(CcuSecErrorCodeTest, UnknownErrorCode) {
    EXPECT_EQ(errorCodeToString(static_cast<CcuSecErrorCode>(9999)), "UNKNOWN_ERROR");
    EXPECT_EQ(errorCodeDescription(static_cast<CcuSecErrorCode>(9999)), "Unknown error");
}
