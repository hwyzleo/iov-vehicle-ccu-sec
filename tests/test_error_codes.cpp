#include <gtest/gtest.h>
#include "error_codes.h"

using namespace cgw_sec;

TEST(CgwSecErrorCodeTest, SuccessCode) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SUCCESS), "SUCCESS");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::SUCCESS), "Operation completed successfully");
}

TEST(CgwSecErrorCodeTest, SeedGenerationFailed) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SEED_GENERATION_FAILED), "SEED_GENERATION_FAILED");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::SEED_GENERATION_FAILED), "Seed generation failed");
}

TEST(CgwSecErrorCodeTest, KeyVerificationFailed) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::KEY_VERIFICATION_FAILED), "KEY_VERIFICATION_FAILED");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::KEY_VERIFICATION_FAILED), "Key verification failed");
}

TEST(CgwSecErrorCodeTest, OtaRootMissing) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::OTA_ROOT_MISSING), "OTA_ROOT_MISSING");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::OTA_ROOT_MISSING), "OTA vehicle root not injected");
}

TEST(CgwSecErrorCodeTest, SessionKeyDerivationFailed) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED), "SESSION_KEY_DERIVATION_FAILED");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED), "Session key derivation failed");
}

TEST(CgwSecErrorCodeTest, DeviceRootMissing) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::DEVICE_ROOT_MISSING), "DEVICE_ROOT_MISSING");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::DEVICE_ROOT_MISSING), "Gateway device root not provisioned");
}

TEST(CgwSecErrorCodeTest, SeHsmAccessFailed) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SE_HSM_ACCESS_FAILED), "SE_HSM_ACCESS_FAILED");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::SE_HSM_ACCESS_FAILED), "SE/HSM access failed (fail-closed)");
}

TEST(CgwSecErrorCodeTest, UnauthorizedRequest) {
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::UNAUTHORIZED_REQUEST), "UNAUTHORIZED_REQUEST");
    EXPECT_EQ(errorCodeDescription(CgwSecErrorCode::UNAUTHORIZED_REQUEST), "Request unauthorized or session not authenticated");
}

TEST(CgwSecErrorCodeTest, UnknownErrorCode) {
    EXPECT_EQ(errorCodeToString(static_cast<CgwSecErrorCode>(9999)), "UNKNOWN_ERROR");
    EXPECT_EQ(errorCodeDescription(static_cast<CgwSecErrorCode>(9999)), "Unknown error");
}
