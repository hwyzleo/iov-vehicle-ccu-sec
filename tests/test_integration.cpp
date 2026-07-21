#include <gtest/gtest.h>
#include "sec_someip_service.h"
#include "sec_someip_proxy.h"
#include "constants.h"
#include <filesystem>

using namespace cgw_sec;

class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        storagePath_ = "/tmp/cgw_sec_test_integration";
        std::filesystem::create_directories(storagePath_);

        secConfig_.seHsmType = "software";
        secConfig_.defaultSecurityLevel = 1;
        secConfig_.seedExpirationMs = 30000;
        secConfig_.maxSeedPoolSize = 100;

        someipConfig_.serviceId = 0x1234;
        someipConfig_.instanceId = 0x5678;
        someipConfig_.getSeedMethodId = 0x0001;
        someipConfig_.verifyKeyMethodId = 0x0002;
        someipConfig_.deriveOtaSessionMethodId = 0x0003;
        someipConfig_.deriveByUidMethodId = 0x0004;
        someipConfig_.wrapByUidMethodId = 0x0005;

        seHsmConfig_.type = "software";
        seHsmConfig_.storagePath = storagePath_;
        seHsmConfig_.keyFiles["OTA_VEHICLE_ROOT"] = "keys/ota_vehicle_root.bin";
        seHsmConfig_.keyFiles["CGW_DEVICE_ROOT"] = "keys/cgw_device_root.bin";
        seHsmConfig_.keyFiles["DIAG_SEEDKEY_SECRET"] = "keys/diag_seedkey_secret.bin";

        service_ = std::make_unique<SecSomeipService>(secConfig_, someipConfig_, seHsmConfig_);
    }

    void TearDown() override {
        service_.reset();
        std::filesystem::remove_all(storagePath_);
    }

    std::string storagePath_;
    SecConfig secConfig_;
    SomeipConfig someipConfig_;
    SeHsmConfig seHsmConfig_;
    std::unique_ptr<SecSomeipService> service_;
};

TEST_F(IntegrationTest, FullSeedKeyFlow) {
    auto seedResult = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(seedResult.error, CgwSecErrorCode::SUCCESS);
    EXPECT_GT(seedResult.seedId, 0u);
    EXPECT_EQ(seedResult.seed.size(), SEED_SIZE);

    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto verifyResult = service_->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(verifyResult, CgwSecErrorCode::SUCCESS);
}

TEST_F(IntegrationTest, FullSeedKeyFlowVerifyTwiceFails) {
    auto seedResult = service_->getSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CgwSecErrorCode::SUCCESS);

    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result1 = service_->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(result1, CgwSecErrorCode::SUCCESS);

    auto result2 = service_->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(result2, CgwSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(IntegrationTest, FullOtaSessionFlow) {
    OtaSessionContext context;
    context.campaignId = "CAMPAIGN_001";
    context.vin = "VIN123456789";
    context.direction = "authorize";
    context.nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    context.timestamp = 1234567890;

    auto result = service_->deriveOtaSession(context, SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CgwSecErrorCode::SUCCESS);
    EXPECT_GT(result.sessionKeyHandle, 0u);
    EXPECT_EQ(result.nonce.size(), NONCE_SIZE);
}

TEST_F(IntegrationTest, FullDeviceRootFlow) {
    std::vector<uint8_t> context = {0x01, 0x02, 0x03};
    auto deriveResult = service_->deriveByUid("TEST_SUB_KEY", context, SECURITY_LEVEL_1);
    EXPECT_EQ(deriveResult.error, CgwSecErrorCode::SUCCESS);
    EXPECT_FALSE(deriveResult.key.empty());

    std::vector<uint8_t> data = {0x10, 0x20, 0x30, 0x40};
    auto wrapResult = service_->wrapByUid(data, SECURITY_LEVEL_1);
    EXPECT_EQ(wrapResult.error, CgwSecErrorCode::SUCCESS);
}

TEST_F(IntegrationTest, UnauthorizedAccess) {
    auto seedResult = service_->getSeed(0x00);
    EXPECT_EQ(seedResult.error, CgwSecErrorCode::UNAUTHORIZED_REQUEST);

    std::vector<uint8_t> key(KEY_SIZE, 0x42);
    auto verifyResult = service_->verifyKey(0x00, 1, key);
    EXPECT_EQ(verifyResult, CgwSecErrorCode::UNAUTHORIZED_REQUEST);

    OtaSessionContext otaCtx;
    auto otaResult = service_->deriveOtaSession(otaCtx, 0x00);
    EXPECT_EQ(otaResult.error, CgwSecErrorCode::UNAUTHORIZED_REQUEST);

    std::vector<uint8_t> ctx = {0x01};
    auto deriveResult = service_->deriveByUid("KEY", ctx, 0x00);
    EXPECT_EQ(deriveResult.error, CgwSecErrorCode::UNAUTHORIZED_REQUEST);

    std::vector<uint8_t> data = {0x10};
    auto wrapResult = service_->wrapByUid(data, 0x00);
    EXPECT_EQ(wrapResult.error, CgwSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(IntegrationTest, ServiceStartStop) {
    service_->start();
    auto result1 = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result1.error, CgwSecErrorCode::SUCCESS);

    service_->stop();

    service_->start();
    auto result2 = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result2.error, CgwSecErrorCode::SUCCESS);
}

TEST_F(IntegrationTest, ProxyNotImplemented) {
    SecSomeipProxy proxy(someipConfig_);

    EXPECT_THROW(proxy.getSeed(SECURITY_LEVEL_1), std::runtime_error);

    std::vector<uint8_t> key(KEY_SIZE, 0x42);
    EXPECT_THROW(proxy.verifyKey(SECURITY_LEVEL_1, 1, key), std::runtime_error);

    OtaSessionContext otaCtx;
    EXPECT_THROW(proxy.deriveOtaSession(otaCtx, SECURITY_LEVEL_1), std::runtime_error);

    std::vector<uint8_t> ctx = {0x01};
    EXPECT_THROW(proxy.deriveByUid("KEY", ctx, SECURITY_LEVEL_1), std::runtime_error);

    std::vector<uint8_t> data = {0x10};
    EXPECT_THROW(proxy.wrapByUid(data, SECURITY_LEVEL_1), std::runtime_error);
}

TEST_F(IntegrationTest, MultipleSeedKeyFlows) {
    for (int i = 0; i < 5; ++i) {
        auto seedResult = service_->getSeed(SECURITY_LEVEL_1);
        ASSERT_EQ(seedResult.error, CgwSecErrorCode::SUCCESS);

        std::vector<uint8_t> key(SEED_SIZE);
        for (size_t j = 0; j < SEED_SIZE; ++j) {
            key[j] = seedResult.seed[j] ^ 0xFF;
        }

        auto verifyResult = service_->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
        EXPECT_EQ(verifyResult, CgwSecErrorCode::SUCCESS);
    }
}
