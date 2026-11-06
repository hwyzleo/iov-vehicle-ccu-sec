#include <gtest/gtest.h>
#include "sec_someip_service.h"
#include "constants.h"
#include <filesystem>

using namespace ccu_sec;

class SecSomeipServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        secConfig_.defaultSecurityLevel = 1;
        secConfig_.seedExpirationMs = 30000;
        secConfig_.maxSeedPoolSize = 100;

        someipConfig_.applicationName = SEC_APPLICATION_NAME;
        someipConfig_.serviceId = 0x1234;
        someipConfig_.instanceId = 0x5678;
        someipConfig_.getSeedMethodId = 0x0001;
        someipConfig_.verifyKeyMethodId = 0x0002;
        someipConfig_.deriveOtaSessionMethodId = 0x0003;
        someipConfig_.deriveByUidMethodId = 0x0004;
        someipConfig_.wrapByUidMethodId = 0x0005;

        // 非生产夹具：software SE/HSM 仅在显式非生产构建开关下可用。
        seHsmConfig_.type = "software";

        service_ = std::make_unique<SecSomeipService>(secConfig_, someipConfig_, seHsmConfig_);

        // 生产初始化绝不从配置推导根密钥；测试夹具显式注入逻辑根材料
        // （CCU-SEC-DSN-CR-005 §5.2/§6.2）。
        std::vector<uint8_t> ota_root(32, 0x42);
        std::vector<uint8_t> device_root(32, 0x42);
        ASSERT_EQ(service_->provisionTestKey(OTA_VEHICLE_ROOT_KEY_NAME, ota_root),
                  CcuSecErrorCode::SUCCESS);
        ASSERT_EQ(service_->provisionTestKey(CCU_DEVICE_ROOT_KEY_NAME, device_root),
                  CcuSecErrorCode::SUCCESS);
    }

    void TearDown() override {
        service_.reset();
    }

    SecConfig secConfig_;
    SomeipConfig someipConfig_;
    SeHsmConfig seHsmConfig_;
    std::unique_ptr<SecSomeipService> service_;
};

TEST_F(SecSomeipServiceTest, GetSeedAuthorized) {
    auto result = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.seedId, 0u);
    EXPECT_EQ(result.seed.size(), SEED_SIZE);
}

TEST_F(SecSomeipServiceTest, GetSeedUnauthorized) {
    auto result = service_->getSeed(0x00);
    EXPECT_EQ(result.error, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecSomeipServiceTest, VerifyKeyAuthorized) {
    auto seedResult = service_->getSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result = service_->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(result, CcuSecErrorCode::SUCCESS);
}

TEST_F(SecSomeipServiceTest, VerifyKeyUnauthorized) {
    std::vector<uint8_t> key(SEED_SIZE, 0x42);
    auto result = service_->verifyKey(0x00, 1, key);
    EXPECT_EQ(result, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecSomeipServiceTest, DeriveOtaSessionAuthorized) {
    OtaSessionContext context;
    context.campaignId = "CAMPAIGN_001";
    context.vin = "VIN123456789";
    context.direction = "authorize";
    context.nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    context.timestamp = 1234567890;

    auto result = service_->deriveOtaSession(context, SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.sessionKeyHandle, 0u);
    EXPECT_EQ(result.nonce.size(), NONCE_SIZE);
}

TEST_F(SecSomeipServiceTest, DeriveOtaSessionUnauthorized) {
    OtaSessionContext context;
    context.campaignId = "CAMPAIGN_001";

    auto result = service_->deriveOtaSession(context, 0x00);
    EXPECT_EQ(result.error, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecSomeipServiceTest, DeriveByUidAuthorized) {
    std::vector<uint8_t> context = {0x01, 0x02, 0x03};
    auto result = service_->deriveByUid("TEST_SUB_KEY", context, SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_FALSE(result.key.empty());
}

TEST_F(SecSomeipServiceTest, DeriveByUidUnauthorized) {
    std::vector<uint8_t> context = {0x01, 0x02, 0x03};
    auto result = service_->deriveByUid("TEST_SUB_KEY", context, 0x00);
    EXPECT_EQ(result.error, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecSomeipServiceTest, WrapByUidAuthorized) {
    std::vector<uint8_t> data = {0x10, 0x20, 0x30, 0x40};
    auto result = service_->wrapByUid(data, SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
}

TEST_F(SecSomeipServiceTest, WrapByUidUnauthorized) {
    std::vector<uint8_t> data = {0x10, 0x20, 0x30, 0x40};
    auto result = service_->wrapByUid(data, 0x00);
    EXPECT_EQ(result.error, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecSomeipServiceTest, ServiceStartStop) {
    service_->start();
    auto result1 = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result1.error, CcuSecErrorCode::SUCCESS);

    service_->stop();

    service_->start();
    auto result2 = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result2.error, CcuSecErrorCode::SUCCESS);
}

TEST_F(SecSomeipServiceTest, DoubleStart) {
    service_->start();
    service_->start();
    auto result = service_->getSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
}

TEST_F(SecSomeipServiceTest, DoubleStop) {
    service_->start();
    service_->stop();
    service_->stop();
}
