#include <gtest/gtest.h>
#include "ota_session_manager.h"
#include "software_se_hsm.h"
#include "se_hsm_factory.h"
#include "constants.h"
#include "error_codes.h"

using namespace ccu_sec;

class OtaSessionManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        SeHsmConfig config;
        config.type = "software";
        config.storagePath = "/tmp/test_ota_session_mgr";
        hsm = std::shared_ptr<SeHsmInterface>(SeHsmFactory::create(config).release());

        std::vector<uint8_t> otaRootKey = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
        };
        hsm->storeKey(OTA_VEHICLE_ROOT_KEY_NAME, otaRootKey);

        manager = std::make_unique<OtaSessionManager>(hsm);
    }

    std::shared_ptr<SeHsmInterface> hsm;
    std::unique_ptr<OtaSessionManager> manager;
};

TEST_F(OtaSessionManagerTest, IsOtaVehicleRootAvailableTrue) {
    EXPECT_TRUE(manager->isOtaVehicleRootAvailable());
}

TEST_F(OtaSessionManagerTest, IsOtaVehicleRootAvailableFalse) {
    SeHsmConfig config;
    config.type = "software";
    config.storagePath = "/tmp/test_ota_no_root";
    std::shared_ptr<SeHsmInterface> emptyHsm(SeHsmFactory::create(config).release());

    OtaSessionManager emptyManager(emptyHsm);
    EXPECT_FALSE(emptyManager.isOtaVehicleRootAvailable());
}

TEST_F(OtaSessionManagerTest, DeriveSessionKeySuccess) {
    OtaSessionContext context;
    context.campaignId = "CAMP001";
    context.vin = "VIN123456789";
    context.direction = "FOTA";
    context.timestamp = 1234567890;

    auto result = manager->deriveSessionKey(context);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.sessionKeyHandle, 0u);
    EXPECT_EQ(result.nonce.size(), NONCE_SIZE);
}

TEST_F(OtaSessionManagerTest, DeriveSessionKeyUniqueHandles) {
    OtaSessionContext context1;
    context1.campaignId = "CAMP001";
    context1.vin = "VIN123456789";
    context1.direction = "FOTA";
    context1.timestamp = 1234567890;

    OtaSessionContext context2;
    context2.campaignId = "CAMP002";
    context2.vin = "VIN987654321";
    context2.direction = "SOTA";
    context2.timestamp = 9876543210;

    auto result1 = manager->deriveSessionKey(context1);
    auto result2 = manager->deriveSessionKey(context2);
    EXPECT_NE(result1.sessionKeyHandle, result2.sessionKeyHandle);
}

TEST_F(OtaSessionManagerTest, DeriveSessionKeyMissingRoot) {
    SeHsmConfig config;
    config.type = "software";
    config.storagePath = "/tmp/test_ota_no_root2";
    std::shared_ptr<SeHsmInterface> emptyHsm(SeHsmFactory::create(config).release());

    OtaSessionManager emptyManager(emptyHsm);

    OtaSessionContext context;
    context.campaignId = "CAMP001";
    context.vin = "VIN123456789";
    context.direction = "FOTA";
    context.timestamp = 1234567890;

    auto result = emptyManager.deriveSessionKey(context);
    EXPECT_EQ(result.error, CcuSecErrorCode::OTA_ROOT_MISSING);
}

TEST_F(OtaSessionManagerTest, GenerateNonceLength) {
    auto nonce = manager->generateNonce();
    EXPECT_EQ(nonce.size(), NONCE_SIZE);
}

TEST_F(OtaSessionManagerTest, GenerateNonceUniqueness) {
    auto nonce1 = manager->generateNonce();
    auto nonce2 = manager->generateNonce();
    EXPECT_NE(nonce1, nonce2);
}

TEST_F(OtaSessionManagerTest, DeriveSessionKeyDifferentContexts) {
    OtaSessionContext context1;
    context1.campaignId = "CAMP001";
    context1.vin = "VIN123456789";
    context1.direction = "FOTA";
    context1.timestamp = 1111111111;

    OtaSessionContext context2;
    context2.campaignId = "CAMP002";
    context2.vin = "VIN987654321";
    context2.direction = "SOTA";
    context2.timestamp = 2222222222;

    auto result1 = manager->deriveSessionKey(context1);
    auto result2 = manager->deriveSessionKey(context2);

    EXPECT_EQ(result1.error, CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(result2.error, CcuSecErrorCode::SUCCESS);
    EXPECT_NE(result1.sessionKeyHandle, result2.sessionKeyHandle);
}
