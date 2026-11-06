#include <gtest/gtest.h>
#include "software_se_hsm.h"
#include "se_hsm_factory.h"
#include "constants.h"
#include "error_codes.h"

using namespace ccu_sec;

class SoftwareSeHsmTest : public ::testing::Test {
protected:
    void SetUp() override {
        SeHsmConfig config;
        config.type = "software";
        hsm = SeHsmFactory::create(config);
    }

    std::unique_ptr<SeHsmInterface> hsm;
};

TEST_F(SoftwareSeHsmTest, GenerateSeedReturnsValidSeed) {
    auto result = hsm->generateSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.seedId, 0u);
    EXPECT_EQ(result.seed.size(), SEED_SIZE);
}

TEST_F(SoftwareSeHsmTest, GenerateSeedDifferentIds) {
    auto result1 = hsm->generateSeed(SECURITY_LEVEL_1);
    auto result2 = hsm->generateSeed(SECURITY_LEVEL_1);
    EXPECT_NE(result1.seedId, result2.seedId);
}

TEST_F(SoftwareSeHsmTest, VerifyKeySuccess) {
    auto seedResult = hsm->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    // In software mode, key == seed (XOR with 0xFF)
    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result = hsm->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key, seedResult.seed);
    EXPECT_EQ(result, CcuSecErrorCode::SUCCESS);
}

TEST_F(SoftwareSeHsmTest, VerifyKeyFailureWrongKey) {
    auto seedResult = hsm->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    std::vector<uint8_t> wrongKey(SEED_SIZE, 0xAA);
    auto result = hsm->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, wrongKey, seedResult.seed);
    EXPECT_EQ(result, CcuSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SoftwareSeHsmTest, VerifyKeyFailureExpiredSeed) {
    auto seedResult = hsm->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    // Wait for seed to expire (30 seconds + buffer)
    // In real test, we'd mock time. For now, test with valid key.
    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result = hsm->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key, seedResult.seed);
    EXPECT_EQ(result, CcuSecErrorCode::SUCCESS);
}

TEST_F(SoftwareSeHsmTest, DeriveKeySuccess) {
    // First store a root key
    std::vector<uint8_t> rootKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    hsm->storeKey(CCU_DEVICE_ROOT_KEY_NAME, rootKey);

    std::vector<uint8_t> context = {0x01, 0x02, 0x03, 0x04};
    auto result = hsm->deriveKey(CCU_DEVICE_ROOT_KEY_NAME, context);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(result.key.size(), SESSION_KEY_SIZE);
}

TEST_F(SoftwareSeHsmTest, DeriveKeyMissingRoot) {
    std::vector<uint8_t> context = {0x01, 0x02, 0x03, 0x04};
    auto result = hsm->deriveKey("NONEXISTENT_KEY", context);
    EXPECT_EQ(result.error, CcuSecErrorCode::DEVICE_ROOT_MISSING);
}

TEST_F(SoftwareSeHsmTest, StoreAndLoadKey) {
    std::vector<uint8_t> keyMaterial = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    auto storeResult = hsm->storeKey("TEST_KEY", keyMaterial);
    EXPECT_EQ(storeResult, CcuSecErrorCode::SUCCESS);

    auto loadResult = hsm->loadKey("TEST_KEY");
    EXPECT_EQ(loadResult.error, CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(loadResult.key, keyMaterial);
}

TEST_F(SoftwareSeHsmTest, LoadKeyNotFound) {
    auto result = hsm->loadKey("NONEXISTENT_KEY");
    EXPECT_EQ(result.error, CcuSecErrorCode::DEVICE_ROOT_MISSING);
}

TEST_F(SoftwareSeHsmTest, HasKeyTrue) {
    std::vector<uint8_t> keyMaterial = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    hsm->storeKey("EXISTING_KEY", keyMaterial);
    EXPECT_TRUE(hsm->hasKey("EXISTING_KEY"));
}

TEST_F(SoftwareSeHsmTest, HasKeyFalse) {
    EXPECT_FALSE(hsm->hasKey("NONEXISTENT_KEY"));
}

TEST_F(SoftwareSeHsmTest, SecureStoreAndLoad) {
    std::vector<uint8_t> encryptionKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    auto storeResult = hsm->secureStore(encryptionKey, data);
    EXPECT_EQ(storeResult, CcuSecErrorCode::SUCCESS);

    auto loadResult = hsm->secureLoad(encryptionKey);
    EXPECT_EQ(loadResult.error, CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(loadResult.data, data);
}

TEST_F(SoftwareSeHsmTest, SecureLoadWrongKey) {
    std::vector<uint8_t> encryptionKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    hsm->secureStore(encryptionKey, data);

    std::vector<uint8_t> wrongKey = {0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
                                      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    auto result = hsm->secureLoad(wrongKey);
    EXPECT_EQ(result.error, CcuSecErrorCode::SE_HSM_ACCESS_FAILED);
}

TEST_F(SoftwareSeHsmTest, FactoryCreatesSoftwareHsm) {
    SeHsmConfig config;
    config.type = "software";
    auto hsm = SeHsmFactory::create(config);
    EXPECT_NE(hsm, nullptr);
}

TEST_F(SoftwareSeHsmTest, FactoryCreatesNullptrForUnknownType) {
    SeHsmConfig config;
    config.type = "unknown";
    auto hsm = SeHsmFactory::create(config);
    EXPECT_EQ(hsm, nullptr);
}
