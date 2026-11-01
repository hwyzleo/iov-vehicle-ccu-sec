#include <gtest/gtest.h>
#include "seed_key_manager.h"
#include "software_se_hsm.h"
#include "se_hsm_factory.h"
#include "constants.h"
#include "error_codes.h"

using namespace ccu_sec;

class SeedKeyManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        SeHsmConfig config;
        config.type = "software";
        config.storagePath = "/tmp/test_seed_key_mgr";
        std::shared_ptr<SeHsmInterface> hsm(SeHsmFactory::create(config).release());
        manager = std::make_unique<SeedKeyManager>(std::move(hsm));
    }

    std::unique_ptr<SeedKeyManager> manager;
};

TEST_F(SeedKeyManagerTest, GenerateSeedSuccess) {
    auto result = manager->generateSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.seedId, 0u);
    EXPECT_EQ(result.seed.size(), SEED_SIZE);
}

TEST_F(SeedKeyManagerTest, GenerateSeedUniqueIds) {
    auto result1 = manager->generateSeed(SECURITY_LEVEL_1);
    auto result2 = manager->generateSeed(SECURITY_LEVEL_1);
    EXPECT_NE(result1.seedId, result2.seedId);
}

TEST_F(SeedKeyManagerTest, VerifyKeySuccess) {
    auto seedResult = manager->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result = manager->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(result, CcuSecErrorCode::SUCCESS);
}

TEST_F(SeedKeyManagerTest, VerifyKeyFailureWrongKey) {
    auto seedResult = manager->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    std::vector<uint8_t> wrongKey(SEED_SIZE, 0xAA);
    auto result = manager->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, wrongKey);
    EXPECT_EQ(result, CcuSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyManagerTest, VerifyKeyFailureInvalidSeedId) {
    std::vector<uint8_t> key(SEED_SIZE, 0xAA);
    auto result = manager->verifyKey(SECURITY_LEVEL_1, 9999, key);
    EXPECT_EQ(result, CcuSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyManagerTest, VerifyKeyFailureConsumedSeed) {
    auto seedResult = manager->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result1 = manager->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(result1, CcuSecErrorCode::SUCCESS);

    auto result2 = manager->verifyKey(SECURITY_LEVEL_1, seedResult.seedId, key);
    EXPECT_EQ(result2, CcuSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyManagerTest, VerifyKeyFailureWrongLevel) {
    auto seedResult = manager->generateSeed(SECURITY_LEVEL_1);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);

    std::vector<uint8_t> key(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        key[i] = seedResult.seed[i] ^ 0xFF;
    }

    auto result = manager->verifyKey(0x02, seedResult.seedId, key);
    EXPECT_EQ(result, CcuSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SeedKeyManagerTest, ActiveSeedCount) {
    EXPECT_EQ(manager->getActiveSeedCount(), 0u);

    manager->generateSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(manager->getActiveSeedCount(), 1u);

    manager->generateSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(manager->getActiveSeedCount(), 2u);
}

TEST_F(SeedKeyManagerTest, MultipleSeedGeneration) {
    std::vector<SeedResult> seeds;
    for (int i = 0; i < 10; ++i) {
        auto result = manager->generateSeed(SECURITY_LEVEL_1);
        EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
        seeds.push_back(result);
    }

    for (size_t i = 0; i < seeds.size(); ++i) {
        for (size_t j = i + 1; j < seeds.size(); ++j) {
            EXPECT_NE(seeds[i].seedId, seeds[j].seedId);
        }
    }
}

TEST_F(SeedKeyManagerTest, CleanupExpiredSeedsDoesNotAffectActive) {
    auto result = manager->generateSeed(SECURITY_LEVEL_1);
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(manager->getActiveSeedCount(), 1u);

    manager->cleanupExpiredSeeds();
    EXPECT_EQ(manager->getActiveSeedCount(), 1u);
}
