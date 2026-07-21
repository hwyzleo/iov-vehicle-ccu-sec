#include <gtest/gtest.h>
#include "data_models.h"

using namespace cgw_sec;

TEST(SeedResultTest, DefaultConstruction) {
    SeedResult result;
    EXPECT_EQ(result.seedId, 0);
    EXPECT_TRUE(result.seed.empty());
    EXPECT_EQ(result.error, CgwSecErrorCode::SUCCESS);
}

TEST(SeedInfoTest, DefaultConstruction) {
    SeedInfo info;
    EXPECT_EQ(info.seedId, 0);
    EXPECT_TRUE(info.seed.empty());
    EXPECT_EQ(info.level, 0);
    EXPECT_FALSE(info.consumed);
}

TEST(OtaSessionContextTest, DefaultConstruction) {
    OtaSessionContext context;
    EXPECT_TRUE(context.campaignId.empty());
    EXPECT_TRUE(context.vin.empty());
    EXPECT_TRUE(context.direction.empty());
    EXPECT_TRUE(context.nonce.empty());
    EXPECT_EQ(context.timestamp, 0);
}

TEST(OtaSessionResultTest, DefaultConstruction) {
    OtaSessionResult result;
    EXPECT_EQ(result.sessionKeyHandle, 0);
    EXPECT_TRUE(result.nonce.empty());
    EXPECT_EQ(result.error, CgwSecErrorCode::SUCCESS);
}

TEST(SecConfigTest, DefaultConstruction) {
    SecConfig config;
    EXPECT_TRUE(config.seHsmType.empty());
    EXPECT_EQ(config.defaultSecurityLevel, 0);
    EXPECT_EQ(config.seedExpirationMs, 0);
    EXPECT_EQ(config.maxSeedPoolSize, 0);
}

TEST(SomeipConfigTest, DefaultConstruction) {
    SomeipConfig config;
    EXPECT_EQ(config.serviceId, 0);
    EXPECT_EQ(config.instanceId, 0);
    EXPECT_EQ(config.getSeedMethodId, 0);
    EXPECT_EQ(config.verifyKeyMethodId, 0);
    EXPECT_EQ(config.deriveOtaSessionMethodId, 0);
    EXPECT_EQ(config.deriveByUidMethodId, 0);
    EXPECT_EQ(config.wrapByUidMethodId, 0);
}

TEST(SeHsmConfigTest, DefaultConstruction) {
    SeHsmConfig config;
    EXPECT_TRUE(config.type.empty());
    EXPECT_TRUE(config.storagePath.empty());
    EXPECT_TRUE(config.keyFiles.empty());
}
