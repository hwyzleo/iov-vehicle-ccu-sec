#include <gtest/gtest.h>
#include "data_models.h"

using namespace ccu_sec;

TEST(SeedResultTest, DefaultConstruction) {
    SeedResult result;
    EXPECT_EQ(result.seedId, 0);
    EXPECT_TRUE(result.seed.empty());
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
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
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
}

TEST(SecConfigTest, DefaultConstruction) {
    SecConfig config;
    EXPECT_EQ(config.defaultSecurityLevel, 0);
    EXPECT_EQ(config.seedExpirationMs, 0);
    EXPECT_EQ(config.maxSeedPoolSize, 0);
}

TEST(SomeipConfigTest, DefaultConstruction) {
    SomeipConfig config;
    EXPECT_TRUE(config.applicationName.empty());
    EXPECT_EQ(config.serviceId, 0);
    EXPECT_EQ(config.instanceId, 0);
    EXPECT_EQ(config.getSeedMethodId, 0);
    EXPECT_EQ(config.verifyKeyMethodId, 0);
    EXPECT_EQ(config.deriveOtaSessionMethodId, 0);
    EXPECT_EQ(config.deriveByUidMethodId, 0);
    EXPECT_EQ(config.wrapByUidMethodId, 0);
    EXPECT_EQ(config.endpointPort, 0);
    EXPECT_TRUE(config.endpointProtocol.empty());
    EXPECT_TRUE(config.endpointUnicast.empty());
    EXPECT_FALSE(config.serviceDiscoveryEnabled);
    EXPECT_TRUE(config.serviceDiscoveryMode.empty());
    EXPECT_TRUE(config.serviceDiscoveryMulticastAddress.empty());
    EXPECT_EQ(config.serviceDiscoveryPort, 0);
}

TEST(SeHsmConfigTest, DefaultConstruction) {
    SeHsmConfig config;
    EXPECT_TRUE(config.type.empty());
    EXPECT_TRUE(config.adapter.empty());
}
