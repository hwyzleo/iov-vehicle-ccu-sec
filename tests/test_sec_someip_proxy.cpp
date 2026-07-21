#include <gtest/gtest.h>
#include "sec_someip_proxy.h"
#include "constants.h"
#include "data_models.h"

using namespace cgw_sec;

class SecSomeipProxyTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.serviceId = 0x1234;
        config_.instanceId = 0x5678;
        config_.getSeedMethodId = 0x0001;
        config_.verifyKeyMethodId = 0x0002;
        config_.deriveOtaSessionMethodId = 0x0003;
        config_.deriveByUidMethodId = 0x0004;
        config_.wrapByUidMethodId = 0x0005;
    }

    SomeipConfig config_;
};

TEST_F(SecSomeipProxyTest, Construction) {
    SecSomeipProxy proxy(config_);
}

TEST_F(SecSomeipProxyTest, GetSeedThrows) {
    SecSomeipProxy proxy(config_);
    EXPECT_THROW(proxy.getSeed(SECURITY_LEVEL_1), std::runtime_error);
}

TEST_F(SecSomeipProxyTest, VerifyKeyThrows) {
    SecSomeipProxy proxy(config_);
    std::vector<uint8_t> key(KEY_SIZE, 0x42);
    EXPECT_THROW(proxy.verifyKey(SECURITY_LEVEL_1, 1, key), std::runtime_error);
}

TEST_F(SecSomeipProxyTest, DeriveOtaSessionThrows) {
    SecSomeipProxy proxy(config_);
    OtaSessionContext context;
    EXPECT_THROW(proxy.deriveOtaSession(context, SECURITY_LEVEL_1), std::runtime_error);
}

TEST_F(SecSomeipProxyTest, DeriveByUidThrows) {
    SecSomeipProxy proxy(config_);
    std::vector<uint8_t> ctx = {0x01, 0x02, 0x03};
    EXPECT_THROW(proxy.deriveByUid("TEST_KEY", ctx, SECURITY_LEVEL_1), std::runtime_error);
}

TEST_F(SecSomeipProxyTest, WrapByUidThrows) {
    SecSomeipProxy proxy(config_);
    std::vector<uint8_t> data = {0x10, 0x20, 0x30, 0x40};
    EXPECT_THROW(proxy.wrapByUid(data, SECURITY_LEVEL_1), std::runtime_error);
}

TEST_F(SecSomeipProxyTest, GetSeedExceptionMessage) {
    SecSomeipProxy proxy(config_);
    try {
        proxy.getSeed(SECURITY_LEVEL_1);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "SOME/IP proxy not implemented - use SecSomeipService directly");
    }
}

TEST_F(SecSomeipProxyTest, VerifyKeyExceptionMessage) {
    SecSomeipProxy proxy(config_);
    std::vector<uint8_t> key(KEY_SIZE, 0x42);
    try {
        proxy.verifyKey(SECURITY_LEVEL_1, 1, key);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "SOME/IP proxy not implemented - use SecSomeipService directly");
    }
}
