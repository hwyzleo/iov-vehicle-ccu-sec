#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "sec_someip_client.h"
#include "config_loader.h"
#include <string>

using namespace ccu_sec;

class SecSomeipClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 统一配置（开发夹具）：仅取 sec.someip 子树构造客户端配置。
        std::string sourceDir = SOURCE_DIR;
        auto unified = ConfigLoader::loadUnifiedConfig(
            sourceDir + "/config/dev/sec.yaml",
            sourceDir + "/config/dev/common.yaml");
        someipConfig_ = unified.someip;
        client_ = std::make_unique<SecSomeipClient>(someipConfig_);
    }
    
    void TearDown() override {
        if (client_) {
            client_->deinitialize();
        }
    }
    
    SomeipConfig someipConfig_;
    std::unique_ptr<SecSomeipClient> client_;
};

TEST_F(SecSomeipClientTest, Initialize) {
    // 测试初始化
    EXPECT_TRUE(client_->initialize());
    // 客户端未连接到服务端，因此 isConnected() 应该返回 false
    EXPECT_FALSE(client_->isConnected());
}

TEST_F(SecSomeipClientTest, GetSeedWithoutConnection) {
    // 未连接时调用应该返回错误
    auto result = client_->getSeed(0x01);
    EXPECT_EQ(result.error, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}

TEST_F(SecSomeipClientTest, VerifyKeyWithoutConnection) {
    std::vector<uint8_t> key(16, 0x42);
    auto result = client_->verifyKey(0x01, 1, key);
    EXPECT_EQ(result, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}
