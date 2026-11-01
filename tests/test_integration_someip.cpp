#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>
#include "sec_someip_server.h"
#include "sec_someip_client.h"
#include "sec_someip_service.h"
#include "config_loader.h"
#include "constants.h"
#include <string>

using namespace ccu_sec;

class SomeipIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 构建配置文件的绝对路径
        std::string sourceDir = SOURCE_DIR;
        std::string secConfigPath = sourceDir + "/config/sec_config.yaml";
        std::string someipConfigPath = sourceDir + "/config/someip_config.yaml";
        std::string seHsmConfigPath = sourceDir + "/config/se_hsm_config.yaml";
        
        // 加载配置
        secConfig_ = ConfigLoader::loadSecConfig(secConfigPath);
        someipConfig_ = ConfigLoader::loadSomeipConfig(someipConfigPath);
        seHsmConfig_ = ConfigLoader::loadSeHsmConfig(seHsmConfigPath);
        
        // 创建服务
        service_ = std::make_shared<SecSomeipService>(secConfig_, someipConfig_, seHsmConfig_);
        
        // 创建服务端
        server_ = std::make_unique<SecSomeipServer>(service_, someipConfig_);
        
        // 创建客户端
        client_ = std::make_unique<SecSomeipClient>(someipConfig_);
    }
    
    void TearDown() override {
        if (client_) {
            client_->deinitialize();
        }
        if (server_) {
            server_->stop();
        }
    }
    
    // 启动服务端和客户端
    bool startBoth() {
        std::cout << "Starting server..." << std::endl;
        if (!server_->start()) {
            std::cerr << "Failed to start server" << std::endl;
            return false;
        }
        
        // 等待服务端启动
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        std::cout << "Initializing client..." << std::endl;
        if (!client_->initialize()) {
            std::cerr << "Failed to initialize client" << std::endl;
            return false;
        }
        
        // 等待客户端连接（增加等待时间）
        for (int i = 0; i < 50; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            bool connected = client_->isConnected();
            if (i % 10 == 0) {
                std::cout << "Waiting for connection... " << i * 100 << " ms, connected: " << connected << std::endl;
            }
            if (connected) {
                std::cout << "Client connected after " << (i + 1) * 100 << " ms" << std::endl;
                return true;
            }
        }
        
        // 最后再检查一次
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        bool connected = client_->isConnected();
        std::cout << "Final check: connected=" << connected << std::endl;
        return connected;
        
        std::cerr << "Client not connected after 5 seconds" << std::endl;
        return false;
    }
    
    SecConfig secConfig_;
    SomeipConfig someipConfig_;
    SeHsmConfig seHsmConfig_;
    std::shared_ptr<SecSomeipService> service_;
    std::unique_ptr<SecSomeipServer> server_;
    std::unique_ptr<SecSomeipClient> client_;
};

TEST_F(SomeipIntegrationTest, GetSeedIntegration) {
    std::cout << "Starting GetSeedIntegration test" << std::endl;
    bool connected = startBoth();
    std::cout << "startBoth returned: " << connected << std::endl;
    ASSERT_TRUE(connected);
    
    // 测试 getSeed
    std::cout << "Calling getSeed" << std::endl;
    auto result = client_->getSeed(0x01);
    std::cout << "getSeed returned: error=" << static_cast<uint32_t>(result.error) << 
              ", seedId=" << result.seedId << 
              ", seed.size=" << result.seed.size() << std::endl;
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.seedId, 0);
    EXPECT_EQ(result.seed.size(), SEED_SIZE);
}

TEST_F(SomeipIntegrationTest, VerifyKeyIntegration) {
    ASSERT_TRUE(startBoth());
    
    // 先获取 seed
    auto seedResult = client_->getSeed(0x01);
    ASSERT_EQ(seedResult.error, CcuSecErrorCode::SUCCESS);
    
    // 这里应该使用正确的 key，但测试中我们使用错误的 key
    std::vector<uint8_t> wrongKey(KEY_SIZE, 0x00);
    auto verifyResult = client_->verifyKey(0x01, seedResult.seedId, wrongKey);
    EXPECT_EQ(verifyResult, CcuSecErrorCode::KEY_VERIFICATION_FAILED);
}

TEST_F(SomeipIntegrationTest, DeriveOtaSessionIntegration) {
    ASSERT_TRUE(startBoth());
    
    // 创建 OTA 会话上下文
    OtaSessionContext context;
    context.campaignId = "test-campaign-001";
    context.vin = "1HGBH41JXMN109186";
    context.direction = "authorize";
    context.nonce = std::vector<uint8_t>(12, 0x42);
    context.timestamp = 1234567890;
    
    // 测试 deriveOtaSession
    auto result = client_->deriveOtaSession(context, 0x01);
    
    // 由于软件模拟 HSM 中存储了 OTA_VEHICLE_ROOT 密钥，应该返回成功
    EXPECT_EQ(result.error, CcuSecErrorCode::SUCCESS);
    EXPECT_GT(result.sessionKeyHandle, 0u);
    EXPECT_EQ(result.nonce.size(), NONCE_SIZE);
}

TEST_F(SomeipIntegrationTest, ServiceUnavailable) {
    // 不启动服务端，测试客户端行为
    ASSERT_TRUE(client_->initialize());
    
    // 等待超时
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    
    EXPECT_FALSE(client_->isConnected());
    
    auto result = client_->getSeed(0x01);
    EXPECT_EQ(result.error, CcuSecErrorCode::UNAUTHORIZED_REQUEST);
}
