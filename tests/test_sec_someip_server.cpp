#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "sec_someip_server.h"
#include "sec_someip_service.h"
#include "config_loader.h"
#include <string>

using namespace ccu_sec;

class SecSomeipServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 构建配置文件的绝对路径
        std::string sourceDir = SOURCE_DIR;
        std::string secConfigPath = sourceDir + "/config/sec_config.yaml";
        std::string someipConfigPath = sourceDir + "/config/someip_config.yaml";
        std::string seHsmConfigPath = sourceDir + "/config/se_hsm_config.yaml";
        
        // 加载测试配置
        secConfig_ = ConfigLoader::loadSecConfig(secConfigPath);
        someipConfig_ = ConfigLoader::loadSomeipConfig(someipConfigPath);
        seHsmConfig_ = ConfigLoader::loadSeHsmConfig(seHsmConfigPath);
        
        // 创建服务实例
        service_ = std::make_shared<SecSomeipService>(secConfig_, someipConfig_, seHsmConfig_);
        
        // 创建服务端实例
        server_ = std::make_unique<SecSomeipServer>(service_, someipConfig_);
    }
    
    void TearDown() override {
        if (server_) {
            server_->stop();
        }
    }
    
    SecConfig secConfig_;
    SomeipConfig someipConfig_;
    SeHsmConfig seHsmConfig_;
    std::shared_ptr<SecSomeipService> service_;
    std::unique_ptr<SecSomeipServer> server_;
};

TEST_F(SecSomeipServerTest, StartStop) {
    // 测试启动
    EXPECT_TRUE(server_->start());
    EXPECT_TRUE(server_->isRunning());
    
    // 测试重复启动
    EXPECT_TRUE(server_->start()); // 应该返回 true，不崩溃
    
    // 测试停止
    server_->stop();
    EXPECT_FALSE(server_->isRunning());
}

TEST_F(SecSomeipServerTest, ServiceAvailability) {
    EXPECT_TRUE(server_->start());
    EXPECT_TRUE(server_->isServiceAvailable());
    
    server_->stop();
    EXPECT_FALSE(server_->isServiceAvailable());
}

TEST_F(SecSomeipServerTest, InvalidConfig) {
    // 测试无效配置
    SomeipConfig invalidConfig;
    invalidConfig.serviceId = 0; // 无效
    
    // 应该抛出异常或返回 false
    SecSomeipServer invalidServer(service_, invalidConfig);
    EXPECT_FALSE(invalidServer.start());
}
