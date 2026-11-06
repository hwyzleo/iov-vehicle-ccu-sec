/**
 * 简单的 SOME/IP 客户端示例
 * 
 * 演示如何使用网络 mock 实现连接到 SEC 服务
 * 
 * 编译方法：
 * cd build && cmake .. -DUSE_MOCK_SOMEIP=ON && make simple_client
 */

#include <iostream>
#include <thread>
#include <chrono>
#include "sec_someip_client.h"
#include "config_loader.h"

using namespace ccu_sec;

int main() {
    std::cout << "Simple SOME/IP Client Example" << std::endl;
    std::cout << "==============================" << std::endl;
    
    // 加载统一配置（开发夹具）：仅取 sec.someip 子树
    auto unified = ConfigLoader::loadUnifiedConfig("config/dev/sec.yaml",
                                                   "config/dev/common.yaml");
    auto someipConfig = unified.someip;
    
    // 创建客户端
    SecSomeipClient client(someipConfig);
    
    // 初始化客户端
    std::cout << "Initializing client..." << std::endl;
    if (!client.initialize()) {
        std::cerr << "Failed to initialize client" << std::endl;
        return 1;
    }
    
    // 等待连接
    std::cout << "Waiting for connection..." << std::endl;
    for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (client.isConnected()) {
            std::cout << "Connected to service!" << std::endl;
            break;
        }
        if (i % 10 == 0) {
            std::cout << "Waiting... " << i * 100 << " ms" << std::endl;
        }
    }
    
    if (!client.isConnected()) {
        std::cerr << "Failed to connect to service" << std::endl;
        return 1;
    }
    
    // 测试 getSeed
    std::cout << "\n1. Testing getSeed..." << std::endl;
    auto seedResult = client.getSeed(0x01);
    std::cout << "   Result: " << (seedResult.error == CcuSecErrorCode::SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
    if (seedResult.error == CcuSecErrorCode::SUCCESS) {
        std::cout << "   Seed ID: " << seedResult.seedId << std::endl;
        std::cout << "   Seed size: " << seedResult.seed.size() << " bytes" << std::endl;
    }
    
    // 测试 deriveOtaSession
    std::cout << "\n2. Testing deriveOtaSession..." << std::endl;
    OtaSessionContext context;
    context.campaignId = "test-campaign-001";
    context.vin = "1HGBH41JXMN109186";
    context.direction = "authorize";
    context.nonce = std::vector<uint8_t>(12, 0x42);
    context.timestamp = 1234567890;
    
    auto sessionResult = client.deriveOtaSession(context, 0x01);
    std::cout << "   Result: " << (sessionResult.error == CcuSecErrorCode::SUCCESS ? "SUCCESS" : "FAILED") << std::endl;
    if (sessionResult.error == CcuSecErrorCode::SUCCESS) {
        std::cout << "   Session Key Handle: " << sessionResult.sessionKeyHandle << std::endl;
        std::cout << "   Nonce size: " << sessionResult.nonce.size() << " bytes" << std::endl;
    }
    
    // 清理
    std::cout << "\nDeinitializing client..." << std::endl;
    client.deinitialize();
    
    std::cout << "Client example completed!" << std::endl;
    return 0;
}
