#include <iostream>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include "config_loader.h"
#include "sec_someip_service.h"
#include "sec_someip_server.h"

#ifdef USE_MOCK_SOMEIP
#include "mock_someip_network.h"
#endif

using namespace cgw_sec;

static std::atomic<bool> running{true};

void signalHandler([[maybe_unused]] int signum) {
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::cout << "CGW-SEC Service starting..." << std::endl;

    try {
        // Load configuration
        auto secConfig = ConfigLoader::loadSecConfig("config/sec_config.yaml");
        auto someipConfig = ConfigLoader::loadSomeipConfig("config/someip_config.yaml");
        auto seHsmConfig = ConfigLoader::loadSeHsmConfig("config/se_hsm_config.yaml");
        
#ifdef USE_MOCK_SOMEIP
        // 加载网络配置
        auto& configManager = mock_someip::ConfigManager::get_instance();
        if (!configManager.load_config("config/vsomeip.json")) {
            std::cerr << "Failed to load network configuration" << std::endl;
            return 1;
        }
        std::cout << "Network configuration loaded" << std::endl;
#endif

        // Initialize business logic
        auto service = std::make_shared<SecSomeipService>(secConfig, someipConfig, seHsmConfig);
        
        // Initialize SOME/IP server
        SecSomeipServer server(service, someipConfig);
        if (!server.start()) {
            std::cerr << "Failed to start SOME/IP server" << std::endl;
            return 1;
        }
        
        std::cout << "CGW-SEC Service started successfully" << std::endl;
        
#ifdef USE_MOCK_SOMEIP
        std::cout << "SOME/IP service available on network (TCP)" << std::endl;
        std::cout << "Configuration: config/vsomeip.json" << std::endl;
#else
        std::cout << "SOME/IP service available (vsomeip)" << std::endl;
#endif

        // Main loop - drive SOME/IP event processing
        while (running) {
            // vsomeip 事件循环在单独线程中运行
            // 主线程可以执行其他任务或监控
            sleep(1);
            
            // 可以在这里添加监控逻辑
            if (!server.isRunning()) {
                std::cerr << "SOME/IP server stopped unexpectedly" << std::endl;
                break;
            }
        }

        // Cleanup
        server.stop();
        service->stop();
        std::cout << "CGW-SEC Service stopped" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "CGW-SEC Service failed: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
