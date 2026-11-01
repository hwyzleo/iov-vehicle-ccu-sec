#include "config_loader.h"
#include "sec_someip_service.h"
#include "sec_someip_server.h"
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include "constants.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include <chrono>

#ifdef USE_MOCK_SOMEIP
#include "mock_someip_network.h"
#endif

using namespace ccu_sec;

static std::atomic<bool> running{true};

void signalHandler([[maybe_unused]] int signum) {
    // 信号处理仍使用 stderr，因为 Logger 可能正在关闭
    std::cerr << "Interrupt signal (" << signum << ") received." << std::endl;
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    try {
        // CCU-SEC-DSN-CR-004: 启动顺序
        // 加载基础配置 -> 读取 common.log.* / sec.log.* -> Logger::init("ccu-sec")
        // -> 创建模块 Logger -> 初始化 SE/HSM / keystore -> 初始化 SOME/IP Provider -> 开放安全接口

        // 加载结构化日志配置并初始化 Logger（在创建业务模块之前）
        auto log_config = ConfigLoader::loadLogConfig("config/sec_config.yaml");
        auto log_result = SecLogAdapter::init("ccu-sec", log_config);
        if (log_result.error != ccu::fw::log::LogError::kOk) {
            // 严格模式初始化失败时，在开放 SOME/IP 安全接口前终止启动
            // （CCU-SEC-DSN-CR-004 §实时性与故障降级）
            std::cerr << "FATAL: Logger init failed: " << log_result.error_message << std::endl;
            return 1;
        }

        // 加载基础配置
        auto secConfig = ConfigLoader::loadSecConfig("config/sec_config.yaml");
        auto someipConfig = ConfigLoader::loadSomeipConfig("config/someip_config.yaml");
        auto seHsmConfig = ConfigLoader::loadSeHsmConfig("config/se_hsm_config.yaml");

#ifdef USE_MOCK_SOMEIP
        // 加载网络配置
        auto& configManager = mock_someip::ConfigManager::get_instance();
        if (!configManager.load_config("config/vsomeip.json")) {
            SecLogAdapter::facade().error(sec_events::SE_ACCESS_FAILED,
                "Failed to load network configuration",
                {slog::f_str("config_path", "config/vsomeip.json")});
            return 1;
        }
        SecLogAdapter::facade().info("sec.service.config_loaded",
            "Network configuration loaded",
            {slog::f_str("config_path", "config/vsomeip.json")});
#endif

        // 初始化业务逻辑（SE/HSM / keystore）
        auto serviceStartTime = std::chrono::steady_clock::now();
        auto service = std::make_shared<SecSomeipService>(secConfig, someipConfig, seHsmConfig);

        // 初始化 SOME/IP server（Provider）
        SecSomeipServer server(service, someipConfig);
        if (!server.start()) {
            SecLogAdapter::facade().error("sec.service.start_failed",
                "Failed to start SOME/IP server",
                {slog::f_str("someip_service_id", hex_id(someipConfig.serviceId)),
                 slog::f_str("someip_instance_id", hex_id(someipConfig.instanceId))});
            return 1;
        }

        // 计算初始化耗时
        auto serviceEndTime = std::chrono::steady_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            serviceEndTime - serviceStartTime).count();

        // sec.service.initialized: Logger、SE/HSM 与接口初始化完成
        // （CCU-SEC-DSN-CR-004 §事件目录）
        SecLogAdapter::facade().info(sec_events::SERVICE_INITIALIZED,
            "CCU-SEC service initialized",
            {slog::f_str("result", "success"),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("someip_service_id", hex_id(someipConfig.serviceId)),
             slog::f_str("someip_instance_id", hex_id(someipConfig.instanceId)),
             slog::f_str("transport", "TCP"),
             slog::f_int("someip_port", SEC_SOMEIP_PORT)});

        // 主循环 - 驱动 SOME/IP 事件处理
        while (running) {
            // vsomeip 事件循环在单独线程中运行
            // 主线程可以执行其他任务或监控
            sleep(1);

            // 可以在这里添加监控逻辑
            if (!server.isRunning()) {
                SecLogAdapter::facade().error("sec.service.server_stopped",
                    "SOME/IP server stopped unexpectedly");
                break;
            }
        }

        // 清理
        server.stop();
        service->stop();

        SecLogAdapter::facade().info("sec.service.stopped",
            "CCU-SEC service stopped");

    } catch (const std::exception& e) {
        std::cerr << "CCU-SEC Service failed: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
