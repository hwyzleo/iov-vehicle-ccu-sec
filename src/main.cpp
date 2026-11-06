#include "config_loader.h"
#include "sec_someip_service.h"
#include "sec_someip_server.h"
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include "constants.h"
#include <iostream>
#include <string>
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

namespace {

void printUsage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  --sec-config <path>      Path to unified SEC config (default: "
              << SEC_DEFAULT_CONFIG_PATH << ")\n"
              << "  --common-config <path>   Path to common config (dev/test override; default: "
              << SEC_DEFAULT_COMMON_CONFIG_PATH << ")\n"
              << "  --vsomeip-config <path>  Dev/test override: mock SOME/IP network JSON "
                 "(required when USE_MOCK_SOMEIP=ON)\n"
              << "  --help                   Show this help message\n";
}

} // namespace

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Production defaults (CCU-SEC-DSN-CR-005 §5.4). The production unit
    // relies only on these; explicit overrides are dev/test entry points.
    std::string sec_config_path = SEC_DEFAULT_CONFIG_PATH;
    std::string common_config_path = SEC_DEFAULT_COMMON_CONFIG_PATH;
    std::string vsomeip_config_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--sec-config" && i + 1 < argc) {
            sec_config_path = argv[++i];
        } else if (arg == "--common-config" && i + 1 < argc) {
            common_config_path = argv[++i];
        } else if (arg == "--vsomeip-config" && i + 1 < argc) {
            vsomeip_config_path = argv[++i];
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    try {
        // CCU-SEC-DSN-CR-005 §8.2 启动顺序：
        // 加载 /etc/ccu/common.yaml 与 /etc/ccu/conf.d/sec.yaml
        // -> 初始化统一 Logger 与零泄露审计字段
        // -> 解析 sec.security / sec.someip / sec.se_hsm（unconfigured 在
        //    ready/offer 前失败）
        // -> 创建批准 SE/HSM adapter 并检查逻辑根已 provisioned
        // -> 初始化本进程唯一的 ccu-sec SOME/IP application 后开放 Provider
        auto config = ConfigLoader::loadUnifiedConfig(sec_config_path, common_config_path);

        auto log_result = SecLogAdapter::init(SEC_APPLICATION_NAME, config.log);
        if (log_result.error != ccu::fw::log::LogError::kOk) {
            // 严格模式初始化失败时，在开放 SOME/IP 安全接口前终止启动
            // （CCU-SEC-DSN-CR-004 §实时性与故障降级）
            std::cerr << "FATAL: Logger init failed: " << log_result.error_message << std::endl;
            return 1;
        }

        SecLogAdapter::facade().info("sec.service.config_loaded",
            "Unified SEC configuration loaded",
            {slog::f_str("sec_config_path", sec_config_path),
             slog::f_str("common_config_path", common_config_path),
             slog::f_str("someip_service_id", hex_id(config.someip.serviceId)),
             slog::f_str("someip_instance_id", hex_id(config.someip.instanceId)),
             slog::f_str("se_hsm_type", config.se_hsm.type)});

#ifdef USE_MOCK_SOMEIP
        // Non-production mock SOME/IP backend. The network fixture path is an
        // explicit dev/test input; production TARGET builds use the real
        // vsomeip backend and platform vsomeip JSON.
        if (vsomeip_config_path.empty()) {
            SecLogAdapter::facade().error(sec_events::SE_ACCESS_FAILED,
                "Mock SOME/IP backend requires --vsomeip-config (NON_PRODUCTION)",
                {slog::f_str("reason", "missing --vsomeip-config")});
            return 1;
        }
        auto& configManager = mock_someip::ConfigManager::get_instance();
        if (!configManager.load_config(vsomeip_config_path)) {
            SecLogAdapter::facade().error(sec_events::SE_ACCESS_FAILED,
                "Failed to load network configuration",
                {slog::f_str("config_path", vsomeip_config_path)});
            return 1;
        }
        SecLogAdapter::facade().info("sec.service.config_loaded",
            "Network configuration loaded",
            {slog::f_str("config_path", vsomeip_config_path)});
#endif

        // 初始化业务逻辑（SE/HSM / keystore）：adapter 不可用或根缺失时
        // 构造即失败（fail-closed，绝不开放 Provider）。
        auto serviceStartTime = std::chrono::steady_clock::now();
        auto service = std::make_shared<SecSomeipService>(
            config.security, config.someip, config.se_hsm);

        // 初始化 SOME/IP server（Provider）
        SecSomeipServer server(service, config.someip);
        if (!server.start()) {
            SecLogAdapter::facade().error("sec.service.start_failed",
                "Failed to start SOME/IP server",
                {slog::f_str("someip_service_id", hex_id(config.someip.serviceId)),
                 slog::f_str("someip_instance_id", hex_id(config.someip.instanceId))});
            return 1;
        }

        // 计算初始化耗时
        auto serviceEndTime = std::chrono::steady_clock::now();
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            serviceEndTime - serviceStartTime).count();

        // sec.service.initialized: Logger、SE/HSM 与接口初始化完成
        // （CCU-SEC-DSN-CR-004 §事件目录；security_ready 区分进程存活与
        //  安全能力 ready，CCU-SEC-DSN-CR-005 §6.2）
        SecLogAdapter::facade().info(sec_events::SERVICE_INITIALIZED,
            "CCU-SEC service initialized",
            {slog::f_str("result", "success"),
             slog::f_bool("security_ready", service->securityReady()),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("someip_service_id", hex_id(config.someip.serviceId)),
             slog::f_str("someip_instance_id", hex_id(config.someip.instanceId)),
             slog::f_str("transport", config.someip.endpointProtocol),
             slog::f_int("someip_port", config.someip.endpointPort)});

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
        // 配置解析失败或 SE/HSM fail-closed：绝不开放安全接口
        if (SecLogAdapter::isInitialized()) {
            SecLogAdapter::facade().error(sec_events::SE_ACCESS_FAILED,
                "CCU-SEC startup aborted (fail-closed)",
                {slog::f_str("reason", e.what())});
        }
        std::cerr << "CCU-SEC Service failed: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
