#pragma once

#include <memory>
#include <mutex>
#include <map>
#include <atomic>
#include <thread>
#include <functional>
#include "data_models.h"
#include "error_codes.h"
#include "sec_someip_service.h"
#include "sec_log_adapter.h"
#include "sec_log_context.h"

// 根据编译选项选择 SOME/IP 实现
#ifdef USE_MOCK_SOMEIP
    #include "mock_someip_network.h"
    namespace someip = mock_someip;
#else
#include <vsomeip/vsomeip.hpp>
namespace someip = vsomeip;
#endif

namespace cgw_sec {

// SOME/IP 方法处理函数类型
using MethodHandler = std::function<void(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response)>;

class SecSomeipServer {
public:
    SecSomeipServer(std::shared_ptr<SecSomeipService> service,
                    const SomeipConfig& config);
    ~SecSomeipServer();

    // 启动/停止服务
    bool start();
    void stop();
    bool isRunning() const;

    // 获取服务状态
    bool isServiceAvailable() const;

private:
    // vsomeip 核心组件
    std::shared_ptr<someip::Runtime> runtime_;
    std::shared_ptr<someip::Application> application_;
    
    // 业务逻辑
    std::shared_ptr<SecSomeipService> service_;
    SomeipConfig config_;
    
    // 状态管理
    std::atomic<bool> running_{false};
    std::atomic<bool> serviceAvailable_{false};
    std::thread routingThread_;
    
    // 方法处理器映射
    std::map<uint16_t, MethodHandler> methodHandlers_;
    
    // 初始化方法
    void initializeApplication();
    void registerMethodHandlers();
    void registerService();
    void unregisterService();
    
    // 方法处理函数
    void handleGetSeed(const std::shared_ptr<someip::Message>& request,
                       std::shared_ptr<someip::Message>& response);
    void handleVerifyKey(const std::shared_ptr<someip::Message>& request,
                         std::shared_ptr<someip::Message>& response);
    void handleDeriveOtaSession(const std::shared_ptr<someip::Message>& request,
                                std::shared_ptr<someip::Message>& response);
    void handleDeriveByUid(const std::shared_ptr<someip::Message>& request,
                           std::shared_ptr<someip::Message>& response);
    void handleWrapByUid(const std::shared_ptr<someip::Message>& request,
                         std::shared_ptr<someip::Message>& response);
    
    // 辅助函数
    std::vector<uint8_t> serializeSeedResult(const SeedResult& result);
    std::vector<uint8_t> serializeOtaSessionResult(const OtaSessionResult& result);
    std::vector<uint8_t> serializeKeyResult(const KeyResult& result);
    std::vector<uint8_t> serializeSecureDataResult(const SecureDataResult& result);
    std::vector<uint8_t> serializeErrorCode(CgwSecErrorCode code);
    
    SeedResult deserializeSeedResult(const std::vector<uint8_t>& data);
    OtaSessionContext deserializeOtaSessionContext(const std::vector<uint8_t>& data);
    std::pair<std::string, std::vector<uint8_t>> deserializeKeyRequest(const std::vector<uint8_t>& data);
    std::pair<std::string, std::vector<uint8_t>> deserializeWrapRequest(const std::vector<uint8_t>& data);
};

} // namespace cgw_sec
