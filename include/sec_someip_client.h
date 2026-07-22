#pragma once

#include <memory>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "data_models.h"
#include "error_codes.h"
#include "se_hsm_interface.h"

// 根据编译选项选择 SOME/IP 实现
#ifdef USE_MOCK_SOMEIP
    #include "mock_someip_network.h"
    namespace someip = mock_someip;
#else
#include <vsomeip/vsomeip.hpp>
namespace someip = vsomeip;
#endif

namespace cgw_sec {

class SecSomeipClient {
public:
    SecSomeipClient(const SomeipConfig& config);
    ~SecSomeipClient();

    // 初始化与连接
    bool initialize();
    void deinitialize();
    bool isConnected() const;

    // 服务调用
    SeedResult getSeed(uint8_t level);
    CgwSecErrorCode verifyKey(uint8_t level, uint32_t seedId, const std::vector<uint8_t>& key);
    OtaSessionResult deriveOtaSession(const OtaSessionContext& context, uint8_t level);
    KeyResult deriveByUid(const std::string& subKeyName, const std::vector<uint8_t>& context, uint8_t level);
    SecureDataResult wrapByUid(const std::vector<uint8_t>& data, uint8_t level);

private:
    // vsomeip 组件
    std::shared_ptr<someip::Runtime> runtime_;
    std::shared_ptr<someip::Application> application_;
    
    // 配置
    SomeipConfig config_;
    
    // 状态管理
    std::atomic<bool> connected_{false};
    std::atomic<bool> running_{false};
    std::thread ioThread_;
    
    // 同步机制
    std::mutex mutex_;
    std::condition_variable cv_;
    bool responseReceived_ = false;
    std::vector<uint8_t> responseData_;
    
    // 初始化方法
    void initializeApplication();
    void registerServiceDiscovery();
    void onServiceAvailability(someip::service_t service, someip::instance_t instance, bool available);
    void onMessage(const std::shared_ptr<someip::Message>& response);
    
    // 序列化/反序列化辅助函数
    std::vector<uint8_t> serializeGetSeedRequest(uint8_t level);
    std::vector<uint8_t> serializeVerifyKeyRequest(uint8_t level, uint32_t seedId, 
                                                   const std::vector<uint8_t>& key);
    std::vector<uint8_t> serializeDeriveOtaSessionRequest(const OtaSessionContext& context, 
                                                          uint8_t level);
    std::vector<uint8_t> serializeDeriveByUidRequest(const std::string& subKeyName,
                                                     const std::vector<uint8_t>& context,
                                                     uint8_t level);
    std::vector<uint8_t> serializeWrapByUidRequest(const std::vector<uint8_t>& data, 
                                                   uint8_t level);
    
    // 发送请求并等待响应
    std::vector<uint8_t> sendRequest(uint16_t methodId, const std::vector<uint8_t>& payload);
    
    // 日志
    void logInfo(const std::string& message);
    void logError(const std::string& message);
    void logWarning(const std::string& message);
};

} // namespace cgw_sec
