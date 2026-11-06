#include "sec_someip_client.h"
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include <sstream>
#include <stdexcept>
#include <chrono>

namespace ccu_sec {

SecSomeipClient::SecSomeipClient(const SomeipConfig& config) : config_(config) {
}

SecSomeipClient::~SecSomeipClient() {
    deinitialize();
}

bool SecSomeipClient::initialize() {
    if (running_) {
        SecLogAdapter::facade().warn("sec.client.already_initialized",
            "Client already initialized");
        return true;
    }
    
    try {
        SecLogAdapter::facade().info("sec.client.initializing",
            "Initializing application...");
        initializeApplication();
        SecLogAdapter::facade().info("sec.client.registering_sd",
            "Registering service discovery...");
        registerServiceDiscovery();
        SecLogAdapter::facade().info("sec.client.sd_registered",
            "Service discovery registered",
            {slog::f_bool("connected", connected_.load())});
        
        running_ = true;
        
        // 启动 IO 线程
        SecLogAdapter::facade().info("sec.client.io_thread_starting",
            "Starting IO thread...");
        ioThread_ = std::thread([this]() {
            application_->start();
        });
        
        // 等待一下，让服务发现有机会完成
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        SecLogAdapter::facade().info("sec.client.initialized",
            "SOME/IP client initialized",
            {slog::f_bool("connected", connected_.load())});
        return true;
        
    } catch (const std::exception& e) {
        SecLogAdapter::facade().error("sec.client.init_failed",
            "Failed to initialize client",
            {slog::f_str("reason", e.what())});
        return false;
    }
}

void SecSomeipClient::deinitialize() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    connected_ = false;
    
    if (application_) {
        application_->stop();
    }
    
    if (ioThread_.joinable()) {
        ioThread_.join();
    }
    
    SecLogAdapter::facade().info("sec.client.deinitialized",
        "SOME/IP client deinitialized");
}

bool SecSomeipClient::isConnected() const {
    return connected_;
}

void SecSomeipClient::initializeApplication() {
    runtime_ = someip::Runtime::get();
    if (!runtime_) {
        throw std::runtime_error("Failed to get vsomeip runtime");
    }
    
    // 注意（CCU-SEC-DSN-CR-005 §5.4）：本类是非生产侧的 SEC client/proxy，
    // 只由测试、examples 与调用方进程使用。生产 daemon（ccu_sec）只创建
    // 唯一的 ccu-sec provider application，不会在同一进程内同时创建
    // ccu-sec-client 与 ccu-sec。
    application_ = runtime_->create_application("ccu-sec-client");
    if (!application_) {
        throw std::runtime_error("Failed to create vsomeip application");
    }
    
    application_->init();
    
    // 注册消息处理器
    application_->register_message_handler(
        config_.serviceId, config_.instanceId, someip::ANY_METHOD,
        std::bind(&SecSomeipClient::onMessage, this, std::placeholders::_1));
    
    // 注册服务可用性处理器
    application_->register_availability_handler(
        config_.serviceId, config_.instanceId,
        std::bind(&SecSomeipClient::onServiceAvailability, this,
                  std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    
    SecLogAdapter::facade().info("sec.client.app_initialized",
        "vsomeip application initialized");
}

void SecSomeipClient::registerServiceDiscovery() {
    // 请求服务
    SecLogAdapter::facade().info("sec.client.requesting_service",
        "Requesting service...");
    application_->request_service(config_.serviceId, config_.instanceId);
    SecLogAdapter::facade().info("sec.client.service_requested",
        "Service request completed",
        {slog::f_bool("connected", connected_.load())});
    
    SecLogAdapter::facade().info("sec.client.sd_registered",
        "Service discovery registered",
        {slog::f_str("someip_service_id", hex_id(config_.serviceId)),
         slog::f_str("someip_instance_id", hex_id(config_.instanceId))});
}

void SecSomeipClient::onServiceAvailability(
    someip::service_t service, someip::instance_t instance, bool available) {
    
    if (service == config_.serviceId && instance == config_.instanceId) {
        connected_ = available;
        SecLogAdapter::facade().info("sec.client.availability_changed",
            "Service availability changed",
            {slog::f_str("result", available ? "available" : "unavailable"),
             slog::f_str("someip_service_id", hex_id(service)),
             slog::f_str("someip_instance_id", hex_id(instance))});
    }
}

void SecSomeipClient::onMessage(const std::shared_ptr<someip::Message>& response) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto payload = response->get_payload();
    auto data = payload->get_data();
    auto length = payload->get_length();
    
    responseData_.assign(data, data + length);
    responseReceived_ = true;
    cv_.notify_all();
    
    SecLogAdapter::facade().info("sec.client.response_received",
        "Response received",
        {slog::f_str("someip_method_id", hex_id(response->get_method()))});
}

SeedResult SecSomeipClient::getSeed(uint8_t level) {
    if (!connected_) {
        SeedResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    
    auto requestPayload = serializeGetSeedRequest(level);
    auto responsePayload = sendRequest(config_.getSeedMethodId, requestPayload);
    
    // 反序列化响应
    if (responsePayload.size() < 4) {
        SeedResult result;
        result.error = CcuSecErrorCode::SEED_GENERATION_FAILED;
        return result;
    }
    
    uint32_t errorCode = (responsePayload[0] << 24) | (responsePayload[1] << 16) | 
                         (responsePayload[2] << 8) | responsePayload[3];
    
    SeedResult result;
    result.error = static_cast<CcuSecErrorCode>(errorCode);
    
    if (result.error == CcuSecErrorCode::SUCCESS && responsePayload.size() >= 12) {
        result.seedId = (responsePayload[4] << 24) | (responsePayload[5] << 16) | 
                        (responsePayload[6] << 8) | responsePayload[7];
        
        uint32_t seedLength = (responsePayload[8] << 24) | (responsePayload[9] << 16) | 
                              (responsePayload[10] << 8) | responsePayload[11];
        
        if (responsePayload.size() >= 12 + seedLength) {
            result.seed.assign(responsePayload.begin() + 12, 
                              responsePayload.begin() + 12 + seedLength);
        }
    }
    
    return result;
}

CcuSecErrorCode SecSomeipClient::verifyKey(uint8_t level, uint32_t seedId, 
                                           const std::vector<uint8_t>& key) {
    if (!connected_) {
        return CcuSecErrorCode::UNAUTHORIZED_REQUEST;
    }
    
    auto requestPayload = serializeVerifyKeyRequest(level, seedId, key);
    auto responsePayload = sendRequest(config_.verifyKeyMethodId, requestPayload);
    
    if (responsePayload.size() < 4) {
        return CcuSecErrorCode::KEY_VERIFICATION_FAILED;
    }
    
    uint32_t errorCode = (responsePayload[0] << 24) | (responsePayload[1] << 16) | 
                         (responsePayload[2] << 8) | responsePayload[3];
    
    return static_cast<CcuSecErrorCode>(errorCode);
}

OtaSessionResult SecSomeipClient::deriveOtaSession(const OtaSessionContext& context, 
                                                    uint8_t level) {
    if (!connected_) {
        OtaSessionResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    
    auto requestPayload = serializeDeriveOtaSessionRequest(context, level);
    auto responsePayload = sendRequest(config_.deriveOtaSessionMethodId, requestPayload);
    
    if (responsePayload.size() < 4) {
        OtaSessionResult result;
        result.error = CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED;
        return result;
    }
    
    uint32_t errorCode = (responsePayload[0] << 24) | (responsePayload[1] << 16) | 
                         (responsePayload[2] << 8) | responsePayload[3];
    
    OtaSessionResult result;
    result.error = static_cast<CcuSecErrorCode>(errorCode);
    
    if (result.error == CcuSecErrorCode::SUCCESS && responsePayload.size() >= 12) {
        result.sessionKeyHandle = (responsePayload[4] << 24) | (responsePayload[5] << 16) | 
                                  (responsePayload[6] << 8) | responsePayload[7];
        
        uint32_t nonceLength = (responsePayload[8] << 24) | (responsePayload[9] << 16) | 
                               (responsePayload[10] << 8) | responsePayload[11];
        
        if (responsePayload.size() >= 12 + nonceLength) {
            result.nonce.assign(responsePayload.begin() + 12, 
                               responsePayload.begin() + 12 + nonceLength);
        }
    }
    
    return result;
}

KeyResult SecSomeipClient::deriveByUid(const std::string& subKeyName,
                                       const std::vector<uint8_t>& context,
                                       uint8_t level) {
    if (!connected_) {
        KeyResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    
    auto requestPayload = serializeDeriveByUidRequest(subKeyName, context, level);
    auto responsePayload = sendRequest(config_.deriveByUidMethodId, requestPayload);
    
    if (responsePayload.size() < 4) {
        KeyResult result;
        result.error = CcuSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }
    
    uint32_t errorCode = (responsePayload[0] << 24) | (responsePayload[1] << 16) | 
                         (responsePayload[2] << 8) | responsePayload[3];
    
    KeyResult result;
    result.error = static_cast<CcuSecErrorCode>(errorCode);
    
    if (result.error == CcuSecErrorCode::SUCCESS && responsePayload.size() >= 8) {
        uint32_t keyLength = (responsePayload[4] << 24) | (responsePayload[5] << 16) | 
                             (responsePayload[6] << 8) | responsePayload[7];
        
        if (responsePayload.size() >= 8 + keyLength) {
            result.key.assign(responsePayload.begin() + 8, 
                              responsePayload.begin() + 8 + keyLength);
        }
    }
    
    return result;
}

SecureDataResult SecSomeipClient::wrapByUid(const std::vector<uint8_t>& data, uint8_t level) {
    if (!connected_) {
        SecureDataResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    
    auto requestPayload = serializeWrapByUidRequest(data, level);
    auto responsePayload = sendRequest(config_.wrapByUidMethodId, requestPayload);
    
    if (responsePayload.size() < 4) {
        SecureDataResult result;
        result.error = CcuSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }
    
    uint32_t errorCode = (responsePayload[0] << 24) | (responsePayload[1] << 16) | 
                         (responsePayload[2] << 8) | responsePayload[3];
    
    SecureDataResult result;
    result.error = static_cast<CcuSecErrorCode>(errorCode);
    
    if (result.error == CcuSecErrorCode::SUCCESS && responsePayload.size() >= 8) {
        uint32_t dataLength = (responsePayload[4] << 24) | (responsePayload[5] << 16) | 
                              (responsePayload[6] << 8) | responsePayload[7];
        
        if (responsePayload.size() >= 8 + dataLength) {
            result.data.assign(responsePayload.begin() + 8, 
                               responsePayload.begin() + 8 + dataLength);
        }
    }
    
    return result;
}

// 序列化函数实现
std::vector<uint8_t> SecSomeipClient::serializeGetSeedRequest(uint8_t level) {
    return {level};
}

std::vector<uint8_t> SecSomeipClient::serializeVerifyKeyRequest(
    uint8_t level, uint32_t seedId, const std::vector<uint8_t>& key) {
    
    std::vector<uint8_t> data;
    
    // level (1 byte)
    data.push_back(level);
    
    // seedId (4 bytes)
    data.push_back(static_cast<uint8_t>((seedId >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((seedId >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((seedId >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(seedId & 0xFF));
    
    // key 长度 (4 bytes)
    uint32_t keyLength = key.size();
    data.push_back(static_cast<uint8_t>((keyLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((keyLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((keyLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(keyLength & 0xFF));
    
    // key 数据
    data.insert(data.end(), key.begin(), key.end());
    
    return data;
}

std::vector<uint8_t> SecSomeipClient::serializeDeriveOtaSessionRequest(
    const OtaSessionContext& context, uint8_t level) {
    
    std::vector<uint8_t> data;
    
    // level (1 byte)
    data.push_back(level);
    
    // campaignId 长度 (4 bytes)
    uint32_t campaignIdLength = context.campaignId.size();
    data.push_back(static_cast<uint8_t>((campaignIdLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((campaignIdLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((campaignIdLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(campaignIdLength & 0xFF));
    
    // campaignId
    data.insert(data.end(), context.campaignId.begin(), context.campaignId.end());
    
    // vin 长度 (4 bytes)
    uint32_t vinLength = context.vin.size();
    data.push_back(static_cast<uint8_t>((vinLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((vinLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((vinLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(vinLength & 0xFF));
    
    // vin
    data.insert(data.end(), context.vin.begin(), context.vin.end());
    
    // direction 长度 (4 bytes)
    uint32_t directionLength = context.direction.size();
    data.push_back(static_cast<uint8_t>((directionLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((directionLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((directionLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(directionLength & 0xFF));
    
    // direction
    data.insert(data.end(), context.direction.begin(), context.direction.end());
    
    // nonce 长度 (4 bytes)
    uint32_t nonceLength = context.nonce.size();
    data.push_back(static_cast<uint8_t>((nonceLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((nonceLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((nonceLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(nonceLength & 0xFF));
    
    // nonce
    data.insert(data.end(), context.nonce.begin(), context.nonce.end());
    
    // timestamp (8 bytes)
    for (int i = 7; i >= 0; i--) {
        data.push_back(static_cast<uint8_t>((context.timestamp >> (i * 8)) & 0xFF));
    }
    
    return data;
}

std::vector<uint8_t> SecSomeipClient::serializeDeriveByUidRequest(
    const std::string& subKeyName, const std::vector<uint8_t>& context, uint8_t level) {
    
    std::vector<uint8_t> data;
    
    // level (1 byte)
    data.push_back(level);
    
    // subKeyName 长度 (4 bytes)
    uint32_t nameLength = subKeyName.size();
    data.push_back(static_cast<uint8_t>((nameLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((nameLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((nameLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(nameLength & 0xFF));
    
    // subKeyName
    data.insert(data.end(), subKeyName.begin(), subKeyName.end());
    
    // context 长度 (4 bytes)
    uint32_t contextLength = context.size();
    data.push_back(static_cast<uint8_t>((contextLength >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((contextLength >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((contextLength >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(contextLength & 0xFF));
    
    // context
    data.insert(data.end(), context.begin(), context.end());
    
    return data;
}

std::vector<uint8_t> SecSomeipClient::serializeWrapByUidRequest(
    const std::vector<uint8_t>& data, uint8_t level) {
    
    std::vector<uint8_t> requestData;
    
    // level (1 byte)
    requestData.push_back(level);
    
    // data 长度 (4 bytes)
    uint32_t dataLength = data.size();
    requestData.push_back(static_cast<uint8_t>((dataLength >> 24) & 0xFF));
    requestData.push_back(static_cast<uint8_t>((dataLength >> 16) & 0xFF));
    requestData.push_back(static_cast<uint8_t>((dataLength >> 8) & 0xFF));
    requestData.push_back(static_cast<uint8_t>(dataLength & 0xFF));
    
    // data
    requestData.insert(requestData.end(), data.begin(), data.end());
    
    return requestData;
}

std::vector<uint8_t> SecSomeipClient::sendRequest(uint16_t methodId, 
                                                   const std::vector<uint8_t>& payload) {
    if (!connected_) {
        SecLogAdapter::facade().error("sec.client.not_connected",
            "Cannot send request: not connected to service");
        return {};
    }
    
#ifdef USE_MOCK_SOMEIP
    // 网络模式：尝试通过TCP socket同步RPC调用
    {
        SecLogAdapter::facade().info("sec.client.sending_rpc",
            "Sending RPC",
            {slog::f_str("someip_method_id", hex_id(methodId))});
        
        auto result = application_->send_rpc(config_.serviceId, config_.instanceId, methodId, payload);
        
        if (!result.empty()) {
            return result;
        }
        
        // 网络 RPC 失败，回退到进程内消息队列
        SecLogAdapter::facade().info("sec.client.rpc_fallback",
            "RPC fallback to in-process",
            {slog::f_str("someip_method_id", hex_id(methodId))});
    }
#endif
    {
        // 进程内消息队列方式（vsomeip 或 mock）
        // 创建请求消息
        auto request = runtime_->create_request();
        request->set_service(config_.serviceId);
        request->set_instance(config_.instanceId);
        request->set_method(methodId);
        
        // 设置负载
        auto requestPayload = runtime_->create_payload();
        requestPayload->set_data(payload);
        request->set_payload(requestPayload);
        
        // 重置响应状态
        {
            std::lock_guard<std::mutex> lock(mutex_);
            responseReceived_ = false;
            responseData_.clear();
        }
        
        // 发送请求
        application_->send(request);
        SecLogAdapter::facade().info("sec.client.request_sent",
            "Request sent",
            {slog::f_str("someip_method_id", hex_id(methodId))});
        
        // 等待响应（带超时）
        std::unique_lock<std::mutex> lock(mutex_);
        auto timeout = std::chrono::milliseconds(5000); // 5秒超时
        bool received = cv_.wait_for(lock, timeout, [this]() { return responseReceived_; });
        
        if (!received) {
            SecLogAdapter::facade().error("sec.client.request_timeout",
                "Request timeout",
                {slog::f_str("someip_method_id", hex_id(methodId))});
            return {};
        }
        
        return responseData_;
    }
}

} // namespace ccu_sec
