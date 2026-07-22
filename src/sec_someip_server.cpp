#include "sec_someip_server.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace cgw_sec {

SecSomeipServer::SecSomeipServer(std::shared_ptr<SecSomeipService> service,
                                 const SomeipConfig& config)
    : service_(service), config_(config) {
    initializeApplication();
}

SecSomeipServer::~SecSomeipServer() {
    stop();
}

void SecSomeipServer::initializeApplication() {
    // 获取 vsomeip runtime
    runtime_ = someip::Runtime::get();
    if (!runtime_) {
        throw std::runtime_error("Failed to get vsomeip runtime");
    }
    
    // 创建应用程序
    application_ = runtime_->create_application("cgw-sec");
    if (!application_) {
        throw std::runtime_error("Failed to create vsomeip application");
    }
    
    // 初始化应用程序
    application_->init();
    
    logInfo("vsomeip application initialized");
}

void SecSomeipServer::registerMethodHandlers() {
    // 注册 getSeed 方法处理器
    methodHandlers_[config_.getSeedMethodId] = 
        [this](const std::shared_ptr<someip::Message>& req,
               std::shared_ptr<someip::Message>& resp) {
            handleGetSeed(req, resp);
        };
    
    // 注册 verifyKey 方法处理器
    methodHandlers_[config_.verifyKeyMethodId] = 
        [this](const std::shared_ptr<someip::Message>& req,
               std::shared_ptr<someip::Message>& resp) {
            handleVerifyKey(req, resp);
        };
    
    // 注册 deriveOtaSession 方法处理器
    methodHandlers_[config_.deriveOtaSessionMethodId] = 
        [this](const std::shared_ptr<someip::Message>& req,
               std::shared_ptr<someip::Message>& resp) {
            handleDeriveOtaSession(req, resp);
        };
    
    // 注册 deriveByUid 方法处理器
    methodHandlers_[config_.deriveByUidMethodId] = 
        [this](const std::shared_ptr<someip::Message>& req,
               std::shared_ptr<someip::Message>& resp) {
            handleDeriveByUid(req, resp);
        };
    
    // 注册 wrapByUid 方法处理器
    methodHandlers_[config_.wrapByUidMethodId] = 
        [this](const std::shared_ptr<someip::Message>& req,
               std::shared_ptr<someip::Message>& resp) {
            handleWrapByUid(req, resp);
        };
    
    logInfo("Method handlers registered");
}

void SecSomeipServer::registerService() {
    // 注册服务
    application_->offer_service(config_.serviceId, config_.instanceId);
    
    // 注册方法处理器
    for (const auto& pair : methodHandlers_) {
        auto methodId = pair.first;
        auto handler = pair.second;
        application_->offer_method(config_.serviceId, config_.instanceId, methodId);
        application_->register_message_handler(
            config_.serviceId, config_.instanceId, methodId,
            [this, handler](const std::shared_ptr<someip::Message>& request) {
                auto response = runtime_->create_response(request);
                handler(request, response);
                application_->send(response);
            });
    }
    
    serviceAvailable_ = true;
    {
        std::ostringstream oss;
        oss << "Service registered: serviceId=0x" << std::hex << config_.serviceId
            << ", instanceId=0x" << std::hex << config_.instanceId;
        logInfo(oss.str());
    }
}

void SecSomeipServer::unregisterService() {
    if (application_) {
        application_->stop_offer_service(config_.serviceId, config_.instanceId);
        serviceAvailable_ = false;
        logInfo("Service unregistered");
    }
}

bool SecSomeipServer::start() {
    if (running_) {
        logWarning("Server already running");
        return true;
    }
    
    // 验证配置
    if (config_.serviceId == 0 || config_.instanceId == 0) {
        logError("Invalid configuration: serviceId and instanceId must be non-zero");
        return false;
    }
    
    try {
        // 注册方法处理器
        registerMethodHandlers();
        
        // 注册服务
        registerService();
        
        // 启动应用程序（在单独线程中运行事件循环）
        running_ = true;
        routingThread_ = std::thread([this]() {
            application_->start();
        });
        
        {
            std::ostringstream oss;
            oss << "SOME/IP server started: serviceId=0x" << std::hex << config_.serviceId
                << ", instanceId=0x" << std::hex << config_.instanceId;
            logInfo(oss.str());
        }
        return true;
        
    } catch (const std::exception& e) {
        logError("Failed to start server: " + std::string(e.what()));
        running_ = false;
        return false;
    }
}

void SecSomeipServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // 注销服务
    unregisterService();
    
    // 停止应用程序
    if (application_) {
        application_->stop();
    }
    
    // 等待路由线程结束
    if (routingThread_.joinable()) {
        routingThread_.join();
    }
    
    logInfo("SOME/IP server stopped");
}

bool SecSomeipServer::isRunning() const {
    return running_;
}

bool SecSomeipServer::isServiceAvailable() const {
    return serviceAvailable_;
}

// 方法处理函数实现
void SecSomeipServer::handleGetSeed(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    try {
        // 从请求中提取 level 参数
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            logError("Invalid getSeed request: missing level parameter");
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 调用业务逻辑
        auto result = service_->getSeed(level);
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeSeedResult(result));
        response->set_payload(responsePayload);
        
        logInfo("getSeed completed: level=" + std::to_string(level) + 
                ", seedId=" + std::to_string(result.seedId));
        
    } catch (const std::exception& e) {
        logError("getSeed failed: " + std::string(e.what()));
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::SEED_GENERATION_FAILED));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleVerifyKey(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        // 验证请求长度: level(1) + seedId(4) + keyLength(4) + key(16)
        if (length < 9) {
            logError("Invalid verifyKey request: insufficient data");
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        uint32_t seedId = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
        uint32_t keyLength = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
        
        if (length < 9 + keyLength) {
            logError("Invalid verifyKey request: key length mismatch");
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        std::vector<uint8_t> key(data + 9, data + 9 + keyLength);
        
        // 调用业务逻辑
        auto result = service_->verifyKey(level, seedId, key);
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeErrorCode(result));
        response->set_payload(responsePayload);
        
        logInfo("verifyKey completed: level=" + std::to_string(level) + 
                ", seedId=" + std::to_string(seedId) + 
                ", result=" + (result == CgwSecErrorCode::SUCCESS ? "SUCCESS" : "FAILED"));
        
    } catch (const std::exception& e) {
        logError("verifyKey failed: " + std::string(e.what()));
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::KEY_VERIFICATION_FAILED));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleDeriveOtaSession(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            logError("Invalid deriveOtaSession request: missing level parameter");
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 反序列化上下文
        std::vector<uint8_t> contextData(data + 1, data + length);
        auto context = deserializeOtaSessionContext(contextData);
        
        // 调用业务逻辑
        auto result = service_->deriveOtaSession(context, level);
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeOtaSessionResult(result));
        response->set_payload(responsePayload);
        
        logInfo("deriveOtaSession completed: campaignId=" + context.campaignId);
        
    } catch (const std::exception& e) {
        logError("deriveOtaSession failed: " + std::string(e.what()));
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleDeriveByUid(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            logError("Invalid deriveByUid request: missing level parameter");
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 反序列化请求
        std::vector<uint8_t> requestData(data + 1, data + length);
        auto [subKeyName, context] = deserializeKeyRequest(requestData);
        
        // 调用业务逻辑
        auto result = service_->deriveByUid(subKeyName, context, level);
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeKeyResult(result));
        response->set_payload(responsePayload);
        
        logInfo("deriveByUid completed: subKeyName=" + subKeyName);
        
    } catch (const std::exception& e) {
        logError("deriveByUid failed: " + std::string(e.what()));
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::DEVICE_ROOT_MISSING));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleWrapByUid(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            logError("Invalid wrapByUid request: missing level parameter");
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 反序列化请求
        std::vector<uint8_t> requestData(data + 1, data + length);
        auto [keyName, dataToWrap] = deserializeWrapRequest(requestData);
        
        // 调用业务逻辑
        auto result = service_->wrapByUid(dataToWrap, level);
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeSecureDataResult(result));
        response->set_payload(responsePayload);
        
        logInfo("wrapByUid completed");
        
    } catch (const std::exception& e) {
        logError("wrapByUid failed: " + std::string(e.what()));
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CgwSecErrorCode::DEVICE_ROOT_MISSING));
        response->set_payload(errorPayload);
    }
}

// 序列化函数实现
std::vector<uint8_t> SecSomeipServer::serializeSeedResult(const SeedResult& result) {
    std::vector<uint8_t> data;
    
    // 错误码 (4 bytes)
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(static_cast<uint32_t>(result.error) & 0xFF));
    
    if (result.error == CgwSecErrorCode::SUCCESS) {
        // seedId (4 bytes)
        data.push_back(static_cast<uint8_t>((result.seedId >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((result.seedId >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((result.seedId >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(result.seedId & 0xFF));
        
        // seed 长度 (4 bytes)
        uint32_t seedLength = result.seed.size();
        data.push_back(static_cast<uint8_t>((seedLength >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((seedLength >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((seedLength >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(seedLength & 0xFF));
        
        // seed 数据
        data.insert(data.end(), result.seed.begin(), result.seed.end());
    }
    
    return data;
}

std::vector<uint8_t> SecSomeipServer::serializeOtaSessionResult(const OtaSessionResult& result) {
    std::vector<uint8_t> data;
    
    // 错误码 (4 bytes)
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(static_cast<uint32_t>(result.error) & 0xFF));
    
    if (result.error == CgwSecErrorCode::SUCCESS) {
        // sessionKeyHandle (4 bytes)
        data.push_back(static_cast<uint8_t>((result.sessionKeyHandle >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((result.sessionKeyHandle >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((result.sessionKeyHandle >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(result.sessionKeyHandle & 0xFF));
        
        // nonce 长度 (4 bytes)
        uint32_t nonceLength = result.nonce.size();
        data.push_back(static_cast<uint8_t>((nonceLength >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((nonceLength >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((nonceLength >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(nonceLength & 0xFF));
        
        // nonce 数据
        data.insert(data.end(), result.nonce.begin(), result.nonce.end());
    }
    
    return data;
}

std::vector<uint8_t> SecSomeipServer::serializeKeyResult(const KeyResult& result) {
    std::vector<uint8_t> data;
    
    // 错误码 (4 bytes)
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(static_cast<uint32_t>(result.error) & 0xFF));
    
    if (result.error == CgwSecErrorCode::SUCCESS) {
        // key 长度 (4 bytes)
        uint32_t keyLength = result.key.size();
        data.push_back(static_cast<uint8_t>((keyLength >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((keyLength >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((keyLength >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(keyLength & 0xFF));
        
        // key 数据
        data.insert(data.end(), result.key.begin(), result.key.end());
    }
    
    return data;
}

std::vector<uint8_t> SecSomeipServer::serializeSecureDataResult(const SecureDataResult& result) {
    std::vector<uint8_t> data;
    
    // 错误码 (4 bytes)
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(result.error) >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(static_cast<uint32_t>(result.error) & 0xFF));
    
    if (result.error == CgwSecErrorCode::SUCCESS) {
        // data 长度 (4 bytes)
        uint32_t dataLength = result.data.size();
        data.push_back(static_cast<uint8_t>((dataLength >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((dataLength >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((dataLength >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(dataLength & 0xFF));
        
        // data 数据
        data.insert(data.end(), result.data.begin(), result.data.end());
    }
    
    return data;
}

std::vector<uint8_t> SecSomeipServer::serializeErrorCode(CgwSecErrorCode code) {
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(code) >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(code) >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((static_cast<uint32_t>(code) >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(static_cast<uint32_t>(code) & 0xFF));
    return data;
}

// 反序列化函数实现
SeedResult SecSomeipServer::deserializeSeedResult(const std::vector<uint8_t>& data) {
    SeedResult result;
    if (data.size() < 4) {
        result.error = CgwSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    
    uint32_t errorCode = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    result.error = static_cast<CgwSecErrorCode>(errorCode);
    
    if (result.error == CgwSecErrorCode::SUCCESS && data.size() >= 12) {
        result.seedId = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        uint32_t seedLength = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
        
        if (data.size() >= 12 + seedLength) {
            result.seed.assign(data.begin() + 12, data.begin() + 12 + seedLength);
        }
    }
    
    return result;
}

OtaSessionContext SecSomeipServer::deserializeOtaSessionContext(const std::vector<uint8_t>& data) {
    OtaSessionContext context;
    
    if (data.size() < 4) {
        return context;
    }
    
    size_t offset = 0;
    
    // campaignId 长度 (4 bytes)
    uint32_t campaignIdLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                                (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + campaignIdLength) {
        return context;
    }
    
    // campaignId
    context.campaignId.assign(data.begin() + offset, data.begin() + offset + campaignIdLength);
    offset += campaignIdLength;
    
    // vin 长度 (4 bytes)
    if (data.size() < offset + 4) {
        return context;
    }
    uint32_t vinLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                         (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + vinLength) {
        return context;
    }
    
    // vin
    context.vin.assign(data.begin() + offset, data.begin() + offset + vinLength);
    offset += vinLength;
    
    // direction 长度 (4 bytes)
    if (data.size() < offset + 4) {
        return context;
    }
    uint32_t directionLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                               (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + directionLength) {
        return context;
    }
    
    // direction
    context.direction.assign(data.begin() + offset, data.begin() + offset + directionLength);
    offset += directionLength;
    
    // nonce 长度 (4 bytes)
    if (data.size() < offset + 4) {
        return context;
    }
    uint32_t nonceLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                           (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + nonceLength) {
        return context;
    }
    
    // nonce
    context.nonce.assign(data.begin() + offset, data.begin() + offset + nonceLength);
    offset += nonceLength;
    
    // timestamp (8 bytes)
    if (data.size() < offset + 8) {
        return context;
    }
    context.timestamp = 0;
    for (int i = 0; i < 8; i++) {
        context.timestamp = (context.timestamp << 8) | data[offset + i];
    }
    
    return context;
}

std::pair<std::string, std::vector<uint8_t>> SecSomeipServer::deserializeKeyRequest(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 4) {
        return {"", {}};
    }
    
    size_t offset = 0;
    
    // subKeyName 长度 (4 bytes)
    uint32_t nameLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                          (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + nameLength) {
        return {"", {}};
    }
    
    // subKeyName
    std::string subKeyName(data.begin() + offset, data.begin() + offset + nameLength);
    offset += nameLength;
    
    // context 长度 (4 bytes)
    if (data.size() < offset + 4) {
        return {subKeyName, {}};
    }
    uint32_t contextLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                             (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + contextLength) {
        return {subKeyName, {}};
    }
    
    // context
    std::vector<uint8_t> context(data.begin() + offset, data.begin() + offset + contextLength);
    
    return {subKeyName, context};
}

std::pair<std::string, std::vector<uint8_t>> SecSomeipServer::deserializeWrapRequest(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 4) {
        return {"", {}};
    }
    
    size_t offset = 0;
    
    // keyName 长度 (4 bytes)
    uint32_t nameLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                          (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + nameLength) {
        return {"", {}};
    }
    
    // keyName
    std::string keyName(data.begin() + offset, data.begin() + offset + nameLength);
    offset += nameLength;
    
    // data 长度 (4 bytes)
    if (data.size() < offset + 4) {
        return {keyName, {}};
    }
    uint32_t dataLength = (data[offset] << 24) | (data[offset + 1] << 16) | 
                          (data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    
    if (data.size() < offset + dataLength) {
        return {keyName, {}};
    }
    
    // data
    std::vector<uint8_t> dataToWrap(data.begin() + offset, data.begin() + offset + dataLength);
    
    return {keyName, dataToWrap};
}

// 日志函数实现
void SecSomeipServer::logInfo(const std::string& message) {
    std::cout << "[INFO] SecSomeipServer: " << message << std::endl;
}

void SecSomeipServer::logError(const std::string& message) {
    std::cerr << "[ERROR] SecSomeipServer: " << message << std::endl;
}

void SecSomeipServer::logWarning(const std::string& message) {
    std::cout << "[WARN] SecSomeipServer: " << message << std::endl;
}

} // namespace cgw_sec
