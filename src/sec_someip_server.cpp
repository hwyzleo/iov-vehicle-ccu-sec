#include "sec_someip_server.h"
#include "constants.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <nlohmann/json.hpp>

namespace ccu_sec {

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
    
    // 创建应用程序：生产进程只使用唯一的 ccu-sec application
    // （CCU-SEC-DSN-CR-005 §5.4），名称由统一配置提供，缺省回落常量。
    const std::string application_name =
        config_.applicationName.empty() ? std::string(SEC_APPLICATION_NAME)
                                        : config_.applicationName;
    application_ = runtime_->create_application(application_name);
    if (!application_) {
        throw std::runtime_error("Failed to create vsomeip application");
    }
    
    // 初始化应用程序
    application_->init();
    
    SecLogAdapter::facade().info("sec.service.app_initialized",
        "vsomeip application initialized");
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
    
    SecLogAdapter::facade().info("sec.service.handlers_registered",
        "Method handlers registered");
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
    SecLogAdapter::facade().info("sec.service.registered",
        "Service registered",
        {slog::f_str("someip_service_id", hex_id(config_.serviceId)),
         slog::f_str("someip_instance_id", hex_id(config_.instanceId))});
}

void SecSomeipServer::unregisterService() {
    if (application_) {
        application_->stop_offer_service(config_.serviceId, config_.instanceId);
        serviceAvailable_ = false;
        SecLogAdapter::facade().info("sec.service.unregistered",
            "Service unregistered");
    }
}

bool SecSomeipServer::start() {
    if (running_) {
        SecLogAdapter::facade().warn("sec.service.already_running",
            "Server already running");
        return true;
    }
    
    // 验证配置
    if (config_.serviceId == 0 || config_.instanceId == 0) {
        SecLogAdapter::facade().error("sec.service.config_invalid",
            "Invalid configuration: serviceId and instanceId must be non-zero",
            {slog::f_str("someip_service_id", hex_id(config_.serviceId)),
             slog::f_str("someip_instance_id", hex_id(config_.instanceId)),
             slog::f_str("error_code", "CCU-FW-0201")});
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
        
        SecLogAdapter::facade().info("sec.service.server_started",
            "SOME/IP server started",
            {slog::f_str("someip_service_id", hex_id(config_.serviceId)),
             slog::f_str("someip_instance_id", hex_id(config_.instanceId))});
        return true;
        
    } catch (const std::exception& e) {
        SecLogAdapter::facade().error("sec.service.start_failed",
            "Failed to start server",
            {slog::f_str("reason", e.what())});
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
    
    SecLogAdapter::facade().info("sec.service.server_stopped",
        "SOME/IP server stopped");
}

bool SecSomeipServer::isRunning() const {
    return running_;
}

bool SecSomeipServer::isServiceAvailable() const {
    return serviceAvailable_;
}

// ============================================================
// 方法处理函数实现
// 每个 handler 建立 ContextScope（CCU-SEC-DSN-CR-004 §上下文传播），
// 输出事件目录中的结构化事件（CCU-SEC-DSN-CR-004 §事件目录），
// 仅记录非密钥元数据（CCU-SEC-DSN-CR-004 §字段白名单与零泄露）。
// ============================================================

void SecSomeipServer::handleGetSeed(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    auto startTime = std::chrono::steady_clock::now();

    // 建立 SOME/IP 入站 ContextScope
    // （CCU-SEC-DSN-CR-004 §上下文传播 第1点：Provider 收到请求时建立 ContextScope）
    auto scope = make_someip_context_scope(
        generate_trace_id(), generate_request_id(),
        hex_id(config_.serviceId), hex_id(config_.getSeedMethodId),
        hex_id(static_cast<uint16_t>(request->get_client())));

    try {
        // 从请求中提取 level 参数
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            // sec.request.unauthorized: 调用方或安全会话未授权
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
                "Invalid getSeed request: missing level parameter",
                {slog::f_str("caller", "unknown"),
                 slog::f_str("operation", "getSeed"),
                 slog::f_str("result", "invalid_request"),
                 slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 调用业务逻辑（创建 SE/HSM 子作用域）
        SeedResult result;
        {
            auto seScope = make_se_child_scope("getSeed");
            result = service_->getSeed(level);
        }

        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeSeedResult(result));
        response->set_payload(responsePayload);
        
        if (result.error == CcuSecErrorCode::SUCCESS) {
            // sec.seed.generated: getSeed 成功
            // 仅记录非密钥元数据，不记录 seed 内容
            SecLogAdapter::seed_key().info(sec_events::SEED_GENERATED,
                "getSeed succeeded",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", hex_id(level)),
                 slog::f_str("operation", "getSeed"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_int("seed_id", static_cast<int64_t>(result.seedId))});
        } else {
            // sec.seed.generate.failed: seed 生成失败
            SecLogAdapter::seed_key().error(sec_events::SEED_GENERATE_FAILED,
                "getSeed failed",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", hex_id(level)),
                 slog::f_str("result", errorCodeToString(result.error)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_str("error_code", errorCodeToString(result.error))});
        }
        
    } catch (const std::exception& e) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        // sec.seed.generate.failed: seed 生成失败（异常）
        SecLogAdapter::seed_key().error(sec_events::SEED_GENERATE_FAILED,
            "getSeed failed",
            {slog::f_str("caller", "diag"),
             slog::f_str("result", "exception"),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::SEED_GENERATION_FAILED))});
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::SEED_GENERATION_FAILED));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleVerifyKey(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    auto startTime = std::chrono::steady_clock::now();

    auto scope = make_someip_context_scope(
        generate_trace_id(), generate_request_id(),
        hex_id(config_.serviceId), hex_id(config_.verifyKeyMethodId),
        hex_id(static_cast<uint16_t>(request->get_client())));

    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        // 验证请求长度: level(1) + seedId(4) + keyLength(4) + key(16)
        if (length < 9) {
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
                "Invalid verifyKey request: insufficient data",
                {slog::f_str("caller", "unknown"),
                 slog::f_str("operation", "verifyKey"),
                 slog::f_str("result", "invalid_request"),
                 slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        uint32_t seedId = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
        uint32_t keyLength = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
        
        if (length < 9 + keyLength) {
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
                "Invalid verifyKey request: key length mismatch",
                {slog::f_str("caller", "unknown"),
                 slog::f_str("operation", "verifyKey"),
                 slog::f_str("result", "invalid_request"),
                 slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        std::vector<uint8_t> key(data + 9, data + 9 + keyLength);
        
        // 调用业务逻辑（创建 SE/HSM 子作用域）
        CcuSecErrorCode result;
        {
            auto seScope = make_se_child_scope("verifyKey");
            result = service_->verifyKey(level, seedId, key);
        }

        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeErrorCode(result));
        response->set_payload(responsePayload);
        
        // sec.key.verify.succeeded/failed: verifyKey 完成
        // 仅记录非密钥元数据，不记录 key 内容
        if (result == CcuSecErrorCode::SUCCESS) {
            SecLogAdapter::seed_key().info(sec_events::KEY_VERIFY_SUCCEEDED,
                "verifyKey succeeded",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", hex_id(level)),
                 slog::f_str("operation", "verifyKey"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_int("seed_id", static_cast<int64_t>(seedId))});
        } else {
            SecLogAdapter::seed_key().warn(sec_events::KEY_VERIFY_FAILED,
                "verifyKey failed",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", hex_id(level)),
                 slog::f_str("operation", "verifyKey"),
                 slog::f_str("result", errorCodeToString(result)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_str("error_code", errorCodeToString(result))});
        }
        
    } catch (const std::exception& e) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        SecLogAdapter::seed_key().error(sec_events::KEY_VERIFY_FAILED,
            "verifyKey failed",
            {slog::f_str("caller", "diag"),
             slog::f_str("operation", "verifyKey"),
             slog::f_str("result", "exception"),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::KEY_VERIFICATION_FAILED))});
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::KEY_VERIFICATION_FAILED));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleDeriveOtaSession(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    auto startTime = std::chrono::steady_clock::now();

    auto scope = make_someip_context_scope(
        generate_trace_id(), generate_request_id(),
        hex_id(config_.serviceId), hex_id(config_.deriveOtaSessionMethodId),
        hex_id(static_cast<uint16_t>(request->get_client())));

    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
                "Invalid deriveOtaSession request: missing level parameter",
                {slog::f_str("caller", "unknown"),
                 slog::f_str("operation", "deriveOtaSession"),
                 slog::f_str("result", "invalid_request"),
                 slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 反序列化上下文
        std::vector<uint8_t> contextData(data + 1, data + length);
        auto context = deserializeOtaSessionContext(contextData);
        
        // 调用业务逻辑（创建 SE/HSM 子作用域）
        OtaSessionResult result;
        {
            auto seScope = make_se_child_scope("deriveOtaSession");
            result = service_->deriveOtaSession(context, level);
        }

        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeOtaSessionResult(result));
        response->set_payload(responsePayload);
        
        // sec.ota.session.derived/derive.failed: OTA 会话派生
        // 仅记录非密钥元数据，不记录 session_key、nonce 原值
        if (result.error == CcuSecErrorCode::SUCCESS) {
            SecLogAdapter::ota_session().info(sec_events::OTA_SESSION_DERIVED,
                "OTA session derived",
                {slog::f_str("caller", "fota"),
                 slog::f_str("operation", "deriveOtaSession"),
                 slog::f_str("direction", context.direction),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
        } else {
            SecLogAdapter::ota_session().error(sec_events::OTA_SESSION_DERIVE_FAILED,
                "OTA session derivation failed",
                {slog::f_str("caller", "fota"),
                 slog::f_str("operation", "deriveOtaSession"),
                 slog::f_str("direction", context.direction),
                 slog::f_str("result", errorCodeToString(result.error)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_str("error_code", errorCodeToString(result.error))});
        }
        
    } catch (const std::exception& e) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        SecLogAdapter::ota_session().error(sec_events::OTA_SESSION_DERIVE_FAILED,
            "OTA session derivation failed",
            {slog::f_str("caller", "fota"),
             slog::f_str("operation", "deriveOtaSession"),
             slog::f_str("result", "exception"),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED))});
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleDeriveByUid(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    auto startTime = std::chrono::steady_clock::now();

    auto scope = make_someip_context_scope(
        generate_trace_id(), generate_request_id(),
        hex_id(config_.serviceId), hex_id(config_.deriveByUidMethodId),
        hex_id(static_cast<uint16_t>(request->get_client())));

    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
                "Invalid deriveByUid request: missing level parameter",
                {slog::f_str("caller", "unknown"),
                 slog::f_str("operation", "deriveByUid"),
                 slog::f_str("result", "invalid_request"),
                 slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 反序列化请求
        std::vector<uint8_t> requestData(data + 1, data + length);
        auto [subKeyName, context] = deserializeKeyRequest(requestData);
        
        // 调用业务逻辑（创建 SE/HSM 子作用域）
        KeyResult result;
        {
            auto seScope = make_se_child_scope("deriveByUid");
            result = service_->deriveByUid(subKeyName, context, level);
        }

        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeKeyResult(result));
        response->set_payload(responsePayload);
        
        // sec.device.key.operation.failed: 设备根缺失或派生失败
        // 仅记录非密钥元数据，不记录 key 内容
        if (result.error == CcuSecErrorCode::SUCCESS) {
            SecLogAdapter::device_key().info("sec.device.key.derived",
                "deriveByUid succeeded",
                {slog::f_str("caller", "device"),
                 slog::f_str("operation", "deriveByUid"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
        } else {
            SecLogAdapter::device_key().error(sec_events::DEVICE_KEY_OPERATION_FAILED,
                "deriveByUid failed",
                {slog::f_str("caller", "device"),
                 slog::f_str("operation", "deriveByUid"),
                 slog::f_str("result", errorCodeToString(result.error)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_str("error_code", errorCodeToString(result.error))});
        }
        
    } catch (const std::exception& e) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        SecLogAdapter::device_key().error(sec_events::DEVICE_KEY_OPERATION_FAILED,
            "deriveByUid failed",
            {slog::f_str("caller", "device"),
             slog::f_str("operation", "deriveByUid"),
             slog::f_str("result", "exception"),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::DEVICE_ROOT_MISSING))});
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::DEVICE_ROOT_MISSING));
        response->set_payload(errorPayload);
    }
}

void SecSomeipServer::handleWrapByUid(
    const std::shared_ptr<someip::Message>& request,
    std::shared_ptr<someip::Message>& response) {
    
    auto startTime = std::chrono::steady_clock::now();

    auto scope = make_someip_context_scope(
        generate_trace_id(), generate_request_id(),
        hex_id(config_.serviceId), hex_id(config_.wrapByUidMethodId),
        hex_id(static_cast<uint16_t>(request->get_client())));

    try {
        auto payload = request->get_payload();
        auto data = payload->get_data();
        auto length = payload->get_length();
        
        if (length < 1) {
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
                "Invalid wrapByUid request: missing level parameter",
                {slog::f_str("caller", "unknown"),
                 slog::f_str("operation", "wrapByUid"),
                 slog::f_str("result", "invalid_request"),
                 slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::UNAUTHORIZED_REQUEST)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
            auto errorPayload = runtime_->create_payload();
            errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::UNAUTHORIZED_REQUEST));
            response->set_payload(errorPayload);
            return;
        }
        
        uint8_t level = data[0];
        
        // 反序列化请求
        std::vector<uint8_t> requestData(data + 1, data + length);
        auto [keyName, dataToWrap] = deserializeWrapRequest(requestData);
        
        // 调用业务逻辑（创建 SE/HSM 子作用域）
        SecureDataResult result;
        {
            auto seScope = make_se_child_scope("wrapByUid");
            result = service_->wrapByUid(dataToWrap, level);
        }

        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        
        // 序列化结果
        auto responsePayload = runtime_->create_payload();
        responsePayload->set_data(serializeSecureDataResult(result));
        response->set_payload(responsePayload);
        
        // 仅记录非密钥元数据，不记录 wrapped data 内容
        if (result.error == CcuSecErrorCode::SUCCESS) {
            SecLogAdapter::device_key().info("sec.device.key.wrapped",
                "wrapByUid succeeded",
                {slog::f_str("caller", "device"),
                 slog::f_str("operation", "wrapByUid"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms))});
        } else {
            SecLogAdapter::device_key().error(sec_events::DEVICE_KEY_OPERATION_FAILED,
                "wrapByUid failed",
                {slog::f_str("caller", "device"),
                 slog::f_str("operation", "wrapByUid"),
                 slog::f_str("result", errorCodeToString(result.error)),
                 slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
                 slog::f_str("error_code", errorCodeToString(result.error))});
        }
        
    } catch (const std::exception& e) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        SecLogAdapter::device_key().error(sec_events::DEVICE_KEY_OPERATION_FAILED,
            "wrapByUid failed",
            {slog::f_str("caller", "device"),
             slog::f_str("operation", "wrapByUid"),
             slog::f_str("result", "exception"),
             slog::f_int("duration_ms", static_cast<int64_t>(duration_ms)),
             slog::f_str("error_code", errorCodeToString(CcuSecErrorCode::DEVICE_ROOT_MISSING))});
        auto errorPayload = runtime_->create_payload();
        errorPayload->set_data(serializeErrorCode(CcuSecErrorCode::DEVICE_ROOT_MISSING));
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
    
    if (result.error == CcuSecErrorCode::SUCCESS) {
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
    
    if (result.error == CcuSecErrorCode::SUCCESS) {
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
    
    if (result.error == CcuSecErrorCode::SUCCESS) {
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
    
    if (result.error == CcuSecErrorCode::SUCCESS) {
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

std::vector<uint8_t> SecSomeipServer::serializeErrorCode(CcuSecErrorCode code) {
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
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    
    uint32_t errorCode = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    result.error = static_cast<CcuSecErrorCode>(errorCode);
    
    if (result.error == CcuSecErrorCode::SUCCESS && data.size() >= 12) {
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

} // namespace ccu_sec
