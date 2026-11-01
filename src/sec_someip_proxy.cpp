#include "sec_someip_proxy.h"
#include "sec_log_adapter.h"
#include <stdexcept>

namespace ccu_sec {

SecSomeipProxy::SecSomeipProxy(const SomeipConfig& config) : config_(config) {
    client_ = std::make_unique<SecSomeipClient>(config);
}

SecSomeipProxy::~SecSomeipProxy() {
    deinitialize();
}

bool SecSomeipProxy::initialize() {
    if (!client_) {
        SecLogAdapter::facade().error("sec.proxy.client_not_initialized",
            "Client not initialized");
        return false;
    }
    
    bool result = client_->initialize();
    if (result) {
        SecLogAdapter::facade().info("sec.proxy.initialized",
            "Initialized successfully");
    } else {
        SecLogAdapter::facade().error("sec.proxy.init_failed",
            "Failed to initialize");
    }
    
    return result;
}

void SecSomeipProxy::deinitialize() {
    if (client_) {
        client_->deinitialize();
    }
}

bool SecSomeipProxy::isConnected() const {
    return client_ ? client_->isConnected() : false;
}

SeedResult SecSomeipProxy::getSeed(uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        SecLogAdapter::facade().error("sec.proxy.not_connected",
            "getSeed failed - not connected",
            {slog::f_str("operation", "getSeed")});
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->getSeed(level);
}

CcuSecErrorCode SecSomeipProxy::verifyKey(uint8_t level, uint32_t seedId,
                                            const std::vector<uint8_t>& key) {
    if (!client_ || !client_->isConnected()) {
        SecLogAdapter::facade().error("sec.proxy.not_connected",
            "verifyKey failed - not connected",
            {slog::f_str("operation", "verifyKey")});
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->verifyKey(level, seedId, key);
}

OtaSessionResult SecSomeipProxy::deriveOtaSession(const OtaSessionContext& context,
                                                    uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        SecLogAdapter::facade().error("sec.proxy.not_connected",
            "deriveOtaSession failed - not connected",
            {slog::f_str("operation", "deriveOtaSession")});
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->deriveOtaSession(context, level);
}

KeyResult SecSomeipProxy::deriveByUid(const std::string& subKeyName,
                                       const std::vector<uint8_t>& context,
                                       uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        SecLogAdapter::facade().error("sec.proxy.not_connected",
            "deriveByUid failed - not connected",
            {slog::f_str("operation", "deriveByUid")});
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->deriveByUid(subKeyName, context, level);
}

SecureDataResult SecSomeipProxy::wrapByUid(const std::vector<uint8_t>& data,
                                            uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        SecLogAdapter::facade().error("sec.proxy.not_connected",
            "wrapByUid failed - not connected",
            {slog::f_str("operation", "wrapByUid")});
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->wrapByUid(data, level);
}

} // namespace ccu_sec
