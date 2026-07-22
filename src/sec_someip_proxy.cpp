#include "sec_someip_proxy.h"
#include <iostream>
#include <stdexcept>

namespace cgw_sec {

SecSomeipProxy::SecSomeipProxy(const SomeipConfig& config) : config_(config) {
    client_ = std::make_unique<SecSomeipClient>(config);
}

SecSomeipProxy::~SecSomeipProxy() {
    deinitialize();
}

bool SecSomeipProxy::initialize() {
    if (!client_) {
        std::cerr << "[ERROR] SecSomeipProxy: Client not initialized" << std::endl;
        return false;
    }
    
    bool result = client_->initialize();
    if (result) {
        std::cout << "[INFO] SecSomeipProxy: Initialized successfully" << std::endl;
    } else {
        std::cerr << "[ERROR] SecSomeipProxy: Failed to initialize" << std::endl;
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
        std::cerr << "[ERROR] SecSomeipProxy: getSeed failed - not connected" << std::endl;
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->getSeed(level);
}

CgwSecErrorCode SecSomeipProxy::verifyKey(uint8_t level, uint32_t seedId,
                                            const std::vector<uint8_t>& key) {
    if (!client_ || !client_->isConnected()) {
        std::cerr << "[ERROR] SecSomeipProxy: verifyKey failed - not connected" << std::endl;
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->verifyKey(level, seedId, key);
}

OtaSessionResult SecSomeipProxy::deriveOtaSession(const OtaSessionContext& context,
                                                    uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        std::cerr << "[ERROR] SecSomeipProxy: deriveOtaSession failed - not connected" << std::endl;
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->deriveOtaSession(context, level);
}

KeyResult SecSomeipProxy::deriveByUid(const std::string& subKeyName,
                                       const std::vector<uint8_t>& context,
                                       uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        std::cerr << "[ERROR] SecSomeipProxy: deriveByUid failed - not connected" << std::endl;
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->deriveByUid(subKeyName, context, level);
}

SecureDataResult SecSomeipProxy::wrapByUid(const std::vector<uint8_t>& data,
                                            uint8_t level) {
    if (!client_ || !client_->isConnected()) {
        std::cerr << "[ERROR] SecSomeipProxy: wrapByUid failed - not connected" << std::endl;
        throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
    }
    
    return client_->wrapByUid(data, level);
}

} // namespace cgw_sec
