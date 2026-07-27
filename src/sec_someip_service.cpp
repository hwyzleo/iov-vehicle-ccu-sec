#include "sec_someip_service.h"
#include "se_hsm_factory.h"
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include "constants.h"
#include <vector>
#include <chrono>

namespace cgw_sec {

SecSomeipService::SecSomeipService(const SecConfig& secConfig,
                                   const SomeipConfig& someipConfig,
                                   const SeHsmConfig& seHsmConfig)
    : secConfig_(secConfig), someipConfig_(someipConfig), seHsmConfig_(seHsmConfig),
      running_(false) {
    initialize();
}

void SecSomeipService::start() {
    if (running_) {
        return;
    }
    running_ = true;
    SecLogAdapter::facade().info("sec.service.serving",
        "CGW-SEC SOME/IP service started");
}

void SecSomeipService::stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    SecLogAdapter::facade().info("sec.service.stopped_serving",
        "CGW-SEC SOME/IP service stopped");
}

SeedResult SecSomeipService::getSeed(uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "get_seed");
    if (permResult != CgwSecErrorCode::SUCCESS) {
        SeedResult result;
        result.error = CgwSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return seedKeyManager_->generateSeed(level);
}

CgwSecErrorCode SecSomeipService::verifyKey(uint8_t level, uint32_t seedId,
                                             const std::vector<uint8_t>& key) {
    auto permResult = securityGuard_->verifyPermission(level, "verify_key");
    if (permResult != CgwSecErrorCode::SUCCESS) {
        return CgwSecErrorCode::UNAUTHORIZED_REQUEST;
    }
    return seedKeyManager_->verifyKey(level, seedId, key);
}

OtaSessionResult SecSomeipService::deriveOtaSession(const OtaSessionContext& context,
                                                      uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "derive_ota_session");
    if (permResult != CgwSecErrorCode::SUCCESS) {
        OtaSessionResult result;
        result.error = CgwSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return otaSessionManager_->deriveSessionKey(context);
}

KeyResult SecSomeipService::deriveByUid(const std::string& subKeyName,
                                         const std::vector<uint8_t>& context,
                                         uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "derive_by_uid");
    if (permResult != CgwSecErrorCode::SUCCESS) {
        KeyResult result;
        result.error = CgwSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return deviceRootManager_->deriveSubKey(subKeyName, context);
}

SecureDataResult SecSomeipService::wrapByUid(const std::vector<uint8_t>& data,
                                              uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "wrap_by_uid");
    if (permResult != CgwSecErrorCode::SUCCESS) {
        SecureDataResult result;
        result.error = CgwSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return deviceRootManager_->wrapData(data);
}

void SecSomeipService::initialize() {
    seHsm_ = SeHsmFactory::create(seHsmConfig_);

    for (const auto& [keyName, keyFile] : seHsmConfig_.keyFiles) {
        std::vector<uint8_t> keyMaterial(32, 0x42);
        seHsm_->storeKey(keyName, keyMaterial);
    }

    seedKeyManager_ = std::make_unique<SeedKeyManager>(seHsm_);
    otaSessionManager_ = std::make_unique<OtaSessionManager>(seHsm_);
    deviceRootManager_ = std::make_unique<DeviceRootManager>(seHsm_);
    securityGuard_ = std::make_unique<SecurityGuard>(seHsm_);
}

} // namespace cgw_sec