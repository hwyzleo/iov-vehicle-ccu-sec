#include "sec_someip_service.h"
#include "se_hsm_factory.h"
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include "constants.h"
#include <vector>
#include <chrono>
#include <stdexcept>
#include <string>

namespace ccu_sec {

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
        "CCU-SEC SOME/IP service started");
}

void SecSomeipService::stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    SecLogAdapter::facade().info("sec.service.stopped_serving",
        "CCU-SEC SOME/IP service stopped");
}

SeedResult SecSomeipService::getSeed(uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "get_seed");
    if (permResult != CcuSecErrorCode::SUCCESS) {
        SeedResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return seedKeyManager_->generateSeed(level);
}

CcuSecErrorCode SecSomeipService::verifyKey(uint8_t level, uint32_t seedId,
                                             const std::vector<uint8_t>& key) {
    auto permResult = securityGuard_->verifyPermission(level, "verify_key");
    if (permResult != CcuSecErrorCode::SUCCESS) {
        return CcuSecErrorCode::UNAUTHORIZED_REQUEST;
    }
    return seedKeyManager_->verifyKey(level, seedId, key);
}

OtaSessionResult SecSomeipService::deriveOtaSession(const OtaSessionContext& context,
                                                      uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "derive_ota_session");
    if (permResult != CcuSecErrorCode::SUCCESS) {
        OtaSessionResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return otaSessionManager_->deriveSessionKey(context);
}

KeyResult SecSomeipService::deriveByUid(const std::string& subKeyName,
                                         const std::vector<uint8_t>& context,
                                         uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "derive_by_uid");
    if (permResult != CcuSecErrorCode::SUCCESS) {
        KeyResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return deviceRootManager_->deriveSubKey(subKeyName, context);
}

SecureDataResult SecSomeipService::wrapByUid(const std::vector<uint8_t>& data,
                                              uint8_t level) {
    auto permResult = securityGuard_->verifyPermission(level, "wrap_by_uid");
    if (permResult != CcuSecErrorCode::SUCCESS) {
        SecureDataResult result;
        result.error = CcuSecErrorCode::UNAUTHORIZED_REQUEST;
        return result;
    }
    return deviceRootManager_->wrapData(data);
}

void SecSomeipService::initialize() {
    // CCU-SEC-DSN-CR-005 §5.2/§8.2: create the approved adapter before
    // declaring ready. Never synthesize key material from configuration.
    seHsm_ = SeHsmFactory::create(seHsmConfig_);
    if (!seHsm_) {
        SecLogAdapter::se_adapter().error(sec_events::SE_ACCESS_FAILED,
            "SE/HSM adapter unavailable; refusing to open security provider",
            {slog::f_str("se_hsm_type", seHsmConfig_.type),
             slog::f_str("error_code", "CCU-SEC-1006")});
        throw std::runtime_error(
            "CCU-SEC: SE/HSM adapter unavailable (CCU-SEC-1006), fail-closed");
    }

    if (seHsmConfig_.type == "software") {
        // Explicit NON_PRODUCTION fixture (software HSM + dev config only).
        // It must never report security capability as healthy.
        securityReady_ = false;
        SecLogAdapter::se_adapter().warn(sec_events::SECURITY_NOT_READY,
            "Non-production software SE/HSM fixture active; security capability not ready",
            {slog::f_str("se_hsm_type", seHsmConfig_.type),
             slog::f_str("result", "non_production"),
             slog::f_bool("security_ready", securityReady_)});
    } else {
        // Approved adapter: required logical roots must already be
        // provisioned by the provisioning flow (CCU-SEC-BUILD-REQ-005).
        // Missing roots keep the existing fail-closed error codes.
        struct RootRequirement {
            const char* key_name;
            CcuSecErrorCode error_code;
        };
        const RootRequirement required_roots[] = {
            {OTA_VEHICLE_ROOT_KEY_NAME, CcuSecErrorCode::OTA_ROOT_MISSING},
            {CCU_DEVICE_ROOT_KEY_NAME, CcuSecErrorCode::DEVICE_ROOT_MISSING},
            {DIAG_SEEDKEY_SECRET_NAME, CcuSecErrorCode::SE_HSM_ACCESS_FAILED},
        };
        for (const RootRequirement& root : required_roots) {
            if (!seHsm_->hasKey(root.key_name)) {
                SecLogAdapter::root_store().error(sec_events::SECURITY_NOT_READY,
                    "Required logical root is not provisioned; refusing to open security provider",
                    {slog::f_str("key_name", root.key_name),
                     slog::f_str("se_hsm_type", seHsmConfig_.type),
                     slog::f_str("error_code", errorCodeToString(root.error_code)),
                     slog::f_bool("security_ready", false)});
                throw std::runtime_error(
                    "CCU-SEC: required logical root missing (" +
                    errorCodeToString(root.error_code) + "), fail-closed");
            }
        }
        securityReady_ = true;
        SecLogAdapter::se_adapter().info(sec_events::SERVICE_INITIALIZED,
            "Approved SE/HSM adapter ready with provisioned logical roots",
            {slog::f_str("se_hsm_type", seHsmConfig_.type),
             slog::f_bool("security_ready", securityReady_)});
    }

    seedKeyManager_ = std::make_unique<SeedKeyManager>(seHsm_);
    otaSessionManager_ = std::make_unique<OtaSessionManager>(seHsm_);
    deviceRootManager_ = std::make_unique<DeviceRootManager>(seHsm_);
    securityGuard_ = std::make_unique<SecurityGuard>(seHsm_);
}

#ifdef CCU_SEC_ENABLE_SOFTWARE_HSM
CcuSecErrorCode SecSomeipService::provisionTestKey(
    const std::string& keyName, const std::vector<uint8_t>& keyMaterial) {
    // NON_PRODUCTION test fixture entry: tests inject logical roots
    // explicitly instead of relying on production initialization.
    if (!seHsm_) {
        return CcuSecErrorCode::SE_HSM_ACCESS_FAILED;
    }
    return seHsm_->storeKey(keyName, keyMaterial);
}
#endif

} // namespace ccu_sec