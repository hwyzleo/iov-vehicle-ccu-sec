#pragma once

#include "data_models.h"
#include "se_hsm_interface.h"
#include "seed_key_manager.h"
#include "ota_session_manager.h"
#include "device_root_manager.h"
#include "security_guard.h"
#include <memory>

namespace ccu_sec {

class SecSomeipService {
public:
    SecSomeipService(const SecConfig& secConfig, const SomeipConfig& someipConfig, const SeHsmConfig& seHsmConfig);
    ~SecSomeipService() = default;

    void start();
    void stop();

    SeedResult getSeed(uint8_t level);
    CcuSecErrorCode verifyKey(uint8_t level, uint32_t seedId, const std::vector<uint8_t>& key);
    OtaSessionResult deriveOtaSession(const OtaSessionContext& context, uint8_t level);
    KeyResult deriveByUid(const std::string& subKeyName, const std::vector<uint8_t>& context, uint8_t level);
    SecureDataResult wrapByUid(const std::vector<uint8_t>& data, uint8_t level);

private:
    SecConfig secConfig_;
    SomeipConfig someipConfig_;
    SeHsmConfig seHsmConfig_;

    std::shared_ptr<SeHsmInterface> seHsm_;
    std::unique_ptr<SeedKeyManager> seedKeyManager_;
    std::unique_ptr<OtaSessionManager> otaSessionManager_;
    std::unique_ptr<DeviceRootManager> deviceRootManager_;
    std::unique_ptr<SecurityGuard> securityGuard_;

    bool running_;

    void initialize();
};

} // namespace ccu_sec
