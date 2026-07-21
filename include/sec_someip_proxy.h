#pragma once

#include "data_models.h"
#include "se_hsm_interface.h"
#include <string>

namespace cgw_sec {

class SecSomeipProxy {
public:
    explicit SecSomeipProxy(const SomeipConfig& config);
    ~SecSomeipProxy() = default;

    SeedResult getSeed(uint8_t level);
    CgwSecErrorCode verifyKey(uint8_t level, uint32_t seedId, const std::vector<uint8_t>& key);
    OtaSessionResult deriveOtaSession(const OtaSessionContext& context, uint8_t level);
    KeyResult deriveByUid(const std::string& subKeyName, const std::vector<uint8_t>& context, uint8_t level);
    SecureDataResult wrapByUid(const std::vector<uint8_t>& data, uint8_t level);

private:
    SomeipConfig config_;
};

} // namespace cgw_sec
