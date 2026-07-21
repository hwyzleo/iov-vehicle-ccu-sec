#pragma once

#include <string>
#include <cstdint>

namespace cgw_sec {

enum class CgwSecErrorCode : uint32_t {
    SUCCESS = 0,
    SEED_GENERATION_FAILED = 1001,
    KEY_VERIFICATION_FAILED = 1002,
    OTA_ROOT_MISSING = 1003,
    SESSION_KEY_DERIVATION_FAILED = 1004,
    DEVICE_ROOT_MISSING = 1005,
    SE_HSM_ACCESS_FAILED = 1006,
    UNAUTHORIZED_REQUEST = 1007
};

std::string errorCodeToString(CgwSecErrorCode code);
std::string errorCodeDescription(CgwSecErrorCode code);

} // namespace cgw_sec
