#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>
#include "error_codes.h"

namespace ccu_sec {

struct SeedResult {
    uint32_t seedId = 0;
    std::vector<uint8_t> seed;
    CcuSecErrorCode error = CcuSecErrorCode::SUCCESS;
};

struct SeedInfo {
    uint32_t seedId = 0;
    std::vector<uint8_t> seed;
    uint8_t level = 0;
    std::chrono::steady_clock::time_point createTime;
    bool consumed = false;
};

struct OtaSessionContext {
    std::string campaignId;
    std::string vin;
    std::string direction;
    std::vector<uint8_t> nonce;
    uint64_t timestamp = 0;
};

struct OtaSessionResult {
    uint32_t sessionKeyHandle = 0;
    std::vector<uint8_t> nonce;
    CcuSecErrorCode error = CcuSecErrorCode::SUCCESS;
};

struct SecConfig {
    std::string seHsmType;
    uint8_t defaultSecurityLevel = 0;
    uint32_t seedExpirationMs = 0;
    uint32_t maxSeedPoolSize = 0;
};

struct SomeipConfig {
    uint16_t serviceId = 0;
    uint16_t instanceId = 0;
    uint16_t getSeedMethodId = 0;
    uint16_t verifyKeyMethodId = 0;
    uint16_t deriveOtaSessionMethodId = 0;
    uint16_t deriveByUidMethodId = 0;
    uint16_t wrapByUidMethodId = 0;
};

struct SeHsmConfig {
    std::string type;
    std::string storagePath;
    std::map<std::string, std::string> keyFiles;
};

} // namespace ccu_sec
