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

// Security parameters (CCU-SEC-DSN-CR-005 §5.1: sec.security)
struct SecConfig {
    uint8_t defaultSecurityLevel = 0;
    uint32_t seedExpirationMs = 0;
    uint32_t maxSeedPoolSize = 0;
};

// SOME/IP provider parameters (CCU-SEC-DSN-CR-005 §5.1: sec.someip).
// Service/Instance/Method IDs and endpoint stay anchored to the SOME/IP
// Service Registry (SSOT); the unified config never re-assigns them.
struct SomeipConfig {
    std::string applicationName;
    uint16_t serviceId = 0;
    uint16_t instanceId = 0;
    uint16_t getSeedMethodId = 0;
    uint16_t verifyKeyMethodId = 0;
    uint16_t deriveOtaSessionMethodId = 0;
    uint16_t deriveByUidMethodId = 0;
    uint16_t wrapByUidMethodId = 0;
    uint16_t endpointPort = 0;
    std::string endpointProtocol;
    std::string endpointUnicast;
    bool serviceDiscoveryEnabled = false;
    std::string serviceDiscoveryMode;
    std::string serviceDiscoveryMulticastAddress;
    uint16_t serviceDiscoveryPort = 0;
};

// SE/HSM adapter selection (CCU-SEC-DSN-CR-005 §5.1/§5.2: sec.se_hsm).
// Only non-secret adapter parameters are carried by the release config;
// logical roots (OTA_VEHICLE_ROOT / CCU_DEVICE_ROOT / DIAG_SEEDKEY_SECRET)
// are resolved through the adapter by keyName, never through this file.
struct SeHsmConfig {
    std::string type;
    std::map<std::string, std::string> adapter;
};

} // namespace ccu_sec
