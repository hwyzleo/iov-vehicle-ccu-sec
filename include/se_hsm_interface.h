#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "error_codes.h"
#include "data_models.h"

namespace cgw_sec {

struct KeyResult {
    std::vector<uint8_t> key;
    CgwSecErrorCode error = CgwSecErrorCode::SUCCESS;
};

struct SecureDataResult {
    std::vector<uint8_t> data;
    CgwSecErrorCode error = CgwSecErrorCode::SUCCESS;
};

class SeHsmInterface {
public:
    virtual ~SeHsmInterface() = default;

    virtual SeedResult generateSeed(uint8_t level) = 0;

    virtual CgwSecErrorCode verifyKey(uint8_t level, uint32_t seedId,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& expectedSeed) = 0;

    virtual KeyResult deriveKey(const std::string& rootKeyName,
                                const std::vector<uint8_t>& context) = 0;

    virtual CgwSecErrorCode storeKey(const std::string& keyName,
                                      const std::vector<uint8_t>& keyMaterial) = 0;

    virtual KeyResult loadKey(const std::string& keyName) = 0;

    virtual bool hasKey(const std::string& keyName) = 0;

    virtual CgwSecErrorCode secureStore(const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& data) = 0;

    virtual SecureDataResult secureLoad(const std::vector<uint8_t>& key) = 0;
};

} // namespace cgw_sec
