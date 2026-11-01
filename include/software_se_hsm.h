#pragma once

#include "se_hsm_interface.h"
#include <map>
#include <mutex>
#include <chrono>

namespace ccu_sec {

class SoftwareSeHsm : public SeHsmInterface {
public:
    SoftwareSeHsm();
    ~SoftwareSeHsm() override = default;

    SeedResult generateSeed(uint8_t level) override;

    CcuSecErrorCode verifyKey(uint8_t level, uint32_t seedId,
                               const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& expectedSeed) override;

    KeyResult deriveKey(const std::string& rootKeyName,
                        const std::vector<uint8_t>& context) override;

    CcuSecErrorCode storeKey(const std::string& keyName,
                              const std::vector<uint8_t>& keyMaterial) override;

    KeyResult loadKey(const std::string& keyName) override;

    bool hasKey(const std::string& keyName) override;

    CcuSecErrorCode secureStore(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& data) override;

    SecureDataResult secureLoad(const std::vector<uint8_t>& key) override;

private:
    uint32_t nextSeedId_ = 1;
    std::mutex mutex_;

    struct SeedInfoInternal {
        std::vector<uint8_t> seed;
        uint8_t level = 0;
        std::chrono::steady_clock::time_point createTime;
        bool consumed = false;
    };

    std::map<uint32_t, SeedInfoInternal> seedPool_;
    std::map<std::string, std::vector<uint8_t>> keyStore_;
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> secureStorage_;

    std::vector<uint8_t> generateRandomBytes(size_t size);
    std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> deriveKeyFromRoot(const std::vector<uint8_t>& rootKey,
                                            const std::vector<uint8_t>& context);
};

} // namespace ccu_sec
