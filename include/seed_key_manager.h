#pragma once

#include <memory>
#include <mutex>
#include <map>
#include <chrono>
#include "se_hsm_interface.h"
#include "data_models.h"
#include "error_codes.h"

namespace cgw_sec {

class SeedKeyManager {
public:
    explicit SeedKeyManager(std::shared_ptr<SeHsmInterface> hsm);
    ~SeedKeyManager() = default;

    SeedResult generateSeed(uint8_t level);

    CgwSecErrorCode verifyKey(uint8_t level, uint32_t seedId,
                               const std::vector<uint8_t>& key);

    void cleanupExpiredSeeds();

    size_t getActiveSeedCount() const;

private:
    std::shared_ptr<SeHsmInterface> hsm_;
    mutable std::mutex mutex_;

    struct SeedEntry {
        std::vector<uint8_t> seed;
        uint8_t level = 0;
        std::chrono::steady_clock::time_point createTime;
        bool consumed = false;
    };

    std::map<uint32_t, SeedEntry> seedPool_;
    uint32_t nextSeedId_ = 1;
    uint32_t seedExpirationMs_ = 30000;
};

} // namespace cgw_sec
