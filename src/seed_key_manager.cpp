#include "seed_key_manager.h"
#include "constants.h"
#include <random>
#include <algorithm>

namespace cgw_sec {

SeedKeyManager::SeedKeyManager(std::shared_ptr<SeHsmInterface> hsm)
    : hsm_(std::move(hsm)) {}

SeedResult SeedKeyManager::generateSeed(uint8_t level) {
    std::lock_guard<std::mutex> lock(mutex_);

    cleanupExpiredSeeds();

    auto hsmResult = hsm_->generateSeed(level);
    if (hsmResult.error != CgwSecErrorCode::SUCCESS) {
        return hsmResult;
    }

    SeedEntry entry;
    entry.seed = hsmResult.seed;
    entry.level = level;
    entry.createTime = std::chrono::steady_clock::now();
    entry.consumed = false;

    uint32_t seedId = nextSeedId_++;
    seedPool_[seedId] = entry;

    hsmResult.seedId = seedId;
    return hsmResult;
}

CgwSecErrorCode SeedKeyManager::verifyKey(uint8_t level, uint32_t seedId,
                                            const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = seedPool_.find(seedId);
    if (it == seedPool_.end()) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    auto& entry = it->second;

    if (entry.consumed) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - entry.createTime).count();
    if (elapsed > seedExpirationMs_) {
        seedPool_.erase(it);
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    if (entry.level != level) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    auto result = hsm_->verifyKey(level, seedId, key, entry.seed);
    if (result == CgwSecErrorCode::SUCCESS) {
        entry.consumed = true;
    }

    return result;
}

void SeedKeyManager::cleanupExpiredSeeds() {
    auto now = std::chrono::steady_clock::now();

    for (auto it = seedPool_.begin(); it != seedPool_.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - it->second.createTime).count();
        if (elapsed > seedExpirationMs_) {
            it = seedPool_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t SeedKeyManager::getActiveSeedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return seedPool_.size();
}

} // namespace cgw_sec
