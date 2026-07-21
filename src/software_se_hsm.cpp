#include "software_se_hsm.h"
#include "constants.h"
#include <random>
#include <algorithm>
#include <cstring>

namespace cgw_sec {

SoftwareSeHsm::SoftwareSeHsm() = default;

std::vector<uint8_t> SoftwareSeHsm::generateRandomBytes(size_t size) {
    std::vector<uint8_t> bytes(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<uint8_t>(dis(gen));
    }
    return bytes;
}

std::vector<uint8_t> SoftwareSeHsm::xorBytes(const std::vector<uint8_t>& a,
                                               const std::vector<uint8_t>& b) {
    size_t minSize = std::min(a.size(), b.size());
    std::vector<uint8_t> result(minSize);
    for (size_t i = 0; i < minSize; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> SoftwareSeHsm::deriveKeyFromRoot(const std::vector<uint8_t>& rootKey,
                                                       const std::vector<uint8_t>& context) {
    // Simple key derivation for software simulation
    // In production, this would use HKDF or similar
    std::vector<uint8_t> derived(SESSION_KEY_SIZE);

    // Use context to derive key material
    for (size_t i = 0; i < SESSION_KEY_SIZE; ++i) {
        derived[i] = rootKey[i % rootKey.size()] ^ context[i % context.size()];
    }

    // Add some mixing
    for (size_t i = 1; i < SESSION_KEY_SIZE; ++i) {
        derived[i] ^= derived[i - 1];
    }

    return derived;
}

SeedResult SoftwareSeHsm::generateSeed(uint8_t level) {
    std::lock_guard<std::mutex> lock(mutex_);

    SeedResult result;
    result.seed = generateRandomBytes(SEED_SIZE);
    result.seedId = nextSeedId_++;

    SeedInfoInternal info;
    info.seed = result.seed;
    info.level = level;
    info.createTime = std::chrono::steady_clock::now();
    info.consumed = false;

    seedPool_[result.seedId] = info;

    result.error = CgwSecErrorCode::SUCCESS;
    return result;
}

CgwSecErrorCode SoftwareSeHsm::verifyKey(uint8_t level, uint32_t seedId,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& expectedSeed) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = seedPool_.find(seedId);
    if (it == seedPool_.end()) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    auto& seedInfo = it->second;

    // Check if seed is consumed
    if (seedInfo.consumed) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    // Check if seed is expired
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - seedInfo.createTime).count();
    if (elapsed > SEED_EXPIRATION_MS) {
        seedPool_.erase(it);
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    // Check level
    if (seedInfo.level != level) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    // In software simulation: key = seed XOR 0xFF
    std::vector<uint8_t> expectedKey(SEED_SIZE);
    for (size_t i = 0; i < SEED_SIZE; ++i) {
        expectedKey[i] = seedInfo.seed[i] ^ 0xFF;
    }

    if (key != expectedKey) {
        return CgwSecErrorCode::KEY_VERIFICATION_FAILED;
    }

    // Mark seed as consumed
    seedInfo.consumed = true;

    return CgwSecErrorCode::SUCCESS;
}

KeyResult SoftwareSeHsm::deriveKey(const std::string& rootKeyName,
                                    const std::vector<uint8_t>& context) {
    std::lock_guard<std::mutex> lock(mutex_);

    KeyResult result;

    auto it = keyStore_.find(rootKeyName);
    if (it == keyStore_.end()) {
        result.error = CgwSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }

    result.key = deriveKeyFromRoot(it->second, context);
    result.error = CgwSecErrorCode::SUCCESS;
    return result;
}

CgwSecErrorCode SoftwareSeHsm::storeKey(const std::string& keyName,
                                         const std::vector<uint8_t>& keyMaterial) {
    std::lock_guard<std::mutex> lock(mutex_);

    keyStore_[keyName] = keyMaterial;
    return CgwSecErrorCode::SUCCESS;
}

KeyResult SoftwareSeHsm::loadKey(const std::string& keyName) {
    std::lock_guard<std::mutex> lock(mutex_);

    KeyResult result;

    auto it = keyStore_.find(keyName);
    if (it == keyStore_.end()) {
        result.error = CgwSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }

    result.key = it->second;
    result.error = CgwSecErrorCode::SUCCESS;
    return result;
}

bool SoftwareSeHsm::hasKey(const std::string& keyName) {
    std::lock_guard<std::mutex> lock(mutex_);
    return keyStore_.find(keyName) != keyStore_.end();
}

CgwSecErrorCode SoftwareSeHsm::secureStore(const std::vector<uint8_t>& key,
                                             const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Simple XOR encryption for software simulation
    // In production, this would use AES or similar
    std::vector<uint8_t> encrypted(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        encrypted[i] = data[i] ^ key[i % key.size()];
    }

    secureStorage_[key] = encrypted;
    return CgwSecErrorCode::SUCCESS;
}

SecureDataResult SoftwareSeHsm::secureLoad(const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    SecureDataResult result;

    auto it = secureStorage_.find(key);
    if (it == secureStorage_.end()) {
        result.error = CgwSecErrorCode::SE_HSM_ACCESS_FAILED;
        return result;
    }

    // Decrypt
    const auto& encrypted = it->second;
    result.data.resize(encrypted.size());
    for (size_t i = 0; i < encrypted.size(); ++i) {
        result.data[i] = encrypted[i] ^ key[i % key.size()];
    }

    result.error = CgwSecErrorCode::SUCCESS;
    return result;
}

} // namespace cgw_sec
