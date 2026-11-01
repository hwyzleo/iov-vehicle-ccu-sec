#include "device_root_manager.h"
#include "constants.h"
#include <algorithm>

namespace ccu_sec {

DeviceRootManager::DeviceRootManager(std::shared_ptr<SeHsmInterface> hsm)
    : hsm_(std::move(hsm)) {}

bool DeviceRootManager::isDeviceRootAvailable() const {
    return hsm_->hasKey(CCU_DEVICE_ROOT_KEY_NAME);
}

KeyResult DeviceRootManager::deriveSubKey(const std::string& subKeyName,
                                            const std::vector<uint8_t>& context) {
    std::lock_guard<std::mutex> lock(mutex_);

    KeyResult result;

    if (!hsm_->hasKey(CCU_DEVICE_ROOT_KEY_NAME)) {
        result.error = CcuSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }

    auto keyResult = hsm_->deriveKey(CCU_DEVICE_ROOT_KEY_NAME, context);
    if (keyResult.error != CcuSecErrorCode::SUCCESS) {
        result.error = keyResult.error;
        return result;
    }

    derivedKeys_[subKeyName] = keyResult.key;
    result.key = keyResult.key;
    result.error = CcuSecErrorCode::SUCCESS;

    return result;
}

SecureDataResult DeviceRootManager::wrapData(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);

    SecureDataResult result;

    if (!hsm_->hasKey(CCU_DEVICE_ROOT_KEY_NAME)) {
        result.error = CcuSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }

    auto keyResult = hsm_->loadKey(CCU_DEVICE_ROOT_KEY_NAME);
    if (keyResult.error != CcuSecErrorCode::SUCCESS) {
        result.error = keyResult.error;
        return result;
    }

    auto storeResult = hsm_->secureStore(keyResult.key, data);
    if (storeResult != CcuSecErrorCode::SUCCESS) {
        result.error = storeResult;
        return result;
    }

    result.data = data;
    result.error = CcuSecErrorCode::SUCCESS;

    return result;
}

SecureDataResult DeviceRootManager::unwrapData(const std::vector<uint8_t>& wrappedData) {
    std::lock_guard<std::mutex> lock(mutex_);

    SecureDataResult result;

    if (!hsm_->hasKey(CCU_DEVICE_ROOT_KEY_NAME)) {
        result.error = CcuSecErrorCode::DEVICE_ROOT_MISSING;
        return result;
    }

    auto keyResult = hsm_->loadKey(CCU_DEVICE_ROOT_KEY_NAME);
    if (keyResult.error != CcuSecErrorCode::SUCCESS) {
        result.error = keyResult.error;
        return result;
    }

    auto loadResult = hsm_->secureLoad(keyResult.key);
    if (loadResult.error != CcuSecErrorCode::SUCCESS) {
        result.error = loadResult.error;
        return result;
    }

    result.data = loadResult.data;
    result.error = CcuSecErrorCode::SUCCESS;

    return result;
}

} // namespace ccu_sec
