#include "ota_session_manager.h"
#include "constants.h"
#include <random>
#include <algorithm>
#include <cstring>

namespace cgw_sec {

OtaSessionManager::OtaSessionManager(std::shared_ptr<SeHsmInterface> hsm)
    : hsm_(std::move(hsm)) {}

bool OtaSessionManager::isOtaVehicleRootAvailable() const {
    return hsm_->hasKey(OTA_VEHICLE_ROOT_KEY_NAME);
}

OtaSessionResult OtaSessionManager::deriveSessionKey(const OtaSessionContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);

    OtaSessionResult result;

    if (!hsm_->hasKey(OTA_VEHICLE_ROOT_KEY_NAME)) {
        result.error = CgwSecErrorCode::OTA_ROOT_MISSING;
        return result;
    }

    std::vector<uint8_t> derivationContext;
    derivationContext.insert(derivationContext.end(),
                              context.campaignId.begin(), context.campaignId.end());
    derivationContext.insert(derivationContext.end(),
                              context.vin.begin(), context.vin.end());
    derivationContext.insert(derivationContext.end(),
                              context.direction.begin(), context.direction.end());
    derivationContext.insert(derivationContext.end(),
                              reinterpret_cast<const uint8_t*>(&context.timestamp),
                              reinterpret_cast<const uint8_t*>(&context.timestamp) + sizeof(context.timestamp));

    auto keyResult = hsm_->deriveKey(OTA_VEHICLE_ROOT_KEY_NAME, derivationContext);
    if (keyResult.error != CgwSecErrorCode::SUCCESS) {
        result.error = CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED;
        return result;
    }

    uint32_t handle = nextSessionHandle_++;
    sessionKeys_[handle] = keyResult.key;

    result.sessionKeyHandle = handle;
    result.nonce = generateNonce();
    result.error = CgwSecErrorCode::SUCCESS;

    return result;
}

std::vector<uint8_t> OtaSessionManager::generateNonce() {
    std::vector<uint8_t> nonce(NONCE_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < NONCE_SIZE; ++i) {
        nonce[i] = static_cast<uint8_t>(dis(gen));
    }

    return nonce;
}

} // namespace cgw_sec
