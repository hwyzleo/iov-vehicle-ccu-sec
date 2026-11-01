#include "security_guard.h"
#include "constants.h"
#include <algorithm>

namespace ccu_sec {

SecurityGuard::SecurityGuard(std::shared_ptr<SeHsmInterface> hsm)
    : hsm_(std::move(hsm)) {
    operationPermissions_["get_seed"] = SECURITY_LEVEL_1;
    operationPermissions_["verify_key"] = SECURITY_LEVEL_1;
    operationPermissions_["derive_ota_session"] = SECURITY_LEVEL_1;
    operationPermissions_["derive_by_uid"] = SECURITY_LEVEL_1;
    operationPermissions_["wrap_by_uid"] = SECURITY_LEVEL_1;
}

CcuSecErrorCode SecurityGuard::verifyPermission(uint8_t level,
                                                  const std::string& operation) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = operationPermissions_.find(operation);
    if (it == operationPermissions_.end()) {
        return CcuSecErrorCode::UNAUTHORIZED_REQUEST;
    }

    if (level < it->second) {
        return CcuSecErrorCode::UNAUTHORIZED_REQUEST;
    }

    return CcuSecErrorCode::SUCCESS;
}

CcuSecErrorCode SecurityGuard::checkSecureSession(uint32_t sessionHandle) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (activeSessions_.find(sessionHandle) == activeSessions_.end()) {
        return CcuSecErrorCode::UNAUTHORIZED_REQUEST;
    }

    return CcuSecErrorCode::SUCCESS;
}

CcuSecErrorCode SecurityGuard::authorizeRequest(uint8_t level,
                                                  const std::string& operation,
                                                  uint32_t sessionHandle) {
    auto permResult = verifyPermission(level, operation);
    if (permResult != CcuSecErrorCode::SUCCESS) {
        return permResult;
    }

    auto sessionResult = checkSecureSession(sessionHandle);
    if (sessionResult != CcuSecErrorCode::SUCCESS) {
        return sessionResult;
    }

    return CcuSecErrorCode::SUCCESS;
}

void SecurityGuard::registerSecureSession(uint32_t sessionHandle) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeSessions_.insert(sessionHandle);
}

void SecurityGuard::removeSecureSession(uint32_t sessionHandle) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeSessions_.erase(sessionHandle);
}

} // namespace ccu_sec
