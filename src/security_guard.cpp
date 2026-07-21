#include "security_guard.h"
#include "constants.h"
#include <algorithm>

namespace cgw_sec {

SecurityGuard::SecurityGuard(std::shared_ptr<SeHsmInterface> hsm)
    : hsm_(std::move(hsm)) {
    operationPermissions_["get_seed"] = SECURITY_LEVEL_1;
    operationPermissions_["verify_key"] = SECURITY_LEVEL_1;
    operationPermissions_["derive_ota_session"] = SECURITY_LEVEL_1;
    operationPermissions_["derive_by_uid"] = SECURITY_LEVEL_1;
    operationPermissions_["wrap_by_uid"] = SECURITY_LEVEL_1;
}

CgwSecErrorCode SecurityGuard::verifyPermission(uint8_t level,
                                                  const std::string& operation) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = operationPermissions_.find(operation);
    if (it == operationPermissions_.end()) {
        return CgwSecErrorCode::UNAUTHORIZED_REQUEST;
    }

    if (level < it->second) {
        return CgwSecErrorCode::UNAUTHORIZED_REQUEST;
    }

    return CgwSecErrorCode::SUCCESS;
}

CgwSecErrorCode SecurityGuard::checkSecureSession(uint32_t sessionHandle) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (activeSessions_.find(sessionHandle) == activeSessions_.end()) {
        return CgwSecErrorCode::UNAUTHORIZED_REQUEST;
    }

    return CgwSecErrorCode::SUCCESS;
}

CgwSecErrorCode SecurityGuard::authorizeRequest(uint8_t level,
                                                  const std::string& operation,
                                                  uint32_t sessionHandle) {
    auto permResult = verifyPermission(level, operation);
    if (permResult != CgwSecErrorCode::SUCCESS) {
        return permResult;
    }

    auto sessionResult = checkSecureSession(sessionHandle);
    if (sessionResult != CgwSecErrorCode::SUCCESS) {
        return sessionResult;
    }

    return CgwSecErrorCode::SUCCESS;
}

void SecurityGuard::registerSecureSession(uint32_t sessionHandle) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeSessions_.insert(sessionHandle);
}

void SecurityGuard::removeSecureSession(uint32_t sessionHandle) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeSessions_.erase(sessionHandle);
}

} // namespace cgw_sec
