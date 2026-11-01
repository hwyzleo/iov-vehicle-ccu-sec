#pragma once

#include <memory>
#include <mutex>
#include <set>
#include <map>
#include "se_hsm_interface.h"
#include "data_models.h"
#include "error_codes.h"

namespace ccu_sec {

class SecurityGuard {
public:
    SecurityGuard(std::shared_ptr<SeHsmInterface> hsm);
    ~SecurityGuard() = default;

    CcuSecErrorCode verifyPermission(uint8_t level, const std::string& operation);

    CcuSecErrorCode checkSecureSession(uint32_t sessionHandle);

    CcuSecErrorCode authorizeRequest(uint8_t level, const std::string& operation,
                                       uint32_t sessionHandle);

    void registerSecureSession(uint32_t sessionHandle);

    void removeSecureSession(uint32_t sessionHandle);

private:
    std::shared_ptr<SeHsmInterface> hsm_;
    mutable std::mutex mutex_;

    std::set<uint32_t> activeSessions_;
    std::map<std::string, uint8_t> operationPermissions_;
};

} // namespace ccu_sec
