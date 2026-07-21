#pragma once

#include <memory>
#include <mutex>
#include <set>
#include <map>
#include "se_hsm_interface.h"
#include "data_models.h"
#include "error_codes.h"

namespace cgw_sec {

class SecurityGuard {
public:
    SecurityGuard(std::shared_ptr<SeHsmInterface> hsm);
    ~SecurityGuard() = default;

    CgwSecErrorCode verifyPermission(uint8_t level, const std::string& operation);

    CgwSecErrorCode checkSecureSession(uint32_t sessionHandle);

    CgwSecErrorCode authorizeRequest(uint8_t level, const std::string& operation,
                                       uint32_t sessionHandle);

    void registerSecureSession(uint32_t sessionHandle);

    void removeSecureSession(uint32_t sessionHandle);

private:
    std::shared_ptr<SeHsmInterface> hsm_;
    mutable std::mutex mutex_;

    std::set<uint32_t> activeSessions_;
    std::map<std::string, uint8_t> operationPermissions_;
};

} // namespace cgw_sec
