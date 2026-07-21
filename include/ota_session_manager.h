#pragma once

#include <memory>
#include <mutex>
#include <map>
#include "se_hsm_interface.h"
#include "data_models.h"
#include "error_codes.h"

namespace cgw_sec {

class OtaSessionManager {
public:
    explicit OtaSessionManager(std::shared_ptr<SeHsmInterface> hsm);
    ~OtaSessionManager() = default;

    bool isOtaVehicleRootAvailable() const;

    OtaSessionResult deriveSessionKey(const OtaSessionContext& context);

    std::vector<uint8_t> generateNonce();

private:
    std::shared_ptr<SeHsmInterface> hsm_;
    mutable std::mutex mutex_;

    uint32_t nextSessionHandle_ = 1;
    std::map<uint32_t, std::vector<uint8_t>> sessionKeys_;
};

} // namespace cgw_sec
