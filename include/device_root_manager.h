#pragma once

#include <memory>
#include <mutex>
#include <map>
#include "se_hsm_interface.h"
#include "data_models.h"
#include "error_codes.h"

namespace cgw_sec {

class DeviceRootManager {
public:
    explicit DeviceRootManager(std::shared_ptr<SeHsmInterface> hsm);
    ~DeviceRootManager() = default;

    bool isDeviceRootAvailable() const;

    KeyResult deriveSubKey(const std::string& subKeyName,
                            const std::vector<uint8_t>& context);

    SecureDataResult wrapData(const std::vector<uint8_t>& data);

    SecureDataResult unwrapData(const std::vector<uint8_t>& wrappedData);

private:
    std::shared_ptr<SeHsmInterface> hsm_;
    mutable std::mutex mutex_;

    std::map<std::string, std::vector<uint8_t>> derivedKeys_;
};

} // namespace cgw_sec
