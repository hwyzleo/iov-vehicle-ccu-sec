#pragma once

#include "config_loader.h"

namespace cgw_sec {

class SecSomeipService {
public:
    SecSomeipService(const SecConfig& secConfig, const SomeipConfig& someipConfig, const SeHsmConfig& seHsmConfig);
    void start();
    void stop();
};

} // namespace cgw_sec
