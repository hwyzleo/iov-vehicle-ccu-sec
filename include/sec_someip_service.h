#pragma once

#include "config_loader.h"

class SecSomeipService {
public:
    SecSomeipService(const SecConfig& secConfig, const SomeipConfig& someipConfig, const SeHsmConfig& seHsmConfig);
    void start();
    void stop();
};
