#pragma once

#include <string>
#include "data_models.h"

namespace cgw_sec {

class ConfigLoader {
public:
    static SecConfig loadSecConfig(const std::string& path);
    static SomeipConfig loadSomeipConfig(const std::string& path);
    static SeHsmConfig loadSeHsmConfig(const std::string& path);
};

} // namespace cgw_sec
