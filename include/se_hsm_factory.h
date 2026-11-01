#pragma once

#include <memory>
#include "se_hsm_interface.h"
#include "data_models.h"

namespace ccu_sec {

class SeHsmFactory {
public:
    static std::unique_ptr<SeHsmInterface> create(const SeHsmConfig& config);
};

} // namespace ccu_sec
