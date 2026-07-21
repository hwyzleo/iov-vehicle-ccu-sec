#include "se_hsm_factory.h"
#include "software_se_hsm.h"

namespace cgw_sec {

std::unique_ptr<SeHsmInterface> SeHsmFactory::create(const SeHsmConfig& config) {
    if (config.type == "software") {
        return std::make_unique<SoftwareSeHsm>();
    }

    // Unknown type
    return nullptr;
}

} // namespace cgw_sec
