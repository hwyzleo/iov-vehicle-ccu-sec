#include "se_hsm_factory.h"

#ifdef CCU_SEC_ENABLE_SOFTWARE_HSM
#include "software_se_hsm.h"
#endif

namespace ccu_sec {

std::unique_ptr<SeHsmInterface> SeHsmFactory::create(const SeHsmConfig& config) {
 (void)config;
#ifdef CCU_SEC_ENABLE_SOFTWARE_HSM
    // Explicit NON_PRODUCTION fixture: the software HSM uses simulated
    // algorithms and an in-memory key store, so it is only compiled into
    // HOST/test builds that pass -DCCU_SEC_ENABLE_SOFTWARE_HSM=ON.
    if (config.type == "software") {
        return std::make_unique<SoftwareSeHsm>();
    }
#endif

    // unconfigured / unavailable / unknown adapter: no software fallback.
    // The caller must fail closed (CCU-SEC-DSN-CR-005 §5.2/§6.2).
    return nullptr;
}

} // namespace ccu_sec
