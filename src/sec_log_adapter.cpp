#include "sec_log_adapter.h"

namespace ccu_sec {

bool SecLogAdapter::s_initialized = false;

ccu::fw::log::InitResult SecLogAdapter::init(
    const std::string& service,
    const ccu::fw::log::LogConfig& config
) {
    auto result = ccu::fw::log::Logger::init(service, config);
    if (result.error == ccu::fw::log::LogError::kOk) {
        s_initialized = true;
    }
    return result;
}

ccu::fw::log::Logger SecLogAdapter::facade() {
    return ccu::fw::log::Logger::get("facade");
}

ccu::fw::log::Logger SecLogAdapter::seed_key() {
    return ccu::fw::log::Logger::get("seed_key");
}

ccu::fw::log::Logger SecLogAdapter::ota_session() {
    return ccu::fw::log::Logger::get("ota_session");
}

ccu::fw::log::Logger SecLogAdapter::root_store() {
    return ccu::fw::log::Logger::get("root_store");
}

ccu::fw::log::Logger SecLogAdapter::device_key() {
    return ccu::fw::log::Logger::get("device_key");
}

ccu::fw::log::Logger SecLogAdapter::se_adapter() {
    return ccu::fw::log::Logger::get("se_adapter");
}

bool SecLogAdapter::isInitialized() {
    return s_initialized;
}

} // namespace ccu_sec
