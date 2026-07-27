#include "sec_log_adapter.h"

namespace cgw_sec {

bool SecLogAdapter::s_initialized = false;

cgw::fw::log::InitResult SecLogAdapter::init(
    const std::string& service,
    const cgw::fw::log::LogConfig& config
) {
    auto result = cgw::fw::log::Logger::init(service, config);
    if (result.error == cgw::fw::log::LogError::kOk) {
        s_initialized = true;
    }
    return result;
}

cgw::fw::log::Logger SecLogAdapter::facade() {
    return cgw::fw::log::Logger::get("facade");
}

cgw::fw::log::Logger SecLogAdapter::seed_key() {
    return cgw::fw::log::Logger::get("seed_key");
}

cgw::fw::log::Logger SecLogAdapter::ota_session() {
    return cgw::fw::log::Logger::get("ota_session");
}

cgw::fw::log::Logger SecLogAdapter::root_store() {
    return cgw::fw::log::Logger::get("root_store");
}

cgw::fw::log::Logger SecLogAdapter::device_key() {
    return cgw::fw::log::Logger::get("device_key");
}

cgw::fw::log::Logger SecLogAdapter::se_adapter() {
    return cgw::fw::log::Logger::get("se_adapter");
}

bool SecLogAdapter::isInitialized() {
    return s_initialized;
}

} // namespace cgw_sec
