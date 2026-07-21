#include "sec_someip_proxy.h"
#include <stdexcept>

namespace cgw_sec {

SecSomeipProxy::SecSomeipProxy(const SomeipConfig& config) : config_(config) {
}

SeedResult SecSomeipProxy::getSeed(uint8_t level) {
    throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
}

CgwSecErrorCode SecSomeipProxy::verifyKey(uint8_t level, uint32_t seedId,
                                            const std::vector<uint8_t>& key) {
    throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
}

OtaSessionResult SecSomeipProxy::deriveOtaSession(const OtaSessionContext& context,
                                                    uint8_t level) {
    throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
}

KeyResult SecSomeipProxy::deriveByUid(const std::string& subKeyName,
                                       const std::vector<uint8_t>& context,
                                       uint8_t level) {
    throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
}

SecureDataResult SecSomeipProxy::wrapByUid(const std::vector<uint8_t>& data,
                                            uint8_t level) {
    throw std::runtime_error("SOME/IP proxy not implemented - use SecSomeipService directly");
}

} // namespace cgw_sec
