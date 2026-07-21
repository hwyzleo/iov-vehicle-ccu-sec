#include "error_codes.h"

namespace cgw_sec {

std::string errorCodeToString(CgwSecErrorCode code) {
    switch (code) {
        case CgwSecErrorCode::SUCCESS: return "SUCCESS";
        case CgwSecErrorCode::SEED_GENERATION_FAILED: return "SEED_GENERATION_FAILED";
        case CgwSecErrorCode::KEY_VERIFICATION_FAILED: return "KEY_VERIFICATION_FAILED";
        case CgwSecErrorCode::OTA_ROOT_MISSING: return "OTA_ROOT_MISSING";
        case CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED: return "SESSION_KEY_DERIVATION_FAILED";
        case CgwSecErrorCode::DEVICE_ROOT_MISSING: return "DEVICE_ROOT_MISSING";
        case CgwSecErrorCode::SE_HSM_ACCESS_FAILED: return "SE_HSM_ACCESS_FAILED";
        case CgwSecErrorCode::UNAUTHORIZED_REQUEST: return "UNAUTHORIZED_REQUEST";
        default: return "UNKNOWN_ERROR";
    }
}

std::string errorCodeDescription(CgwSecErrorCode code) {
    switch (code) {
        case CgwSecErrorCode::SUCCESS: return "Operation completed successfully";
        case CgwSecErrorCode::SEED_GENERATION_FAILED: return "Seed generation failed";
        case CgwSecErrorCode::KEY_VERIFICATION_FAILED: return "Key verification failed";
        case CgwSecErrorCode::OTA_ROOT_MISSING: return "OTA vehicle root not injected";
        case CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED: return "Session key derivation failed";
        case CgwSecErrorCode::DEVICE_ROOT_MISSING: return "Gateway device root not provisioned";
        case CgwSecErrorCode::SE_HSM_ACCESS_FAILED: return "SE/HSM access failed (fail-closed)";
        case CgwSecErrorCode::UNAUTHORIZED_REQUEST: return "Request unauthorized or session not authenticated";
        default: return "Unknown error";
    }
}

} // namespace cgw_sec
