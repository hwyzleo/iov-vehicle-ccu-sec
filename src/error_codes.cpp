#include "error_codes.h"

namespace ccu_sec {

std::string errorCodeToString(CcuSecErrorCode code) {
    switch (code) {
        case CcuSecErrorCode::SUCCESS: return "SUCCESS";
        case CcuSecErrorCode::SEED_GENERATION_FAILED: return "SEED_GENERATION_FAILED";
        case CcuSecErrorCode::KEY_VERIFICATION_FAILED: return "KEY_VERIFICATION_FAILED";
        case CcuSecErrorCode::OTA_ROOT_MISSING: return "OTA_ROOT_MISSING";
        case CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED: return "SESSION_KEY_DERIVATION_FAILED";
        case CcuSecErrorCode::DEVICE_ROOT_MISSING: return "DEVICE_ROOT_MISSING";
        case CcuSecErrorCode::SE_HSM_ACCESS_FAILED: return "SE_HSM_ACCESS_FAILED";
        case CcuSecErrorCode::UNAUTHORIZED_REQUEST: return "UNAUTHORIZED_REQUEST";
        default: return "UNKNOWN_ERROR";
    }
}

std::string errorCodeDescription(CcuSecErrorCode code) {
    switch (code) {
        case CcuSecErrorCode::SUCCESS: return "Operation completed successfully";
        case CcuSecErrorCode::SEED_GENERATION_FAILED: return "Seed generation failed";
        case CcuSecErrorCode::KEY_VERIFICATION_FAILED: return "Key verification failed";
        case CcuSecErrorCode::OTA_ROOT_MISSING: return "OTA vehicle root not injected";
        case CcuSecErrorCode::SESSION_KEY_DERIVATION_FAILED: return "Session key derivation failed";
        case CcuSecErrorCode::DEVICE_ROOT_MISSING: return "CCU device root not provisioned";
        case CcuSecErrorCode::SE_HSM_ACCESS_FAILED: return "SE/HSM access failed (fail-closed)";
        case CcuSecErrorCode::UNAUTHORIZED_REQUEST: return "Request unauthorized or session not authenticated";
        default: return "Unknown error";
    }
}

} // namespace ccu_sec
