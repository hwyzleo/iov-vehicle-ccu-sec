#pragma once

#include <cstdint>
#include <cstddef>

namespace cgw_sec {

// Security levels
constexpr uint8_t SECURITY_LEVEL_1 = 0x01;

// Seed/Key parameters
constexpr size_t SEED_SIZE = 16;
constexpr size_t KEY_SIZE = 16;
constexpr uint32_t SEED_EXPIRATION_MS = 30000; // 30 seconds
constexpr uint32_t MAX_SEED_POOL_SIZE = 100;

// OTA session parameters
constexpr size_t NONCE_SIZE = 12;
constexpr size_t SESSION_KEY_SIZE = 32; // AES-256

// Key names
constexpr const char* OTA_VEHICLE_ROOT_KEY_NAME = "OTA_VEHICLE_ROOT";
constexpr const char* CGW_DEVICE_ROOT_KEY_NAME = "CGW_DEVICE_ROOT";
constexpr const char* DIAG_SEEDKEY_SECRET_NAME = "DIAG_SEEDKEY_SECRET";

} // namespace cgw_sec
