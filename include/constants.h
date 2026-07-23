#pragma once

#include <cstdint>
#include <cstddef>

namespace cgw_sec {

// ====================================================================
// SOME/IP Service & Instance ID 定义
// 来源：CGW 模块库 SSOT（已分配）
// ====================================================================

// Service ID: 0x7726（CGW-SEC 安全服务）
// Instance ID: 0x0001
// SOME/IP 端口: 30502
// 完整寻址: Message ID = Service ID << 16 | Method ID
// 本服务方法即 0x7726_xxxx
constexpr uint16_t SEC_SERVICE_ID = 0x7726;
constexpr uint16_t SEC_INSTANCE_ID = 0x0001;
constexpr uint16_t SEC_SOMEIP_PORT = 30502;

// ====================================================================
// Method ID 分配约定
// ====================================================================
// - Method ID 为 service-scoped（仅需在本 Service 内唯一）
// - 0x0001–0x7FFF 用于 method（request/response）
// - 0x8000–0xFFFF 预留 event/notification（配合 Eventgroup）
// - 标准命名统一采用 METHOD_<动作> 大写蛇形
// - 一经分配不复用、不重编号
//
// Method ID 分配表（v1.1，CGW-SEC-DSN-CR-002）：
// | Method ID | 标准名                  | 方法签名                        | 方向                | 对应需求 |
// |-----------|------------------------|--------------------------------|--------------------|---------| 
// | 0x0001    | METHOD_GET_SEED        | getSeed(level)                 | CGW-DIAG → SEC     | US-001  |
// | 0x0002    | METHOD_VERIFY_KEY      | verifyKey(level, seedId, key)  | CGW-DIAG → SEC     | US-001  |
// | 0x0003    | METHOD_DERIVE_OTA_SESSION | deriveOtaSession(context)   | FOTA/OTA → SEC     | US-002  |
// | 0x0004    | METHOD_DERIVE_BY_UID   | deriveByUid(keyName, info)     | 设备级调用方 → SEC  | US-003  |
// | 0x0005    | METHOD_WRAP_BY_UID     | wrapByUid(keyName, plaintext)  | 设备级调用方 → SEC  | US-003  |
//
// 后续新增 method/event 按本约定顺延分配并另开 CR。
// ====================================================================

// Method ID 常量（service-scoped）
constexpr uint16_t METHOD_GET_SEED = 0x0001;
constexpr uint16_t METHOD_VERIFY_KEY = 0x0002;
constexpr uint16_t METHOD_DERIVE_OTA_SESSION = 0x0003;
constexpr uint16_t METHOD_DERIVE_BY_UID = 0x0004;
constexpr uint16_t METHOD_WRAP_BY_UID = 0x0005;

// Method ID 范围约定
constexpr uint16_t METHOD_ID_MIN = 0x0001;
constexpr uint16_t METHOD_ID_MAX = 0x7FFF;
constexpr uint16_t EVENT_ID_MIN = 0x8000;
constexpr uint16_t EVENT_ID_MAX = 0xFFFF;

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
