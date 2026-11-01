#pragma once

/**
 * CCU-SEC 日志适配器
 *
 * 封装 ccu-framework-log 的初始化和模块 Logger 管理。
 * 业务模块仅使用 SecLogAdapter 提供的模块 Logger 和 slog:: 字段构造器，
 * 禁止直接调用 spdlog/syslog 或自行打开日志文件。
 *
 * 模块划分（CCU-SEC-DSN-CR-004 §启动与模块 Logger）：
 * - facade:      SOME/IP 入站方法、调用方和响应结果
 * - seed_key:    getSeed / verifyKey 操作状态，仅记录非密钥元数据
 * - ota_session: OTA 会话密钥派生操作、方向和结果
 * - root_store:  信任根存在性、访问结果和 keyName 摘要，不记录根材料
 * - device_key:  deriveByUid / wrapByUid 操作结果
 * - se_adapter:  SE/HSM 可用性、调用结果、耗时和错误码
 */

#include "log.h"
#include "log_types.h"
#include <string>
#include <cstdint>

namespace ccu_sec {

// ============================================================
// SEC 事件名常量（CCU-SEC-DSN-CR-004 §事件目录）
// ============================================================
namespace sec_events {
// Service lifecycle
constexpr const char* SERVICE_INITIALIZED = "sec.service.initialized";
// Seed/Key
constexpr const char* SEED_GENERATED         = "sec.seed.generated";
constexpr const char* SEED_GENERATE_FAILED   = "sec.seed.generate.failed";
constexpr const char* KEY_VERIFY_SUCCEEDED   = "sec.key.verify.succeeded";
constexpr const char* KEY_VERIFY_FAILED      = "sec.key.verify.failed";
// OTA session
constexpr const char* OTA_SESSION_DERIVED      = "sec.ota.session.derived";
constexpr const char* OTA_SESSION_DERIVE_FAILED = "sec.ota.session.derive.failed";
// Device key
constexpr const char* DEVICE_KEY_OPERATION_FAILED = "sec.device.key.operation.failed";
// SE/HSM
constexpr const char* SE_ACCESS_FAILED = "sec.se.access.failed";
// Authorization
constexpr const char* REQUEST_UNAUTHORIZED = "sec.request.unauthorized";
// Framework field rejection
constexpr const char* LOG_FIELD_REJECTED = "sec.log.field.rejected";
} // namespace sec_events

// ============================================================
// 便捷字段构造器 - 减少业务代码中的冗长写法
// ============================================================
namespace slog {
inline ccu::fw::log::Field f_str(const std::string& key, const std::string& val,
                                  ccu::fw::log::Sensitivity s = ccu::fw::log::Sensitivity::Normal) {
    return ccu::fw::log::Field(key, ccu::fw::log::FieldValue::makeString(val), s);
}
inline ccu::fw::log::Field f_int(const std::string& key, int64_t val) {
    return ccu::fw::log::Field(key, ccu::fw::log::FieldValue::makeInt(val));
}
inline ccu::fw::log::Field f_bool(const std::string& key, bool val) {
    return ccu::fw::log::Field(key, ccu::fw::log::FieldValue::makeBool(val));
}
inline ccu::fw::log::Field f_double(const std::string& key, double val) {
    return ccu::fw::log::Field(key, ccu::fw::log::FieldValue::makeDouble(val));
}
} // namespace slog

// ============================================================
// SecLogAdapter - 封装 ccu-framework-log 的初始化和模块 Logger
// ============================================================
class SecLogAdapter {
public:
    /// 初始化日志系统（在 main.cpp 中调用一次）
    static ccu::fw::log::InitResult init(
        const std::string& service,
        const ccu::fw::log::LogConfig& config
    );

    /// 获取各模块的 Logger 实例
    static ccu::fw::log::Logger facade();
    static ccu::fw::log::Logger seed_key();
    static ccu::fw::log::Logger ota_session();
    static ccu::fw::log::Logger root_store();
    static ccu::fw::log::Logger device_key();
    static ccu::fw::log::Logger se_adapter();

    /// 是否已初始化
    static bool isInitialized();

private:
    static bool s_initialized;
};

} // namespace ccu_sec
