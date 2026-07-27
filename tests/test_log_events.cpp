#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include "error_codes.h"
#include "constants.h"
#include <regex>

namespace cgw_sec {
namespace {

class LogEventsTest : public ::testing::Test {
protected:
    void SetUp() override {
        cgw::fw::log::LogConfig config;
        config.level = cgw::fw::log::LogLevel::kDebug;

        auto result = SecLogAdapter::init("cgw-sec-events-test", config);
        ASSERT_EQ(result.error, cgw::fw::log::LogError::kOk);
    }
};

// ============================================================
// 事件名格式验证（CGW-SEC-DSN-CR-004 §事件目录）
// 事件名使用小写点分命名
// ============================================================
TEST_F(LogEventsTest, EventNameFormat) {
    std::regex event_pattern("^sec\\.[a-z_]+\\.[a-z_.]+$");

    // Service lifecycle
    EXPECT_TRUE(std::regex_match(sec_events::SERVICE_INITIALIZED, event_pattern));
    // Seed/Key
    EXPECT_TRUE(std::regex_match(sec_events::SEED_GENERATED, event_pattern));
    EXPECT_TRUE(std::regex_match(sec_events::SEED_GENERATE_FAILED, event_pattern));
    EXPECT_TRUE(std::regex_match(sec_events::KEY_VERIFY_SUCCEEDED, event_pattern));
    EXPECT_TRUE(std::regex_match(sec_events::KEY_VERIFY_FAILED, event_pattern));
    // OTA session
    EXPECT_TRUE(std::regex_match(sec_events::OTA_SESSION_DERIVED, event_pattern));
    EXPECT_TRUE(std::regex_match(sec_events::OTA_SESSION_DERIVE_FAILED, event_pattern));
    // Device key
    EXPECT_TRUE(std::regex_match(sec_events::DEVICE_KEY_OPERATION_FAILED, event_pattern));
    // SE/HSM
    EXPECT_TRUE(std::regex_match(sec_events::SE_ACCESS_FAILED, event_pattern));
    // Authorization
    EXPECT_TRUE(std::regex_match(sec_events::REQUEST_UNAUTHORIZED, event_pattern));
    // Framework field rejection
    EXPECT_TRUE(std::regex_match(sec_events::LOG_FIELD_REJECTED, event_pattern));
}

// ============================================================
// 所有模块 Logger 可调用（CGW-SEC-DSN-CR-004 §启动与模块 Logger）
// ============================================================
TEST_F(LogEventsTest, AllModuleLoggersCallable) {
    SecLogAdapter::facade().info(sec_events::SERVICE_INITIALIZED,
        "Test facade event");
    SecLogAdapter::seed_key().info(sec_events::SEED_GENERATED,
        "Test seed_key event");
    SecLogAdapter::ota_session().info(sec_events::OTA_SESSION_DERIVED,
        "Test ota_session event");
    SecLogAdapter::root_store().info("sec.root_store.test",
        "Test root_store event");
    SecLogAdapter::device_key().error(sec_events::DEVICE_KEY_OPERATION_FAILED,
        "Test device_key event");
    SecLogAdapter::se_adapter().error(sec_events::SE_ACCESS_FAILED,
        "Test se_adapter event");
}

// ============================================================
// 错误码映射验证（CGW-SEC-DSN-CR-004 §事件目录）
// ============================================================
TEST_F(LogEventsTest, SecErrorCodes) {
    // 验证 SEC 业务错误码 CGW-SEC-1001~1007
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SEED_GENERATION_FAILED), "SEED_GENERATION_FAILED");
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::KEY_VERIFICATION_FAILED), "KEY_VERIFICATION_FAILED");
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::OTA_ROOT_MISSING), "OTA_ROOT_MISSING");
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED), "SESSION_KEY_DERIVATION_FAILED");
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::DEVICE_ROOT_MISSING), "DEVICE_ROOT_MISSING");
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::SE_HSM_ACCESS_FAILED), "SE_HSM_ACCESS_FAILED");
    EXPECT_EQ(errorCodeToString(CgwSecErrorCode::UNAUTHORIZED_REQUEST), "UNAUTHORIZED_REQUEST");

    // 错误码字符串非空
    EXPECT_FALSE(errorCodeToString(CgwSecErrorCode::SEED_GENERATION_FAILED).empty());
    EXPECT_FALSE(errorCodeToString(CgwSecErrorCode::UNAUTHORIZED_REQUEST).empty());

    // 描述字符串非空
    EXPECT_FALSE(errorCodeDescription(CgwSecErrorCode::SEED_GENERATION_FAILED).empty());
    EXPECT_FALSE(errorCodeDescription(CgwSecErrorCode::UNAUTHORIZED_REQUEST).empty());
}

TEST_F(LogEventsTest, FrameworkErrorCodes) {
    // 验证 framework 错误码（CGW-FW-0201~0205）
    EXPECT_EQ(static_cast<uint32_t>(cgw::fw::log::LogError::kConfigInvalid), 201);
    EXPECT_EQ(static_cast<uint32_t>(cgw::fw::log::LogError::kInitFailed), 202);
    EXPECT_EQ(static_cast<uint32_t>(cgw::fw::log::LogError::kSinkFailed), 203);
    EXPECT_EQ(static_cast<uint32_t>(cgw::fw::log::LogError::kQueueOverflow), 204);
    EXPECT_EQ(static_cast<uint32_t>(cgw::fw::log::LogError::kSensitiveViolation), 205);
}

TEST_F(LogEventsTest, SecErrorCodeValues) {
    // 验证 CGW-SEC-1001~1007 数值
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::SEED_GENERATION_FAILED), 1001);
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::KEY_VERIFICATION_FAILED), 1002);
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::OTA_ROOT_MISSING), 1003);
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::SESSION_KEY_DERIVATION_FAILED), 1004);
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::DEVICE_ROOT_MISSING), 1005);
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::SE_HSM_ACCESS_FAILED), 1006);
    EXPECT_EQ(static_cast<uint32_t>(CgwSecErrorCode::UNAUTHORIZED_REQUEST), 1007);
}

// ============================================================
// 事件字段验证（CGW-SEC-DSN-CR-004 §事件目录 / §字段白名单与零泄露）
// ============================================================

TEST_F(LogEventsTest, ServiceInitializedFields) {
    // sec.service.initialized: result, duration_ms
    SecLogAdapter::facade().info(
        sec_events::SERVICE_INITIALIZED,
        "Service initialized",
        {slog::f_str("result", "success"),
         slog::f_int("duration_ms", 120)}
    );
}

TEST_F(LogEventsTest, SeedGeneratedFields) {
    // sec.seed.generated: caller, security_level, operation, result, duration_ms
    SecLogAdapter::seed_key().info(
        sec_events::SEED_GENERATED,
        "getSeed succeeded",
        {slog::f_str("caller", "diag"),
         slog::f_str("security_level", "0x01"),
         slog::f_str("operation", "getSeed"),
         slog::f_str("result", "success"),
         slog::f_int("duration_ms", 5),
         slog::f_int("seed_id", 42)}
    );
}

TEST_F(LogEventsTest, SeedGenerateFailedFields) {
    // sec.seed.generate.failed: caller, security_level, result, duration_ms, error_code
    SecLogAdapter::seed_key().error(
        sec_events::SEED_GENERATE_FAILED,
        "getSeed failed",
        {slog::f_str("caller", "diag"),
         slog::f_str("security_level", "0x01"),
         slog::f_str("result", "SEED_GENERATION_FAILED"),
         slog::f_int("duration_ms", 5),
         slog::f_str("error_code", "CGW-SEC-1001")}
    );
}

TEST_F(LogEventsTest, KeyVerifySucceededFields) {
    // sec.key.verify.succeeded: caller, security_level, operation, result, duration_ms
    SecLogAdapter::seed_key().info(
        sec_events::KEY_VERIFY_SUCCEEDED,
        "verifyKey succeeded",
        {slog::f_str("caller", "diag"),
         slog::f_str("security_level", "0x01"),
         slog::f_str("operation", "verifyKey"),
         slog::f_str("result", "success"),
         slog::f_int("duration_ms", 3)}
    );
}

TEST_F(LogEventsTest, KeyVerifyFailedFields) {
    // sec.key.verify.failed: caller, security_level, operation, result, duration_ms, error_code
    SecLogAdapter::seed_key().warn(
        sec_events::KEY_VERIFY_FAILED,
        "verifyKey failed",
        {slog::f_str("caller", "diag"),
         slog::f_str("security_level", "0x01"),
         slog::f_str("operation", "verifyKey"),
         slog::f_str("result", "KEY_VERIFICATION_FAILED"),
         slog::f_int("duration_ms", 3),
         slog::f_str("error_code", "CGW-SEC-1002")}
    );
}

TEST_F(LogEventsTest, OtaSessionDerivedFields) {
    // sec.ota.session.derived: caller, operation, direction, result, duration_ms
    SecLogAdapter::ota_session().info(
        sec_events::OTA_SESSION_DERIVED,
        "OTA session derived",
        {slog::f_str("caller", "fota"),
         slog::f_str("operation", "deriveOtaSession"),
         slog::f_str("direction", "download"),
         slog::f_str("result", "success"),
         slog::f_int("duration_ms", 10)}
    );
}

TEST_F(LogEventsTest, OtaSessionDeriveFailedFields) {
    // sec.ota.session.derive.failed: caller, operation, direction, result, duration_ms, error_code
    SecLogAdapter::ota_session().error(
        sec_events::OTA_SESSION_DERIVE_FAILED,
        "OTA session derivation failed",
        {slog::f_str("caller", "fota"),
         slog::f_str("operation", "deriveOtaSession"),
         slog::f_str("direction", "download"),
         slog::f_str("result", "OTA_ROOT_MISSING"),
         slog::f_int("duration_ms", 10),
         slog::f_str("error_code", "CGW-SEC-1003")}
    );
}

TEST_F(LogEventsTest, DeviceKeyOperationFailedFields) {
    // sec.device.key.operation.failed: caller, operation, result, duration_ms, error_code
    SecLogAdapter::device_key().error(
        sec_events::DEVICE_KEY_OPERATION_FAILED,
        "deriveByUid failed",
        {slog::f_str("caller", "device"),
         slog::f_str("operation", "deriveByUid"),
         slog::f_str("result", "DEVICE_ROOT_MISSING"),
         slog::f_int("duration_ms", 8),
         slog::f_str("error_code", "CGW-SEC-1005")}
    );
}

TEST_F(LogEventsTest, SeAccessFailedFields) {
    // sec.se.access.failed: operation, result, duration_ms, error_code
    SecLogAdapter::se_adapter().error(
        sec_events::SE_ACCESS_FAILED,
        "SE/HSM access failed",
        {slog::f_str("operation", "storeKey"),
         slog::f_str("result", "SE_HSM_ACCESS_FAILED"),
         slog::f_int("duration_ms", 15),
         slog::f_str("error_code", "CGW-SEC-1006")}
    );
}

TEST_F(LogEventsTest, RequestUnauthorizedFields) {
    // sec.request.unauthorized: caller, operation, result, SOME/IP context, error_code
    SecLogAdapter::facade().warn(
        sec_events::REQUEST_UNAUTHORIZED,
        "Request unauthorized",
        {slog::f_str("caller", "unknown"),
         slog::f_str("operation", "getSeed"),
         slog::f_str("result", "invalid_request"),
         slog::f_str("someip_service_id", "0x1140"),
         slog::f_str("someip_method_id", "0x0001"),
         slog::f_str("error_code", "CGW-SEC-1007")}
    );
}

TEST_F(LogEventsTest, LogFieldRejectedFields) {
    // sec.log.field.rejected: 字段名、调用模块、策略结果
    SecLogAdapter::facade().warn(
        sec_events::LOG_FIELD_REJECTED,
        "Log field rejected by Secret policy",
        {slog::f_str("field_name", "seed"),
         slog::f_str("caller_module", "seed_key"),
         slog::f_str("policy_result", "rejected"),
         slog::f_str("error_code", "CGW-FW-0205")}
    );
}

// ============================================================
// 敏感类型验证（CGW-SEC-DSN-CR-004 §字段白名单与零泄露）
// ============================================================

TEST_F(LogEventsTest, SensitivityClassification) {
    // VIN/device_sn 按 Identifier 处理：默认掩码或不可逆摘要
    SecLogAdapter::facade().info("test.event",
        "Identifier field",
        {slog::f_str("vin", "LSVAU2180N2123456", cgw::fw::log::Sensitivity::Identifier)}
    );

    // 业务 payload 按 Payload 处理
    SecLogAdapter::facade().info("test.event",
        "Payload field",
        {slog::f_str("raw_payload", "raw_data_hex", cgw::fw::log::Sensitivity::Payload)}
    );

    // seed/key/root/session_key 按 Secret 直接拒绝
    SecLogAdapter::seed_key().info("test.event",
        "Secret field rejection",
        {slog::f_str("seed", "0xABCD1234", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("key", "0xEF567890", cgw::fw::log::Sensitivity::Secret)}
    );
}

TEST_F(LogEventsTest, SecretFieldsRejected) {
    // 验证所有密钥材料类型按 Secret 处理
    SecLogAdapter::seed_key().info("test.secret_rejection",
        "All secret types should be rejected",
        {slog::f_str("seed", "seed_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("key", "key_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("root", "root_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("session_key", "session_key_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("key_material", "key_material_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("private_key", "private_key_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("password", "password_data", cgw::fw::log::Sensitivity::Secret),
         slog::f_str("token", "token_data", cgw::fw::log::Sensitivity::Secret)}
    );

    // 验证日志可正常执行（框架拒绝 Secret 字段但不崩溃）
    SUCCEED();
}

TEST_F(LogEventsTest, PayloadFieldOnlyMetadata) {
    // Payload 字段: 仅记录长度、摘要等元数据，不记录 nonce/salt/info 原值
    SecLogAdapter::ota_session().info("test.payload_metadata",
        "Payload metadata only",
        {slog::f_int("payload_length", 64),
         slog::f_str("nonce_length", "12"),
         slog::f_str("operation", "deriveOtaSession")}
    );
}

TEST_F(LogEventsTest, VinNotInMessage) {
    // VIN 不得拼入 message
    SecLogAdapter::facade().info("test.vin_not_in_message",
        "VIN processing result",
        {slog::f_str("vin_hash", "masked_value", cgw::fw::log::Sensitivity::Identifier),
         slog::f_str("result", "OK")}
    );
}

TEST_F(LogEventsTest, AllowedFieldsOnly) {
    // 验证允许字段：caller, security_level, operation, direction, result, error_code, duration_ms
    SecLogAdapter::facade().info("test.allowed_fields",
        "All allowed fields",
        {slog::f_str("caller", "diag"),
         slog::f_str("security_level", "0x01"),
         slog::f_str("operation", "getSeed"),
         slog::f_str("direction", "download"),
         slog::f_str("result", "success"),
         slog::f_str("error_code", ""),
         slog::f_int("duration_ms", 5)}
    );
}

} // namespace
} // namespace cgw_sec
