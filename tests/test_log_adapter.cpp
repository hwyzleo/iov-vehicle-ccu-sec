#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include <regex>

namespace cgw_sec {
namespace {

class SecLogAdapterTest : public ::testing::Test {
protected:
    void SetUp() override {
        cgw::fw::log::LogConfig config;
        config.level = cgw::fw::log::LogLevel::kDebug;

        auto result = SecLogAdapter::init("cgw-sec-test", config);
        ASSERT_EQ(result.error, cgw::fw::log::LogError::kOk);
    }
};

TEST_F(SecLogAdapterTest, InitSucceeds) {
    // SetUp 已验证初始化成功
    SUCCEED();
}

TEST_F(SecLogAdapterTest, IsInitializedFlag) {
    EXPECT_TRUE(SecLogAdapter::isInitialized());
}

// ============================================================
// 模块 Logger 获取（CGW-SEC-DSN-CR-004 §启动与模块 Logger）
// ============================================================
TEST_F(SecLogAdapterTest, GetFacadeLogger) {
    auto logger = SecLogAdapter::facade();
    logger.info("test.event", "test message");
}

TEST_F(SecLogAdapterTest, GetSeedKeyLogger) {
    auto logger = SecLogAdapter::seed_key();
    logger.info("test.event", "test message");
}

TEST_F(SecLogAdapterTest, GetOtaSessionLogger) {
    auto logger = SecLogAdapter::ota_session();
    logger.info("test.event", "test message");
}

TEST_F(SecLogAdapterTest, GetRootStoreLogger) {
    auto logger = SecLogAdapter::root_store();
    logger.info("test.event", "test message");
}

TEST_F(SecLogAdapterTest, GetDeviceKeyLogger) {
    auto logger = SecLogAdapter::device_key();
    logger.info("test.event", "test message");
}

TEST_F(SecLogAdapterTest, GetSeAdapterLogger) {
    auto logger = SecLogAdapter::se_adapter();
    logger.info("test.event", "test message");
}

// ============================================================
// 字段类型验证
// ============================================================
TEST_F(SecLogAdapterTest, FieldTypesWork) {
    SecLogAdapter::facade().info("test.event",
        "Test field types",
        {slog::f_str("string_field", "value"),
         slog::f_int("int_field", 42),
         slog::f_bool("bool_field", true),
         slog::f_double("double_field", 3.14)}
    );
}

// ============================================================
// 敏感度级别验证（CGW-SEC-DSN-CR-004 §字段白名单与零泄露）
// ============================================================
TEST_F(SecLogAdapterTest, SensitivityLevelsWork) {
    SecLogAdapter::facade().info("test.event",
        "Test sensitivity levels",
        {slog::f_str("normal_field", "normal"),
         slog::f_str("identifier_field", "VIN123", cgw::fw::log::Sensitivity::Identifier),
         slog::f_str("payload_field", "raw_data", cgw::fw::log::Sensitivity::Payload),
         slog::f_str("secret_field", "secret", cgw::fw::log::Sensitivity::Secret)}
    );
}

// ============================================================
// 日志级别方法验证
// ============================================================
TEST_F(SecLogAdapterTest, LogLevelMethods) {
    auto logger = SecLogAdapter::facade();
    logger.trace("test.trace", "trace message");
    logger.debug("test.debug", "debug message");
    logger.info("test.info", "info message");
    logger.warn("test.warn", "warn message");
    logger.error("test.error", "error message");
}

// ============================================================
// ID 生成验证
// ============================================================
TEST_F(SecLogAdapterTest, GenerateTraceId) {
    std::string id1 = generate_trace_id();
    std::string id2 = generate_trace_id();

    EXPECT_NE(id1, id2);
    EXPECT_EQ(id1.substr(0, 10), "sec-trace-");
}

TEST_F(SecLogAdapterTest, GenerateRequestId) {
    std::string id1 = generate_request_id();
    std::string id2 = generate_request_id();

    EXPECT_NE(id1, id2);
    EXPECT_EQ(id1.substr(0, 8), "sec-req-");
}

// ============================================================
// 十六进制 ID 格式验证（CGW-FW-SPEC设计 §5.4）
// ============================================================
TEST_F(SecLogAdapterTest, HexIdFormatUint16) {
    EXPECT_EQ(hex_id(static_cast<uint16_t>(0x1140)), "0x1140");
    EXPECT_EQ(hex_id(static_cast<uint16_t>(0x0001)), "0x0001");
    EXPECT_EQ(hex_id(static_cast<uint16_t>(0xF190)), "0xf190");
}

TEST_F(SecLogAdapterTest, HexIdFormatUint8) {
    EXPECT_EQ(hex_id(static_cast<uint8_t>(0x22)), "0x22");
    EXPECT_EQ(hex_id(static_cast<uint8_t>(0x27)), "0x27");
    EXPECT_EQ(hex_id(static_cast<uint8_t>(0x7F)), "0x7f");
}

TEST_F(SecLogAdapterTest, FlushWorks) {
    auto logger = SecLogAdapter::facade();
    logger.info("test.before_flush", "Message before flush");
    logger.flush();
    logger.info("test.after_flush", "Message after flush");
}

} // namespace
} // namespace cgw_sec
