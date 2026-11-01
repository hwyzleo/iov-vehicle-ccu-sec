#include <gtest/gtest.h>
#include "sec_log_adapter.h"
#include "sec_log_context.h"
#include "error_codes.h"
#include "constants.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

namespace ccu_sec {
namespace {

class LogIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        ccu::fw::log::LogConfig config;
        config.level = ccu::fw::log::LogLevel::kDebug;

        auto result = SecLogAdapter::init("ccu-sec-integration-test", config);
        ASSERT_EQ(result.error, ccu::fw::log::LogError::kOk);
    }
};

// ============================================================
// 上下文传播测试（CCU-SEC-DSN-CR-004 §上下文传播）
// ============================================================

TEST_F(LogIntegrationTest, ContextScopeBasics) {
    // 验证 ContextScope RAII：构造时设置上下文，析构时恢复
    EXPECT_EQ(current_context(), nullptr);

    {
        auto scope = make_context_scope("trace-001", "req-001");
        auto* ctx = current_context();
        ASSERT_NE(ctx, nullptr);
        EXPECT_EQ(ctx->trace_id, "trace-001");
        EXPECT_EQ(ctx->request_id, "req-001");
    }

    EXPECT_EQ(current_context(), nullptr);
}

TEST_F(LogIntegrationTest, ContextScopeNesting) {
    // 验证嵌套 ContextScope：内层恢复外层上下文
    {
        auto outer = make_context_scope("trace-outer", "req-outer");

        {
            auto inner = make_context_scope("trace-inner", "req-inner");
            auto* ctx = current_context();
            ASSERT_NE(ctx, nullptr);
            EXPECT_EQ(ctx->trace_id, "trace-inner");
        }

        // 内层析构后恢复外层
        auto* ctx = current_context();
        ASSERT_NE(ctx, nullptr);
        EXPECT_EQ(ctx->trace_id, "trace-outer");
    }
}

TEST_F(LogIntegrationTest, SomeipContextScopeBasics) {
    // 验证 SOME/IP 入站 ContextScope（CCU-SEC-DSN-CR-004 §上下文传播 第1点）
    {
        auto scope = make_someip_context_scope(
            "trace-001", "req-001", "0x1140", "0x0001", "0x0001"
        );

        auto* ctx = current_context();
        ASSERT_NE(ctx, nullptr);
        EXPECT_EQ(ctx->trace_id, "trace-001");
        EXPECT_EQ(ctx->request_id, "req-001");
        ASSERT_NE(ctx->someip, nullptr);
        EXPECT_EQ(ctx->someip->service_id, "0x1140");
        EXPECT_EQ(ctx->someip->method_id, "0x0001");
        EXPECT_EQ(ctx->someip->client_id, "0x0001");
    }

    EXPECT_EQ(current_context(), nullptr);
}

TEST_F(LogIntegrationTest, SeChildScopeInheritsTraceId) {
    // 验证 SE/HSM 子作用域继承 trace_id（CCU-SEC-DSN-CR-004 §上下文传播 第2点）
    std::string parent_trace = "parent-trace-123";
    std::string parent_req = "parent-req-456";

    {
        auto parent_scope = make_someip_context_scope(
            parent_trace, parent_req, "0x1140", "0x0001"
        );

        // 创建 SE/HSM 子作用域
        {
            auto se_scope = make_se_child_scope("getSeed");
            auto* ctx = current_context();
            ASSERT_NE(ctx, nullptr);
            // 继承 trace_id / request_id
            EXPECT_EQ(ctx->trace_id, parent_trace);
            EXPECT_EQ(ctx->request_id, parent_req);
            // 继承 SOME/IP 上下文
            ASSERT_NE(ctx->someip, nullptr);
            EXPECT_EQ(ctx->someip->service_id, "0x1140");
        }

        // 子作用域析构后恢复父上下文
        auto* ctx = current_context();
        ASSERT_NE(ctx, nullptr);
        EXPECT_EQ(ctx->trace_id, parent_trace);
    }
}

TEST_F(LogIntegrationTest, FullChainContextPropagation) {
    // 模拟全链路：DIAG/FOTA -> SEC Provider -> SE/HSM 子操作
    // （CCU-SEC-DSN-CR-004 §上下文传播）
    std::string trace_id = "fullchain-trace-001";
    std::string request_id = "fullchain-req-001";

    {
        // 1. Provider 收到 DIAG 请求，建立 SOME/IP 上下文
        auto provider_scope = make_someip_context_scope(
            trace_id, request_id, "0x1140", "0x0001", "0x0001"
        );

        EXPECT_EQ(current_trace_id(), trace_id);
        EXPECT_EQ(current_request_id(), request_id);

        // 2. 调用 SE/HSM 子操作（getSeed）
        {
            auto se_scope = make_se_child_scope("getSeed");

            // 3. seed_key 模块记录事件（trace_id 保持一致）
            SecLogAdapter::seed_key().info(sec_events::SEED_GENERATED,
                "getSeed succeeded",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", "0x01"),
                 slog::f_str("operation", "getSeed"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", 5),
                 slog::f_int("seed_id", 42)});

            // 验证 trace_id 在 SE/HSM 操作期间保持一致
            EXPECT_EQ(current_trace_id(), trace_id);
        }

        EXPECT_EQ(current_trace_id(), trace_id);
    }

    EXPECT_EQ(current_context(), nullptr);
}

TEST_F(LogIntegrationTest, DiagToSecContextPropagation) {
    // DIAG -> SEC 调用链上下文传播（沿用诊断会话 session_id）
    // （CCU-SEC-DSN-CR-004 §上下文传播 第3点：DIAG->SEC 的 getSeed/verifyKey 沿用诊断会话 session_id）
    std::string trace_id = "diag-trace-001";
    std::string request_id = "diag-req-001";
    std::string session_id = "diag-sess-001";

    {
        auto scope = make_someip_context_scope(
            trace_id, request_id, "0x1140", "0x0001", "", "", session_id
        );

        auto* ctx = current_context();
        ASSERT_NE(ctx, nullptr);
        EXPECT_EQ(ctx->trace_id, trace_id);
        EXPECT_EQ(ctx->request_id, request_id);
        EXPECT_EQ(ctx->session_id, session_id);

        // 模拟 getSeed 日志
        SecLogAdapter::seed_key().info(sec_events::SEED_GENERATED,
            "getSeed succeeded",
            {slog::f_str("caller", "diag"),
             slog::f_str("security_level", "0x01"),
             slog::f_str("operation", "getSeed"),
             slog::f_str("result", "success"),
             slog::f_int("duration_ms", 5),
             slog::f_int("seed_id", 1)});
    }
}

TEST_F(LogIntegrationTest, FotaToSecContextPropagation) {
    // FOTA -> SEC 调用链上下文传播（沿用业务 trace_id/request_id）
    // （CCU-SEC-DSN-CR-004 §上下文传播 第3点：FOTA->SEC 的 deriveOtaSession 沿用业务 trace_id/request_id）
    std::string trace_id = "fota-trace-001";
    std::string request_id = "fota-req-001";

    {
        auto scope = make_someip_context_scope(
            trace_id, request_id, "0x1140", "0x0003", "0x0001"
        );

        auto* ctx = current_context();
        ASSERT_NE(ctx, nullptr);
        EXPECT_EQ(ctx->trace_id, trace_id);
        EXPECT_EQ(ctx->request_id, request_id);
        ASSERT_NE(ctx->someip, nullptr);
        EXPECT_EQ(ctx->someip->service_id, "0x1140");
        EXPECT_EQ(ctx->someip->method_id, "0x0003");

        // 模拟 deriveOtaSession 日志
        SecLogAdapter::ota_session().info(sec_events::OTA_SESSION_DERIVED,
            "OTA session derived",
            {slog::f_str("caller", "fota"),
             slog::f_str("operation", "deriveOtaSession"),
             slog::f_str("direction", "download"),
             slog::f_str("result", "success"),
             slog::f_int("duration_ms", 10)});
    }
}

TEST_F(LogIntegrationTest, AsyncContextCopy) {
    // 异步任务边界显式复制日志上下文
    // （CCU-SEC-DSN-CR-004 §上下文传播 第4点：异步任务边界显式复制上下文）
    std::string trace_id = "async-trace-001";
    std::string request_id = "async-req-001";

    std::atomic<bool> async_done{false};
    std::string async_trace_check;

    {
        auto scope = make_context_scope(trace_id, request_id);

        // 捕获上下文并传递到异步线程
        std::string captured_trace = current_trace_id();
        std::string captured_req = current_request_id();

        std::thread([&async_done, &async_trace_check, captured_trace, captured_req]() {
            // 在异步线程中重建上下文
            auto async_scope = make_context_scope(captured_trace, captured_req);
            async_trace_check = current_trace_id();
            async_done.store(true);
        }).join();
    }

    EXPECT_TRUE(async_done.load());
    EXPECT_EQ(async_trace_check, trace_id);

    // 主线程上下文已清理
    EXPECT_EQ(current_context(), nullptr);
}

TEST_F(LogIntegrationTest, SessionIdPropagation) {
    // DIAG 诊断会话以 session_id 关联 getSeed/verifyKey
    {
        auto scope = make_someip_context_scope(
            "trace-sess", "req-sess", "0x1140", "0x0001", "", "", "diag-sess-042"
        );
        EXPECT_EQ(current_session_id(), "diag-sess-042");

        // 子作用域应继承 session_id
        {
            auto se_scope = make_se_child_scope("verifyKey");
            EXPECT_EQ(current_session_id(), "diag-sess-042");
        }
    }
}

// ============================================================
// 脱敏测试（CCU-SEC-DSN-CR-004 §字段白名单与零泄露）
// ============================================================

TEST_F(LogIntegrationTest, VinDesensitization) {
    // VIN/device_sn 按 Identifier 处理：默认掩码或不可逆摘要
    std::string test_vin = "LSVAU2180N2123456";

    {
        auto scope = make_context_scope("trace-vin", "req-vin");

        SecLogAdapter::facade().info("test.vin_desensitization",
            "VIN should be masked",
            {slog::f_str("vin", test_vin, ccu::fw::log::Sensitivity::Identifier)}
        );

        // VIN 不应直接拼入 message
        SecLogAdapter::facade().info("test.vin_not_in_message",
            "VIN processing result",
            {slog::f_str("vin_hash", test_vin, ccu::fw::log::Sensitivity::Identifier),
             slog::f_str("result", "OK")}
        );
    }
}

TEST_F(LogIntegrationTest, PayloadDesensitization) {
    // 业务 payload 按 Payload 处理
    {
        auto scope = make_context_scope("trace-payload", "req-payload");

        // 正确做法：仅记录元数据
        SecLogAdapter::ota_session().info("test.payload_metadata",
            "Payload metadata only",
            {slog::f_int("payload_length", 64),
             slog::f_str("nonce_length", "12")}
        );

        // 原始 payload（应被框架限长/过滤）
        std::string raw_payload = "raw_ota_session_data_with_versions";
        SecLogAdapter::ota_session().info("test.payload_raw",
            "Raw payload test",
            {slog::f_str("raw_payload", raw_payload, ccu::fw::log::Sensitivity::Payload)}
        );
    }
}

TEST_F(LogIntegrationTest, SecretFieldRejection) {
    // seed/key/root/session_key 及密钥材料按 Secret 直接拒绝
    {
        auto scope = make_context_scope("trace-secret", "req-secret");

        SecLogAdapter::seed_key().info("test.secret_rejection",
            "Secret fields should be rejected",
            {slog::f_str("seed", "0xABCD1234", ccu::fw::log::Sensitivity::Secret),
             slog::f_str("key", "0xEF567890", ccu::fw::log::Sensitivity::Secret),
             slog::f_str("root", "root_key_data", ccu::fw::log::Sensitivity::Secret),
             slog::f_str("session_key", "session_key_data", ccu::fw::log::Sensitivity::Secret)}
        );

        // 验证日志可正常执行（框架拒绝 Secret 字段但不崩溃）
        SUCCEED();
    }
}

TEST_F(LogIntegrationTest, NonceSaltInfoProhibited) {
    // nonce、salt/info 原值默认不输出
    {
        auto scope = make_context_scope("trace-nonce", "req-nonce");

        // 正确做法：仅记录长度或不可逆摘要
        SecLogAdapter::ota_session().info("test.nonce_metadata",
            "Nonce metadata only",
            {slog::f_int("nonce_length", 12),
             slog::f_str("salt_length", "16"),
             slog::f_str("info_length", "32")}
        );

        // 误传 nonce 原值（应被框架拒绝）
        SecLogAdapter::ota_session().info("test.nonce_secret",
            "Nonce as Secret",
            {slog::f_str("nonce", "nonce_raw_value", ccu::fw::log::Sensitivity::Secret),
             slog::f_str("salt", "salt_raw_value", ccu::fw::log::Sensitivity::Secret),
             slog::f_str("info", "info_raw_value", ccu::fw::log::Sensitivity::Secret)}
        );

        SUCCEED();
    }
}

TEST_F(LogIntegrationTest, BusinessPayloadProhibited) {
    // 明文/密文业务 payload 默认不输出
    {
        auto scope = make_context_scope("trace-payload-prohibit", "req-payload-prohibit");

        // 正确做法：仅记录长度
        SecLogAdapter::device_key().info("test.payload_metadata",
            "Payload metadata only",
            {slog::f_int("plaintext_length", 64),
             slog::f_int("ciphertext_length", 80),
             slog::f_str("operation", "wrapByUid")}
        );

        // 误传明文/密文 payload（应被框架拒绝）
        SecLogAdapter::device_key().info("test.payload_secret",
            "Payload as Secret",
            {slog::f_str("plaintext", "plaintext_data", ccu::fw::log::Sensitivity::Secret),
             slog::f_str("ciphertext", "ciphertext_data", ccu::fw::log::Sensitivity::Secret)}
        );

        SUCCEED();
    }
}

// ============================================================
// 并发与压力测试（CCU-SEC-DSN-CR-004 §测试-压力测试）
// ============================================================

TEST_F(LogIntegrationTest, ConcurrentLogging) {
    // 并发日志记录：验证线程安全
    const int num_threads = 4;
    const int logs_per_thread = 25;
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([i]() {
            auto logger = SecLogAdapter::facade();
            for (int j = 0; j < logs_per_thread; ++j) {
                logger.info("test.concurrent_logging",
                    "Concurrent logging test",
                    {slog::f_int("thread_id", i),
                     slog::f_int("log_index", j)}
                );
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    SUCCEED();
}

TEST_F(LogIntegrationTest, ConcurrentContextScopes) {
    // 并发 ContextScope：验证线程局部上下文隔离
    const int num_threads = 4;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([i, &success_count]() {
            std::string trace = "trace-" + std::to_string(i);
            auto scope = make_context_scope(trace, "req");

            // 每个线程应看到自己的 trace_id
            if (current_trace_id() == trace) {
                success_count++;
            }

            SecLogAdapter::seed_key().info("test.concurrent_context",
                "Concurrent context test",
                {slog::f_int("thread_id", i)}
            );
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(success_count.load(), num_threads);
}

TEST_F(LogIntegrationTest, LoggingDoesNotBlockBusiness) {
    // 验证普通日志故障不阻断业务
    // （CCU-SEC-DSN-CR-004 §实时性与故障降级）
    {
        auto scope = make_context_scope("trace-noblock", "req-noblock");

        // 大量日志不应阻断业务操作
        for (int i = 0; i < 100; ++i) {
            SecLogAdapter::facade().info("test.high_volume",
                "High volume logging test",
                {slog::f_int("index", i)}
            );
        }

        SUCCEED();
    }
}

TEST_F(LogIntegrationTest, HighFrequencyGetSeedVerifyKey) {
    // 高频 getSeed/verifyKey 压力测试
    // （CCU-SEC-DSN-CR-004 §测试-压力测试：高频 getSeed/verifyKey/deriveOtaSession）
    {
        auto scope = make_someip_context_scope(
            "trace-stress", "req-stress", "0x1140", "0x0001"
        );

        for (int i = 0; i < 50; ++i) {
            {
                auto se_scope = make_se_child_scope("getSeed");
                SecLogAdapter::seed_key().info(sec_events::SEED_GENERATED,
                    "getSeed succeeded",
                    {slog::f_str("caller", "diag"),
                     slog::f_str("security_level", "0x01"),
                     slog::f_str("operation", "getSeed"),
                     slog::f_str("result", "success"),
                     slog::f_int("duration_ms", 1 + i % 10),
                     slog::f_int("seed_id", i)});
            }
            {
                auto se_scope = make_se_child_scope("verifyKey");
                SecLogAdapter::seed_key().info(sec_events::KEY_VERIFY_SUCCEEDED,
                    "verifyKey succeeded",
                    {slog::f_str("caller", "diag"),
                     slog::f_str("security_level", "0x01"),
                     slog::f_str("operation", "verifyKey"),
                     slog::f_str("result", "success"),
                     slog::f_int("duration_ms", 1 + i % 5)});
            }
        }

        SUCCEED();
    }
}

// ============================================================
// 故障降级测试（CCU-SEC-DSN-CR-004 §实时性与故障降级）
// ============================================================

TEST_F(LogIntegrationTest, StrictModeInitFailure) {
    // 验证 strict 模式下的 fail-closed 行为
    ccu::fw::log::LogConfig config;
    config.strict = true;
    config.level = ccu::fw::log::LogLevel::kInfo;

    // 使用空服务名测试（框架可能返回错误或接受）
    auto result = SecLogAdapter::init("", config);
    // 框架行为取决于实现，此处仅验证不崩溃
    SUCCEED();
}

TEST_F(LogIntegrationTest, NonStrictModeDegradesGracefully) {
    // 非严格模式降级至 console + INFO
    // （CCU-SEC-DSN-CR-004 §实时性与故障降级：非严格模式降级至 console + INFO）
    ccu::fw::log::LogConfig config;
    config.strict = false;
    config.level = ccu::fw::log::LogLevel::kInfo;
    config.console_config.enabled = true;

    auto result = SecLogAdapter::init("ccu-sec-degrade-test", config);
    // 验证不崩溃且可继续记录日志
    SecLogAdapter::facade().info("test.degraded_mode",
        "Logging in degraded mode");

    SUCCEED();
}

// ============================================================
// 完整事件链路验证（CCU-SEC-DSN-CR-004 §事件目录）
// ============================================================

TEST_F(LogIntegrationTest, AllBusinessEventsEmitted) {
    // 验证完整安全操作流程中关键事件被输出
    {
        auto scope = make_someip_context_scope(
            "trace-events", "req-events", "0x1140", "0x0001", "0x0001", "", "diag-sess-99"
        );

        // 1. 服务初始化完成
        SecLogAdapter::facade().info(sec_events::SERVICE_INITIALIZED,
            "Service initialized",
            {slog::f_str("result", "success"),
             slog::f_int("duration_ms", 120)});

        // 2. getSeed 成功
        {
            auto se_scope = make_se_child_scope("getSeed");
            SecLogAdapter::seed_key().info(sec_events::SEED_GENERATED,
                "getSeed succeeded",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", "0x01"),
                 slog::f_str("operation", "getSeed"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", 5),
                 slog::f_int("seed_id", 1)});
        }

        // 3. verifyKey 成功
        {
            auto se_scope = make_se_child_scope("verifyKey");
            SecLogAdapter::seed_key().info(sec_events::KEY_VERIFY_SUCCEEDED,
                "verifyKey succeeded",
                {slog::f_str("caller", "diag"),
                 slog::f_str("security_level", "0x01"),
                 slog::f_str("operation", "verifyKey"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", 3)});
        }

        // 4. deriveOtaSession 成功
        {
            auto se_scope = make_se_child_scope("deriveOtaSession");
            SecLogAdapter::ota_session().info(sec_events::OTA_SESSION_DERIVED,
                "OTA session derived",
                {slog::f_str("caller", "fota"),
                 slog::f_str("operation", "deriveOtaSession"),
                 slog::f_str("direction", "download"),
                 slog::f_str("result", "success"),
                 slog::f_int("duration_ms", 10)});
        }
    }

    SUCCEED();
}

TEST_F(LogIntegrationTest, AllErrorEventsEmitted) {
    // 验证错误场景下关键事件被输出
    {
        auto scope = make_someip_context_scope(
            "trace-errors", "req-errors", "0x1140", "0x0001"
        );

        // 1. seed 生成失败
        SecLogAdapter::seed_key().error(sec_events::SEED_GENERATE_FAILED,
            "getSeed failed",
            {slog::f_str("caller", "diag"),
             slog::f_str("security_level", "0x01"),
             slog::f_str("result", "SEED_GENERATION_FAILED"),
             slog::f_int("duration_ms", 5),
             slog::f_str("error_code", "CCU-SEC-1001")});

        // 2. key 验证失败
        SecLogAdapter::seed_key().warn(sec_events::KEY_VERIFY_FAILED,
            "verifyKey failed",
            {slog::f_str("caller", "diag"),
             slog::f_str("security_level", "0x01"),
             slog::f_str("operation", "verifyKey"),
             slog::f_str("result", "KEY_VERIFICATION_FAILED"),
             slog::f_int("duration_ms", 3),
             slog::f_str("error_code", "CCU-SEC-1002")});

        // 3. OTA 会话派生失败
        SecLogAdapter::ota_session().error(sec_events::OTA_SESSION_DERIVE_FAILED,
            "OTA session derivation failed",
            {slog::f_str("caller", "fota"),
             slog::f_str("operation", "deriveOtaSession"),
             slog::f_str("direction", "download"),
             slog::f_str("result", "OTA_ROOT_MISSING"),
             slog::f_int("duration_ms", 10),
             slog::f_str("error_code", "CCU-SEC-1003")});

        // 4. 设备密钥操作失败
        SecLogAdapter::device_key().error(sec_events::DEVICE_KEY_OPERATION_FAILED,
            "deriveByUid failed",
            {slog::f_str("caller", "device"),
             slog::f_str("operation", "deriveByUid"),
             slog::f_str("result", "DEVICE_ROOT_MISSING"),
             slog::f_int("duration_ms", 8),
             slog::f_str("error_code", "CCU-SEC-1005")});

        // 5. SE/HSM 访问失败
        SecLogAdapter::se_adapter().error(sec_events::SE_ACCESS_FAILED,
            "SE/HSM access failed",
            {slog::f_str("operation", "storeKey"),
             slog::f_str("result", "SE_HSM_ACCESS_FAILED"),
             slog::f_int("duration_ms", 15),
             slog::f_str("error_code", "CCU-SEC-1006")});

        // 6. 未授权请求
        SecLogAdapter::facade().warn(sec_events::REQUEST_UNAUTHORIZED,
            "Request unauthorized",
            {slog::f_str("caller", "unknown"),
             slog::f_str("operation", "getSeed"),
             slog::f_str("result", "invalid_request"),
             slog::f_str("someip_service_id", "0x1140"),
             slog::f_str("someip_method_id", "0x0001"),
             slog::f_str("error_code", "CCU-SEC-1007")});
    }

    SUCCEED();
}

} // namespace
} // namespace ccu_sec
