#pragma once

/**
 * CCU-SEC 上下文传播辅助
 *
 * 使用 ccu-framework-log 提供的 ContextScope 和 LogContext
 * 实现 trace_id / request_id / session_id 跨 SOME/IP 调用链与
 * SE/HSM 子操作的传播（CCU-SEC-DSN-CR-004 §上下文传播）
 *
 * 传播规则：
 * 1. SOME/IP Provider 收到 DIAG/FOTA 请求时建立 ContextScope，
 *    记录 Service 0x1140、Method ID、调用方、trace_id/request_id/session_id。
 * 2. 调用 SE/HSM 时创建子作用域，继承链路上下文并附加 operation。
 * 3. DIAG->SEC 的 getSeed/verifyKey 沿用诊断会话 session_id；
 *    FOTA->SEC 的 deriveOtaSession 沿用业务 trace_id/request_id。
 * 4. 异步任务边界显式复制上下文；不得在上下文对象中携带 seed、key、
 *    root 或会话密钥材料。
 */

#include "log.h"
#include "log_types.h"
#include <string>
#include <sstream>
#include <iomanip>

namespace ccu_sec {

/// 创建顶层 ContextScope 的便捷函数
/// 用法：auto scope = make_context_scope(trace_id, request_id);
[[nodiscard]] ccu::fw::log::ContextScope make_context_scope(
    const std::string& trace_id,
    const std::string& request_id,
    const std::string& session_id = ""
);

/// 创建带 SOME/IP 上下文的顶层 ContextScope（用于 Provider 收到入站请求时）
/// （CCU-SEC-DSN-CR-004 §上下文传播 第1点：SOME/IP Provider 收到 DIAG/FOTA 请求时建立 ContextScope）
[[nodiscard]] ccu::fw::log::ContextScope make_someip_context_scope(
    const std::string& trace_id,
    const std::string& request_id,
    const std::string& service_id,
    const std::string& method_id,
    const std::string& client_id = "",
    const std::string& remote_endpoint = "",
    const std::string& session_id = ""
);

/// 创建 SE/HSM 子作用域（继承当前上下文的 trace_id/request_id/session_id，附加 operation）
/// （CCU-SEC-DSN-CR-004 §上下文传播 第2点：调用 SE/HSM 时创建子作用域）
[[nodiscard]] ccu::fw::log::ContextScope make_se_child_scope(
    const std::string& operation
);

/// 生成 trace ID（格式: sec-trace-<timestamp>-<random>）
std::string generate_trace_id();

/// 生成 request ID（格式: sec-req-<timestamp>-<random>）
std::string generate_request_id();

/// 获取当前上下文（便捷封装）
inline const ccu::fw::log::LogContext* current_context() {
    return ccu::fw::log::ContextScope::current();
}

/// 从当前上下文获取 trace_id
inline std::string current_trace_id() {
    const auto* ctx = ccu::fw::log::ContextScope::current();
    return ctx ? ctx->trace_id : "";
}

/// 从当前上下文获取 request_id
inline std::string current_request_id() {
    const auto* ctx = ccu::fw::log::ContextScope::current();
    return ctx ? ctx->request_id : "";
}

/// 从当前上下文获取 session_id
inline std::string current_session_id() {
    const auto* ctx = ccu::fw::log::ContextScope::current();
    return ctx ? ctx->session_id : "";
}

/// 将 uint16_t 格式为规范十六进制字符串（如 0x1140）
/// （CCU-FW-SPEC设计 §5.4: 规范十六进制字符串）
inline std::string hex_id(uint16_t id) {
    std::ostringstream oss;
    oss << "0x" << std::setfill('0') << std::setw(4) << std::hex << id;
    return oss.str();
}

/// 将 uint8_t 格式为规范十六进制字符串（如 0x22）
inline std::string hex_id(uint8_t id) {
    std::ostringstream oss;
    oss << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(id);
    return oss.str();
}

} // namespace ccu_sec
