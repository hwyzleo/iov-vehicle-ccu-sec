#include "sec_log_context.h"
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

namespace ccu_sec {

ccu::fw::log::ContextScope make_context_scope(
    const std::string& trace_id,
    const std::string& request_id,
    const std::string& session_id
) {
    ccu::fw::log::LogContext ctx;
    ctx.trace_id = trace_id;
    ctx.request_id = request_id;
    ctx.session_id = session_id;
    return ccu::fw::log::ContextScope(std::move(ctx));
}

ccu::fw::log::ContextScope make_someip_context_scope(
    const std::string& trace_id,
    const std::string& request_id,
    const std::string& service_id,
    const std::string& method_id,
    const std::string& client_id,
    const std::string& remote_endpoint,
    const std::string& session_id
) {
    ccu::fw::log::LogContext ctx;
    ctx.trace_id = trace_id;
    ctx.request_id = request_id;
    ctx.session_id = session_id;

    // 附加 SOME/IP 入站上下文（Service 0x1140、Method ID、调用方）
    // （CCU-SEC-DSN-CR-004 §上下文传播 第1点）
    ctx.someip = std::make_unique<ccu::fw::log::SomeIpContext>();
    ctx.someip->service_id = service_id;
    ctx.someip->method_id = method_id;
    ctx.someip->client_id = client_id;
    ctx.someip->remote_endpoint = remote_endpoint;

    return ccu::fw::log::ContextScope(std::move(ctx));
}

ccu::fw::log::ContextScope make_se_child_scope(
    const std::string& operation
) {
    ccu::fw::log::LogContext ctx;

    // 继承当前上下文的 trace_id / request_id / session_id
    // （CCU-SEC-DSN-CR-004 §上下文传播 第2点：调用 SE/HSM 时创建子作用域，继承链路上下文）
    const auto* current = ccu::fw::log::ContextScope::current();
    if (current) {
        ctx.trace_id = current->trace_id;
        ctx.request_id = current->request_id;
        ctx.session_id = current->session_id;
        // 继承上层 SOME/IP 上下文（Provider 入站）
        if (current->someip) {
            ctx.someip = std::make_unique<ccu::fw::log::SomeIpContext>(*current->someip);
        }
    }

    // 附加 operation 到 SOME/IP 上下文的 method_id 字段位置（复用现有结构）
    // operation 不携带密钥材料，仅用于关联 SE/HSM 操作类型
    if (!ctx.someip) {
        ctx.someip = std::make_unique<ccu::fw::log::SomeIpContext>();
    }
    // 将 operation 记录在 remote_endpoint 中作为子操作标识（不覆盖原有 service/method）
    // 注意：operation 字段不包含密钥材料
    if (!operation.empty()) {
        ctx.someip->remote_endpoint = operation;
    }

    return ccu::fw::log::ContextScope(std::move(ctx));
}

std::string generate_trace_id() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    std::ostringstream oss;
    oss << "sec-trace-" << timestamp << "-" << dis(gen);
    return oss.str();
}

std::string generate_request_id() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    std::ostringstream oss;
    oss << "sec-req-" << timestamp << "-" << dis(gen);
    return oss.str();
}

} // namespace ccu_sec
