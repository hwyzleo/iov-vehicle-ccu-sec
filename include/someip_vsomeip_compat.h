#pragma once

// =============================================================================
// include/someip_vsomeip_compat.h - vsomeip3 命名适配（TARGET readiness）
// =============================================================================
// vsomeip3（vsomeip_v3，经 vsomeip.hpp 别名 vsomeip）API 为小写类型
// （runtime/application/message/payload）与 MT_* 枚举成员；仓库共享代码按
// mock 命名（大写类型 + 无前缀枚举成员）编写。真实 vsomeip3 后端下，
// 共享代码继续使用 someip::Runtime/Application/Message 等名称。
// 本头文件仅用于非 mock（真实 vsomeip3）编译路径。
// =============================================================================

#include <vsomeip/vsomeip.hpp>

namespace someip {
    using Runtime     = ::vsomeip::runtime;
    using Application = ::vsomeip::application;
    using Message     = ::vsomeip::message;
    using Payload     = ::vsomeip::payload;
    using Request     = ::vsomeip::message;
    using service_t   = ::vsomeip::service_t;
    using instance_t  = ::vsomeip::instance_t;
    using method_t    = ::vsomeip::method_t;
    using session_t   = ::vsomeip::session_t;
    using client_t    = ::vsomeip::client_t;
    using message_type_e = ::vsomeip::message_type_e;
    using return_code_e  = ::vsomeip::return_code_e;
    constexpr method_t    ANY_METHOD    = ::vsomeip::ANY_METHOD;
    constexpr service_t   ANY_SERVICE   = ::vsomeip::ANY_SERVICE;
    constexpr instance_t  ANY_INSTANCE  = ::vsomeip::ANY_INSTANCE;
} // namespace someip
