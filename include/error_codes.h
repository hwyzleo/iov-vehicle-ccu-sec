#pragma once

#include <string>
#include <cstdint>
#include <ostream>

namespace cgw_sec {

enum class CgwSecErrorCode : uint32_t {
    SUCCESS = 0,
    SEED_GENERATION_FAILED = 1001,
    KEY_VERIFICATION_FAILED = 1002,
    OTA_ROOT_MISSING = 1003,
    SESSION_KEY_DERIVATION_FAILED = 1004,
    DEVICE_ROOT_MISSING = 1005,
    SE_HSM_ACCESS_FAILED = 1006,
    UNAUTHORIZED_REQUEST = 1007
};

std::string errorCodeToString(CgwSecErrorCode code);
std::string errorCodeDescription(CgwSecErrorCode code);

// 为枚举提供流输出运算符。
// 目的：让 GoogleTest 在断言失败时通过 operator<< 打印该枚举，
// 而不是回退到 RawBytesPrinter 的字节打印路径——后者在本环境的
// libc++/GTest ABI 组合下会触发 SEGV。
inline std::ostream& operator<<(std::ostream& os, CgwSecErrorCode code) {
    return os << errorCodeToString(code)
              << "(" << static_cast<uint32_t>(code) << ")";
}

} // namespace cgw_sec
