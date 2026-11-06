#pragma once

#include <string>
#include "data_models.h"
#include "log_types.h"
#include <yaml-cpp/yaml.h>

namespace ccu_sec {

// Unified production configuration loaded from /etc/ccu/conf.d/sec.yaml
// plus the BUILD-owned /etc/ccu/common.yaml (CCU-SEC-DSN-CR-005 §5).
struct UnifiedSecConfig {
    SecConfig security;
    SomeipConfig someip;
    SeHsmConfig se_hsm;
    ccu::fw::log::LogConfig log;
};

class ConfigLoader {
public:
    /// Production entry: unified sec: subtree + common.log.* from common.yaml.
    /// Fails closed on top-level common:, unknown/deprecated root nodes,
    /// secret/provisioning fields and unknown sec.* sub-keys; migrated legacy
    /// configuration is never silently ignored.
    static UnifiedSecConfig loadUnifiedConfig(
        const std::string& sec_config_path,
        const std::string& common_config_path);

    /// 解析日志配置节点（供测试和组合使用）
    /// common_root 提供 common.log.*，sec_root 提供 sec.log.*。
    static void parseLogConfigNode(const YAML::Node& root,
                                   ccu::fw::log::LogConfig& log_config);
};

} // namespace ccu_sec
