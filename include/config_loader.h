#pragma once

#include <string>
#include "data_models.h"
#include "log_types.h"
#include <yaml-cpp/yaml.h>

namespace cgw_sec {

class ConfigLoader {
public:
    static SecConfig loadSecConfig(const std::string& path);
    static SomeipConfig loadSomeipConfig(const std::string& path);
    static SeHsmConfig loadSeHsmConfig(const std::string& path);

    /// 加载结构化日志配置（common.log.* + sec.log.*）
    /// （CGW-SEC-DSN-CR-004 §启动与模块 Logger）
    static cgw::fw::log::LogConfig loadLogConfig(const std::string& path);

    /// 解析日志配置节点（供测试和组合使用）
    static void parseLogConfigNode(const YAML::Node& root,
                                   cgw::fw::log::LogConfig& log_config);
};

} // namespace cgw_sec
