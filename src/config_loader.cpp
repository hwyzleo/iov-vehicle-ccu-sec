#include "config_loader.h"
#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace ccu_sec {

SecConfig ConfigLoader::loadSecConfig(const std::string& path) {
    try {
        YAML::Node config = YAML::LoadFile(path);
        SecConfig secConfig;

        if (config["se_hsm_type"]) {
            secConfig.seHsmType = config["se_hsm_type"].as<std::string>();
        }
        if (config["default_security_level"]) {
            secConfig.defaultSecurityLevel = config["default_security_level"].as<uint8_t>();
        }
        if (config["seed_expiration_ms"]) {
            secConfig.seedExpirationMs = config["seed_expiration_ms"].as<uint32_t>();
        }
        if (config["max_seed_pool_size"]) {
            secConfig.maxSeedPoolSize = config["max_seed_pool_size"].as<uint32_t>();
        }

        return secConfig;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load SEC config: " + std::string(e.what()));
    }
}

SomeipConfig ConfigLoader::loadSomeipConfig(const std::string& path) {
    try {
        YAML::Node config = YAML::LoadFile(path);
        SomeipConfig someipConfig;

        if (config["service_id"]) {
            someipConfig.serviceId = config["service_id"].as<uint16_t>();
        }
        if (config["instance_id"]) {
            someipConfig.instanceId = config["instance_id"].as<uint16_t>();
        }
        if (config["get_seed_method_id"]) {
            someipConfig.getSeedMethodId = config["get_seed_method_id"].as<uint16_t>();
        }
        if (config["verify_key_method_id"]) {
            someipConfig.verifyKeyMethodId = config["verify_key_method_id"].as<uint16_t>();
        }
        if (config["derive_ota_session_method_id"]) {
            someipConfig.deriveOtaSessionMethodId = config["derive_ota_session_method_id"].as<uint16_t>();
        }
        if (config["derive_by_uid_method_id"]) {
            someipConfig.deriveByUidMethodId = config["derive_by_uid_method_id"].as<uint16_t>();
        }
        if (config["wrap_by_uid_method_id"]) {
            someipConfig.wrapByUidMethodId = config["wrap_by_uid_method_id"].as<uint16_t>();
        }

        return someipConfig;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load SOME/IP config: " + std::string(e.what()));
    }
}

SeHsmConfig ConfigLoader::loadSeHsmConfig(const std::string& path) {
    try {
        YAML::Node config = YAML::LoadFile(path);
        SeHsmConfig seHsmConfig;

        if (config["type"]) {
            seHsmConfig.type = config["type"].as<std::string>();
        }
        if (config["storage_path"]) {
            seHsmConfig.storagePath = config["storage_path"].as<std::string>();
        }
        if (config["key_files"]) {
            YAML::Node keyFiles = config["key_files"];
            for (auto it = keyFiles.begin(); it != keyFiles.end(); ++it) {
                seHsmConfig.keyFiles[it->first.as<std::string>()] = it->second.as<std::string>();
            }
        }

        return seHsmConfig;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load SE/HSM config: " + std::string(e.what()));
    }
}

ccu::fw::log::LogConfig ConfigLoader::loadLogConfig(const std::string& path) {
    ccu::fw::log::LogConfig log_config;
    // 默认值
    log_config.schema_version = 1;
    log_config.level = ccu::fw::log::LogLevel::kInfo;
    log_config.strict = false;
    log_config.format = "standard";

    try {
        YAML::Node root = YAML::LoadFile(path);
        parseLogConfigNode(root, log_config);
    } catch (const YAML::Exception&) {
        // 配置加载失败时返回默认配置，由调用方决定是否严格模式终止
    }

    return log_config;
}

void ConfigLoader::parseLogConfigNode(const YAML::Node& root,
                                      ccu::fw::log::LogConfig& log_config) {
    // common.log.*
    if (root["common"] && root["common"]["log"]) {
        auto common_log = root["common"]["log"];

        if (common_log["schema_version"]) {
            log_config.schema_version = common_log["schema_version"].as<uint32_t>();
        }
        if (common_log["level"]) {
            log_config.level = ccu::fw::log::logLevelFromString(common_log["level"].as<std::string>());
        }
        if (common_log["strict"]) {
            log_config.strict = common_log["strict"].as<bool>();
        }
        if (common_log["format"]) {
            log_config.format = common_log["format"].as<std::string>();
        }

        // async
        if (common_log["async"]) {
            auto async = common_log["async"];
            if (async["enabled"]) {
                log_config.async_config.enabled = async["enabled"].as<bool>();
            }
            if (async["queue_size"]) {
                log_config.async_config.queue_size = async["queue_size"].as<uint32_t>();
            }
            if (async["flush_interval_ms"]) {
                log_config.async_config.flush_interval_ms = async["flush_interval_ms"].as<uint32_t>();
            }
        }

        // console
        if (common_log["console"]) {
            auto console = common_log["console"];
            if (console["enabled"]) {
                log_config.console_config.enabled = console["enabled"].as<bool>();
            }
        }

        // file
        if (common_log["file"]) {
            auto file = common_log["file"];
            if (file["enabled"]) {
                log_config.file_config.enabled = file["enabled"].as<bool>();
            }
            if (file["root"]) {
                log_config.file_config.root = file["root"].as<std::string>();
            }
            if (file["max_file_size_mb"]) {
                log_config.file_config.max_file_size_mb = file["max_file_size_mb"].as<uint32_t>();
            }
            if (file["max_files"]) {
                log_config.file_config.max_files = file["max_files"].as<uint32_t>();
            }
            if (file["total_budget_mb"]) {
                log_config.file_config.total_budget_mb = file["total_budget_mb"].as<uint32_t>();
            }
        }

        // redact
        if (common_log["redact"]) {
            auto redact = common_log["redact"];
            if (redact["identifiers"]) {
                log_config.redact_config.identifiers = redact["identifiers"].as<std::string>();
            }
            if (redact["payload_max_bytes"]) {
                log_config.redact_config.raw_payload_max_bytes = redact["payload_max_bytes"].as<uint32_t>();
            }
        }
    }

    // sec.log.* (service-level overrides)
    if (root["sec"] && root["sec"]["log"]) {
        auto sec_log = root["sec"]["log"];

        if (sec_log["level"]) {
            log_config.level = ccu::fw::log::logLevelFromString(sec_log["level"].as<std::string>());
        }

        // module-level overrides (CCU-SEC-DSN-CR-004 §启动与模块 Logger)
        if (sec_log["modules"]) {
            auto modules = sec_log["modules"];
            for (auto it = modules.begin(); it != modules.end(); ++it) {
                std::string mod_name = it->first.as<std::string>();
                std::string mod_level = it->second.as<std::string>();
                log_config.module_levels[mod_name] =
                    ccu::fw::log::logLevelFromString(mod_level);
            }
        }
    }
}

} // namespace ccu_sec
