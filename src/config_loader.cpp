#include "config_loader.h"
#include "constants.h"
#include <yaml-cpp/yaml.h>
#include <stdexcept>
#include <initializer_list>
#include <string>

namespace ccu_sec {

namespace {

YAML::Node loadYamlFile(const std::string& file_path, const char* what) {
    try {
        return YAML::LoadFile(file_path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error(
            "Failed to load " + std::string(what) + " (" + file_path + "): " +
            std::string(e.what()));
    }
}

void requireMap(const YAML::Node& node, const std::string& context) {
    if (!node.IsMap()) {
        throw std::runtime_error(context + " must be a mapping");
    }
}

void rejectUnknownKeys(const YAML::Node& node,
                       std::initializer_list<const char*> allowed,
                       const std::string& context) {
    requireMap(node, context);
    for (auto it = node.begin(); it != node.end(); ++it) {
        const std::string key = it->first.as<std::string>();
        bool ok = false;
        for (const char* candidate : allowed) {
            if (key == candidate) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            throw std::runtime_error("unknown config key: " + context + "." + key);
        }
    }
}

void requireMethodIdRange(uint16_t method_id, const std::string& context) {
    if (method_id < METHOD_ID_MIN || method_id > METHOD_ID_MAX) {
        throw std::runtime_error(
            context + " must be in 0x0001-0x7FFF (method segment)");
    }
}

uint16_t parseMethodId(const YAML::Node& methods,
                       const char* name,
                       uint16_t fallback,
                       const std::string& context) {
    const YAML::Node entry = methods[name];
    if (!entry) {
        return fallback;
    }
    requireMap(entry, context + "." + name);
    rejectUnknownKeys(entry, {"method_id"}, context + "." + name);
    if (!entry["method_id"]) {
        throw std::runtime_error(context + "." + name + ".method_id is required");
    }
    const uint16_t method_id = entry["method_id"].as<uint16_t>();
    requireMethodIdRange(method_id, context + "." + name + ".method_id");
    return method_id;
}

// CCU-SEC-DSN-CR-005 §5.3: release config must never carry secret/
// provisioning fields or a plain-file key mapping bypass.
bool isForbiddenConfigKey(const std::string& key) {
    static const char* const kForbidden[] = {
        "key_files", "key_file", "keyfiles", "storage_path",
        "storage-path", "secret", "secrets", "seed", "session_key",
        "session-key", "private_key", "private-key", "key_material",
        "token", "password", "credentials", "cert", "certificate",
        "provisioning",
    };
    for (const char* forbidden : kForbidden) {
        if (key == forbidden) {
            return true;
        }
    }
    return false;
}

// /tmp must never be proposed as a production security store.
bool isForbiddenStorageLocation(const std::string& value) {
    return value == "/tmp" || value.rfind("/tmp/", 0) == 0;
}

} // namespace

UnifiedSecConfig ConfigLoader::loadUnifiedConfig(
    const std::string& sec_config_path,
    const std::string& common_config_path) {

    YAML::Node root = loadYamlFile(sec_config_path, "unified SEC config");
    requireMap(root, "unified SEC config");

    // CCU-SEC-BUILD-REQ-003: the service file must never inline common:.
    if (root["common"]) {
        throw std::runtime_error(
            "unified SEC config must not declare a top-level 'common:' key "
            "(common.log.* is provided by CCU-BUILD /etc/ccu/common.yaml)");
    }
    // Only sec: is allowed; pre-migration root nodes (se_hsm_type,
    // service_id, type, key_files, ...) are rejected instead of being
    // silently ignored after migration.
    rejectUnknownKeys(root, {"sec"}, "sec.yaml");

    const YAML::Node sec = root["sec"];
    if (!sec) {
        throw std::runtime_error("unified SEC config is missing required 'sec:' root");
    }
    rejectUnknownKeys(sec, {"log", "security", "someip", "se_hsm"}, "sec");

    UnifiedSecConfig config;

    // ---------------------------------------------------------------
    // sec.security - security parameters (CCU-SEC-DSN-CR-005 §5.1)
    // ---------------------------------------------------------------
    config.security.defaultSecurityLevel = SECURITY_LEVEL_1;
    config.security.seedExpirationMs = SEED_EXPIRATION_MS;
    config.security.maxSeedPoolSize = MAX_SEED_POOL_SIZE;
    if (const YAML::Node security = sec["security"]) {
        rejectUnknownKeys(security,
                          {"default_security_level", "seed_expiration_ms",
                           "max_seed_pool_size"},
                          "sec.security");
        config.security.defaultSecurityLevel =
            security["default_security_level"].as<uint8_t>(
                config.security.defaultSecurityLevel);
        config.security.seedExpirationMs =
            security["seed_expiration_ms"].as<uint32_t>(
                config.security.seedExpirationMs);
        config.security.maxSeedPoolSize =
            security["max_seed_pool_size"].as<uint32_t>(
                config.security.maxSeedPoolSize);
    }

    // ---------------------------------------------------------------
    // sec.someip - provider parameters; IDs stay anchored to the Registry
    // ---------------------------------------------------------------
    config.someip.applicationName = SEC_APPLICATION_NAME;
    config.someip.serviceId = SEC_SERVICE_ID;
    config.someip.instanceId = SEC_INSTANCE_ID;
    config.someip.getSeedMethodId = METHOD_GET_SEED;
    config.someip.verifyKeyMethodId = METHOD_VERIFY_KEY;
    config.someip.deriveOtaSessionMethodId = METHOD_DERIVE_OTA_SESSION;
    config.someip.deriveByUidMethodId = METHOD_DERIVE_BY_UID;
    config.someip.wrapByUidMethodId = METHOD_WRAP_BY_UID;
    config.someip.endpointPort = SEC_SOMEIP_PORT;
    config.someip.endpointProtocol = SEC_SOMEIP_PROTOCOL;

    if (const YAML::Node someip = sec["someip"]) {
        rejectUnknownKeys(someip,
                          {"application_name", "service_id", "instance_id",
                           "methods", "endpoint", "service_discovery"},
                          "sec.someip");

        config.someip.applicationName =
            someip["application_name"].as<std::string>(
                config.someip.applicationName);
        if (!config.someip.applicationName.empty() &&
            config.someip.applicationName != SEC_APPLICATION_NAME) {
            throw std::runtime_error(
                "sec.someip.application_name must stay '" +
                std::string(SEC_APPLICATION_NAME) +
                "' (one process uses one vsomeip application)");
        }
        config.someip.serviceId =
            someip["service_id"].as<uint16_t>(config.someip.serviceId);
        config.someip.instanceId =
            someip["instance_id"].as<uint16_t>(config.someip.instanceId);

        if (const YAML::Node methods = someip["methods"]) {
            rejectUnknownKeys(methods,
                              {"get_seed", "verify_key", "derive_ota_session",
                               "derive_by_uid", "wrap_by_uid"},
                              "sec.someip.methods");
            config.someip.getSeedMethodId = parseMethodId(
                methods, "get_seed", config.someip.getSeedMethodId,
                "sec.someip.methods");
            config.someip.verifyKeyMethodId = parseMethodId(
                methods, "verify_key", config.someip.verifyKeyMethodId,
                "sec.someip.methods");
            config.someip.deriveOtaSessionMethodId = parseMethodId(
                methods, "derive_ota_session",
                config.someip.deriveOtaSessionMethodId,
                "sec.someip.methods");
            config.someip.deriveByUidMethodId = parseMethodId(
                methods, "derive_by_uid", config.someip.deriveByUidMethodId,
                "sec.someip.methods");
            config.someip.wrapByUidMethodId = parseMethodId(
                methods, "wrap_by_uid", config.someip.wrapByUidMethodId,
                "sec.someip.methods");
        }

        if (const YAML::Node endpoint = someip["endpoint"]) {
            rejectUnknownKeys(endpoint, {"port", "protocol", "unicast"},
                              "sec.someip.endpoint");
            config.someip.endpointPort =
                endpoint["port"].as<uint16_t>(config.someip.endpointPort);
            config.someip.endpointProtocol =
                endpoint["protocol"].as<std::string>(
                    config.someip.endpointProtocol);
            config.someip.endpointUnicast =
                endpoint["unicast"].as<std::string>(
                    config.someip.endpointUnicast);
            if (config.someip.endpointProtocol != "TCP" &&
                config.someip.endpointProtocol != "UDP") {
                throw std::runtime_error(
                    "sec.someip.endpoint.protocol must be TCP or UDP");
            }
        }

        if (const YAML::Node sd = someip["service_discovery"]) {
            rejectUnknownKeys(sd,
                              {"enabled", "mode", "multicast_address", "port"},
                              "sec.someip.service_discovery");
            config.someip.serviceDiscoveryEnabled =
                sd["enabled"].as<bool>(config.someip.serviceDiscoveryEnabled);
            config.someip.serviceDiscoveryMode =
                sd["mode"].as<std::string>(config.someip.serviceDiscoveryMode);
            config.someip.serviceDiscoveryMulticastAddress =
                sd["multicast_address"].as<std::string>(
                    config.someip.serviceDiscoveryMulticastAddress);
            config.someip.serviceDiscoveryPort =
                sd["port"].as<uint16_t>(config.someip.serviceDiscoveryPort);
            if (!config.someip.serviceDiscoveryMode.empty() &&
                config.someip.serviceDiscoveryMode != "static" &&
                config.someip.serviceDiscoveryMode != "dynamic") {
                throw std::runtime_error(
                    "sec.someip.service_discovery.mode must be static or dynamic");
            }
        }
    }

    // ---------------------------------------------------------------
    // sec.se_hsm - adapter selection; no secret material is ever parsed
    // ---------------------------------------------------------------
    config.se_hsm.type = "unconfigured";
    if (const YAML::Node se_hsm = sec["se_hsm"]) {
        rejectUnknownKeys(se_hsm, {"type", "adapter"}, "sec.se_hsm");
        config.se_hsm.type = se_hsm["type"].as<std::string>(config.se_hsm.type);
        if (config.se_hsm.type.empty()) {
            throw std::runtime_error("sec.se_hsm.type must not be empty");
        }
        if (isForbiddenConfigKey(config.se_hsm.type) ||
            config.se_hsm.type.find('/') != std::string::npos) {
            throw std::runtime_error(
                "sec.se_hsm.type must not reference key files or paths");
        }
        if (const YAML::Node adapter = se_hsm["adapter"]) {
            requireMap(adapter, "sec.se_hsm.adapter");
            for (auto it = adapter.begin(); it != adapter.end(); ++it) {
                const std::string key = it->first.as<std::string>();
                if (isForbiddenConfigKey(key)) {
                    throw std::runtime_error(
                        "sec.se_hsm.adapter." + key +
                        " is a secret/provisioning field and must not be released");
                }
                const YAML::Node value = it->second;
                if (!value.IsScalar()) {
                    throw std::runtime_error(
                        "sec.se_hsm.adapter." + key +
                        " must be a non-secret scalar value");
                }
                const std::string text = value.as<std::string>();
                if (isForbiddenStorageLocation(text)) {
                    throw std::runtime_error(
                        "sec.se_hsm.adapter." + key +
                        " must not use /tmp as a security store");
                }
                config.se_hsm.adapter[key] = text;
            }
        }
    }

    // ---------------------------------------------------------------
    // Logging: common.log.* from BUILD common.yaml, sec.log.* overrides
    // from the unified service file. No second deep-merge algorithm.
    // ---------------------------------------------------------------
    YAML::Node common_root = loadYamlFile(common_config_path, "common config");
    requireMap(common_root, "common config");

    config.log.schema_version = 1;
    config.log.level = ccu::fw::log::LogLevel::kInfo;
    config.log.strict = false;
    config.log.format = "standard";
    parseLogConfigNode(common_root, config.log);
    parseLogConfigNode(root, config.log);

    return config;
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
