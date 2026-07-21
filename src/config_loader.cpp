#include "config_loader.h"
#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace cgw_sec {

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

} // namespace cgw_sec
