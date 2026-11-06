#include <gtest/gtest.h>
#include <config_loader.h>
#include <constants.h>
#include <log_types.h>
#include <yaml-cpp/yaml.h>

#include <filesystem>
#include <fstream>
#include <set>
#include <string>

namespace ccu_sec {
namespace tests {

// Contract tests for the unified sec.yaml (CCU-SEC-DSN-CR-005 §5, §9):
//   * release template is a safe placeholder with Registry-anchored IDs
//   * dev fixture is value-equivalent to the pre-migration three-file layout
//     for every NON-SECRET field
//   * logical key names, error anchors and method IDs are unchanged
//   * migrated legacy files are rejected instead of silently ignored
//   * no secret/provisioning content or top-level common: is releaseable
class UnifiedConfigTest : public ::testing::Test {
protected:
    std::string sourceDir() const { return SOURCE_DIR; }
    std::string defaultPath() const { return sourceDir() + "/config/sec.default.yaml"; }
    std::string devPath() const { return sourceDir() + "/config/dev/sec.yaml"; }
    std::string devCommonPath() const { return sourceDir() + "/config/dev/common.yaml"; }
    std::string legacyDir() const { return sourceDir() + "/config/dev/legacy/"; }
};

TEST_F(UnifiedConfigTest, ReleaseDefaultIsSafePlaceholder) {
    UnifiedSecConfig config =
        ConfigLoader::loadUnifiedConfig(defaultPath(), devCommonPath());

    // Safe install placeholder: unconfigured is NOT a software fallback.
    EXPECT_EQ(config.se_hsm.type, "unconfigured");
    EXPECT_TRUE(config.se_hsm.adapter.empty());

    // Registry SSOT unchanged by the migration.
    EXPECT_EQ(config.someip.applicationName, "ccu-sec");
    EXPECT_EQ(config.someip.serviceId, SEC_SERVICE_ID);
    EXPECT_EQ(config.someip.instanceId, SEC_INSTANCE_ID);
    EXPECT_EQ(config.someip.endpointPort, SEC_SOMEIP_PORT);
    EXPECT_EQ(config.someip.endpointProtocol, "TCP");

    // Security parameters unchanged.
    EXPECT_EQ(config.security.defaultSecurityLevel, 1);
    EXPECT_EQ(config.security.seedExpirationMs, 30000u);
    EXPECT_EQ(config.security.maxSeedPoolSize, 100u);
}

TEST_F(UnifiedConfigTest, MethodIdsStayUniqueInsideMethodSegment) {
    UnifiedSecConfig config =
        ConfigLoader::loadUnifiedConfig(defaultPath(), devCommonPath());

    const uint16_t method_ids[] = {
        config.someip.getSeedMethodId,
        config.someip.verifyKeyMethodId,
        config.someip.deriveOtaSessionMethodId,
        config.someip.deriveByUidMethodId,
        config.someip.wrapByUidMethodId,
    };
    std::set<uint16_t> unique_ids;
    for (uint16_t method_id : method_ids) {
        EXPECT_GE(method_id, METHOD_ID_MIN);
        EXPECT_LE(method_id, METHOD_ID_MAX);
        EXPECT_TRUE(unique_ids.insert(method_id).second)
            << "duplicate method_id " << method_id;
    }

    EXPECT_EQ(config.someip.getSeedMethodId, METHOD_GET_SEED);
    EXPECT_EQ(config.someip.verifyKeyMethodId, METHOD_VERIFY_KEY);
    EXPECT_EQ(config.someip.deriveOtaSessionMethodId, METHOD_DERIVE_OTA_SESSION);
    EXPECT_EQ(config.someip.deriveByUidMethodId, METHOD_DERIVE_BY_UID);
    EXPECT_EQ(config.someip.wrapByUidMethodId, METHOD_WRAP_BY_UID);
}

TEST_F(UnifiedConfigTest, LogicalKeyNamesAreUnchanged) {
    // These are security-contract anchors (CCU-SEC-BUILD-REQ-005): the
    // release YAML only references logical identifiers, never key values.
    EXPECT_STREQ(OTA_VEHICLE_ROOT_KEY_NAME, "OTA_VEHICLE_ROOT");
    EXPECT_STREQ(CCU_DEVICE_ROOT_KEY_NAME, "CCU_DEVICE_ROOT");
    EXPECT_STREQ(DIAG_SEEDKEY_SECRET_NAME, "DIAG_SEEDKEY_SECRET");
}

TEST_F(UnifiedConfigTest, DevFixtureMatchesLegacyNonSecretValues) {
    UnifiedSecConfig config =
        ConfigLoader::loadUnifiedConfig(devPath(), devCommonPath());

    // --- legacy sec_config.yaml (security + adapter type + log) ---
    YAML::Node legacy_sec =
        YAML::LoadFile(legacyDir() + "sec_config.yaml");
    EXPECT_EQ(config.security.defaultSecurityLevel,
              legacy_sec["default_security_level"].as<uint8_t>());
    EXPECT_EQ(config.security.seedExpirationMs,
              legacy_sec["seed_expiration_ms"].as<uint32_t>());
    EXPECT_EQ(config.security.maxSeedPoolSize,
              legacy_sec["max_seed_pool_size"].as<uint32_t>());
    EXPECT_EQ(config.se_hsm.type, legacy_sec["se_hsm_type"].as<std::string>());

    // --- legacy someip_config.yaml (IDs, endpoint, SD) ---
    YAML::Node legacy_someip =
        YAML::LoadFile(legacyDir() + "someip_config.yaml");
    EXPECT_EQ(config.someip.serviceId,
              legacy_someip["service_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.instanceId,
              legacy_someip["instance_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.getSeedMethodId,
              legacy_someip["get_seed_method_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.verifyKeyMethodId,
              legacy_someip["verify_key_method_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.deriveOtaSessionMethodId,
              legacy_someip["derive_ota_session_method_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.deriveByUidMethodId,
              legacy_someip["derive_by_uid_method_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.wrapByUidMethodId,
              legacy_someip["wrap_by_uid_method_id"].as<uint16_t>());
    EXPECT_EQ(config.someip.endpointPort,
              legacy_someip["endpoint"]["port"].as<uint16_t>());
    EXPECT_EQ(config.someip.endpointProtocol,
              legacy_someip["endpoint"]["protocol"].as<std::string>());
    EXPECT_EQ(config.someip.endpointUnicast,
              legacy_someip["endpoint"]["unicast"].as<std::string>());
    EXPECT_EQ(config.someip.serviceDiscoveryEnabled,
              legacy_someip["service_discovery"]["enabled"].as<bool>());
    EXPECT_EQ(config.someip.serviceDiscoveryMode,
              legacy_someip["service_discovery"]["mode"].as<std::string>());
    EXPECT_EQ(config.someip.serviceDiscoveryMulticastAddress,
              legacy_someip["service_discovery"]["multicast_address"].as<std::string>());
    EXPECT_EQ(config.someip.serviceDiscoveryPort,
              legacy_someip["service_discovery"]["port"].as<uint16_t>());

    // --- legacy se_hsm_config.yaml: only the non-secret type migrates ---
    YAML::Node legacy_se_hsm =
        YAML::LoadFile(legacyDir() + "se_hsm_config.yaml");
    EXPECT_EQ(config.se_hsm.type, legacy_se_hsm["type"].as<std::string>());
    EXPECT_TRUE(config.se_hsm.adapter.empty());

    // --- log: sec.log.* override plus BUILD-style common.log.* -----------
    const std::string legacy_level =
        legacy_sec["sec"]["log"]["level"].as<std::string>();
    EXPECT_EQ(config.log.level, ccu::fw::log::logLevelFromString(legacy_level));

    const YAML::Node legacy_modules = legacy_sec["sec"]["log"]["modules"];
    for (auto it = legacy_modules.begin(); it != legacy_modules.end(); ++it) {
        const std::string name = it->first.as<std::string>();
        const std::string level = it->second.as<std::string>();
        ASSERT_EQ(config.log.module_levels.count(name), 1u) << name;
        EXPECT_EQ(config.log.module_levels.at(name),
                  ccu::fw::log::logLevelFromString(level)) << name;
    }

    // Dev common.yaml stands in for BUILD /etc/ccu/common.yaml.
    YAML::Node dev_common = YAML::LoadFile(devCommonPath());
    const YAML::Node common_log = dev_common["common"]["log"];
    EXPECT_EQ(config.log.schema_version, common_log["schema_version"].as<uint32_t>());
    EXPECT_EQ(config.log.strict, common_log["strict"].as<bool>());
    EXPECT_EQ(config.log.format, common_log["format"].as<std::string>());
    EXPECT_EQ(config.log.async_config.queue_size,
              common_log["async"]["queue_size"].as<uint32_t>());
    EXPECT_EQ(config.log.async_config.flush_interval_ms,
              common_log["async"]["flush_interval_ms"].as<uint32_t>());
    EXPECT_EQ(config.log.redact_config.raw_payload_max_bytes,
              common_log["redact"]["payload_max_bytes"].as<uint32_t>());
    EXPECT_EQ(config.log.redact_config.identifiers,
              common_log["redact"]["identifiers"].as<std::string>());
}

TEST_F(UnifiedConfigTest, LegacyFilesAreRejectedAfterMigration) {
    // Any pre-migration file passed to the unified loader must fail instead of
    // silently dropping security-relevant configuration.
    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(
                     legacyDir() + "sec_config.yaml", devCommonPath()),
                 std::runtime_error);
    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(
                     legacyDir() + "someip_config.yaml", devCommonPath()),
                 std::runtime_error);
    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(
                     legacyDir() + "se_hsm_config.yaml", devCommonPath()),
                 std::runtime_error);
}

TEST_F(UnifiedConfigTest, ReleaseTemplatesContainNoSecretOrProvisioningContent) {
    const std::string forbidden_tokens[] = {
        "key_files",
        "storage_path",
        "/tmp/ccu_sec_se_hsm",
        "OTA_VEHICLE_ROOT",
        "CCU_DEVICE_ROOT",
        "DIAG_SEEDKEY_SECRET",
        "session_key",
        "private_key",
        "provisioning",
    };

    for (const std::string& rel : {std::string("/config/sec.default.yaml"),
                                   std::string("/config/dev/sec.yaml")}) {
        std::ifstream file(sourceDir() + rel);
        ASSERT_TRUE(file.is_open()) << rel;

        // Only configuration keys/values are checked; comments may document
        // the forbidden fields they are warning about.
        std::string keys_only;
        std::string line;
        while (std::getline(file, line)) {
            const std::size_t first = line.find_first_not_of(" \t");
            if (first == std::string::npos || line[first] == '#') {
                continue;
            }
            keys_only += line + "\n";
        }
        for (const std::string& token : forbidden_tokens) {
            EXPECT_EQ(keys_only.find(token), std::string::npos)
                << rel << " must not contain '" << token << "'";
        }
        // A top-level common: block is never allowed in the service file.
        EXPECT_EQ(keys_only.find("common:"), std::string::npos) << rel;
    }
}

} // namespace tests
} // namespace ccu_sec
