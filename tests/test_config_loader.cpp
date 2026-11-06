#include <gtest/gtest.h>
#include "config_loader.h"
#include "constants.h"
#include <filesystem>
#include <fstream>
#include <string>

using namespace ccu_sec;

// Low-level unified loader contract (CCU-SEC-DSN-CR-005 §5.3/§5.4).
// Real release/dev fixture equivalence and cross-field ID checks live in
// tests/test_unified_config.cpp; fail-closed service behavior lives in
// tests/test_fail_closed.cpp.
class ConfigLoaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        temp_dir_ = std::filesystem::temp_directory_path() / "ccu_sec_config_loader_test";
        std::filesystem::remove_all(temp_dir_);
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override {
        std::filesystem::remove_all(temp_dir_);
    }

    std::filesystem::path secPath() const { return temp_dir_ / "sec.yaml"; }
    std::filesystem::path commonPath() const { return temp_dir_ / "common.yaml"; }

    void writeFile(const std::filesystem::path& path, const std::string& content) {
        std::ofstream file(path);
        file << content;
        file.close();
    }

    void writeCommon(const std::string& level = "WARN") {
        writeFile(commonPath(), "common:\n  log:\n    level: " + level +
                                "\n    strict: true\n    format: json\n");
    }

    // Minimal valid platform-style unified config (dev fixtures enable the
    // non-production software adapter explicitly).
    void writeUnified(const std::string& method_seed = "0x0001",
                      const std::string& protocol = "TCP",
                      const std::string& adapter_type = "software") {
        writeFile(secPath(), R"(
sec:
  security:
    default_security_level: 1
    seed_expiration_ms: 30000
    max_seed_pool_size: 100
  someip:
    application_name: ccu-sec
    service_id: 0x1140
    instance_id: 0x0001
    methods:
      get_seed:
        method_id: )" + method_seed + R"(
      verify_key:
        method_id: 0x0002
      derive_ota_session:
        method_id: 0x0003
      derive_by_uid:
        method_id: 0x0004
      wrap_by_uid:
        method_id: 0x0005
    endpoint:
      port: 51140
      protocol: )" + protocol + R"(
    service_discovery:
      enabled: true
      mode: static
  se_hsm:
    type: )" + adapter_type + R"(
    adapter: {}
)");
        writeCommon();
    }

    std::filesystem::path temp_dir_;
};

TEST_F(ConfigLoaderTest, LoadsUnifiedSubtreeWithDefaults) {
    writeFile(secPath(), "sec: {}\n");
    writeCommon();

    UnifiedSecConfig config =
        ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string());

    // Security defaults stay anchored to constants.
    EXPECT_EQ(config.security.defaultSecurityLevel, SECURITY_LEVEL_1);
    EXPECT_EQ(config.security.seedExpirationMs, SEED_EXPIRATION_MS);
    EXPECT_EQ(config.security.maxSeedPoolSize, MAX_SEED_POOL_SIZE);

    // Service/Instance/Method IDs and endpoint stay anchored to the Registry.
    EXPECT_EQ(config.someip.applicationName, SEC_APPLICATION_NAME);
    EXPECT_EQ(config.someip.serviceId, SEC_SERVICE_ID);
    EXPECT_EQ(config.someip.instanceId, SEC_INSTANCE_ID);
    EXPECT_EQ(config.someip.getSeedMethodId, METHOD_GET_SEED);
    EXPECT_EQ(config.someip.verifyKeyMethodId, METHOD_VERIFY_KEY);
    EXPECT_EQ(config.someip.deriveOtaSessionMethodId, METHOD_DERIVE_OTA_SESSION);
    EXPECT_EQ(config.someip.deriveByUidMethodId, METHOD_DERIVE_BY_UID);
    EXPECT_EQ(config.someip.wrapByUidMethodId, METHOD_WRAP_BY_UID);
    EXPECT_EQ(config.someip.endpointPort, SEC_SOMEIP_PORT);
    EXPECT_EQ(config.someip.endpointProtocol, SEC_SOMEIP_PROTOCOL);

    // Safe install placeholder: no adapter is selected by default.
    EXPECT_EQ(config.se_hsm.type, "unconfigured");
    EXPECT_TRUE(config.se_hsm.adapter.empty());

    // common.log.* comes from the BUILD-owned common.yaml.
    EXPECT_EQ(config.log.level, ccu::fw::log::LogLevel::kWarn);
    EXPECT_TRUE(config.log.strict);
    EXPECT_EQ(config.log.format, "json");
}

TEST_F(ConfigLoaderTest, LoadsExplicitPlatformValues) {
    writeUnified();

    UnifiedSecConfig config =
        ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string());

    EXPECT_EQ(config.security.defaultSecurityLevel, 1);
    EXPECT_EQ(config.security.seedExpirationMs, 30000u);
    EXPECT_EQ(config.security.maxSeedPoolSize, 100u);
    EXPECT_EQ(config.someip.serviceId, 0x1140);
    EXPECT_EQ(config.someip.instanceId, 0x0001);
    EXPECT_EQ(config.someip.getSeedMethodId, 0x0001);
    EXPECT_EQ(config.someip.endpointPort, 51140);
    EXPECT_EQ(config.someip.endpointProtocol, "TCP");
    EXPECT_EQ(config.someip.serviceDiscoveryMode, "static");
    EXPECT_EQ(config.se_hsm.type, "software");
}

TEST_F(ConfigLoaderTest, SecLogOverridesCommonLog) {
    writeUnified();
    writeFile(secPath(), R"(
sec:
  log:
    level: DEBUG
    modules:
      facade: TRACE
  security:
    default_security_level: 1
  se_hsm:
    type: unconfigured
)");
    writeCommon("ERROR");

    UnifiedSecConfig config =
        ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string());

    EXPECT_EQ(config.log.level, ccu::fw::log::LogLevel::kDebug);
    ASSERT_EQ(config.log.module_levels.count("facade"), 1u);
    EXPECT_EQ(config.log.module_levels.at("facade"),
              ccu::fw::log::LogLevel::kTrace);
}

TEST_F(ConfigLoaderTest, MissingSecFileFailsClosed) {
    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(
                     (temp_dir_ / "missing.yaml").string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, MissingCommonFileFailsClosed) {
    writeUnified();
    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(
                     secPath().string(), (temp_dir_ / "missing-common.yaml").string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, TopLevelCommonIsRejected) {
    writeFile(secPath(), R"(
common:
  log:
    level: INFO
sec:
  se_hsm:
    type: unconfigured
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, LegacyRootNodesAreRejected) {
    // Any pre-migration root (se_hsm_type/service_id/type/key_files) must fail
    // instead of being silently ignored after migration.
    writeFile(secPath(), R"(
se_hsm_type: software
default_security_level: 1
service_id: 0x1140
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, KeyFilesAreRejected) {
    writeFile(secPath(), R"(
sec:
  se_hsm:
    type: software
    key_files:
      OTA_VEHICLE_ROOT: keys/ota_vehicle_root.bin
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, StoragePathIsRejected) {
    writeFile(secPath(), R"(
sec:
  se_hsm:
    type: software
    storage_path: /var/lib/ccu/sec/store
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, TmpSecurityStoreIsRejected) {
    writeFile(secPath(), R"(
sec:
  se_hsm:
    type: software
    adapter:
      device_path: /tmp/ccu_sec_se_hsm
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, SecretAdapterFieldIsRejected) {
    writeFile(secPath(), R"(
sec:
  se_hsm:
    type: software
    adapter:
      session_key: "0000"
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, NonScalarAdapterValueIsRejected) {
    writeFile(secPath(), R"(
sec:
  se_hsm:
    type: software
    adapter:
      slot:
        nested: value
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, UnknownSubKeyIsRejected) {
    writeFile(secPath(), R"(
sec:
  se_hsm:
    type: unconfigured
  security:
    seed_expiry_ms: 100
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, UnknownMethodIsRejected) {
    writeFile(secPath(), R"(
sec:
  someip:
    methods:
      unknown_method:
        method_id: 0x0006
  se_hsm:
    type: unconfigured
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, EventSegmentMethodIdIsRejected) {
    // 0x8000+ is the event segment; method IDs stay in 0x0001-0x7FFF.
    writeFile(secPath(), R"(
sec:
  someip:
    methods:
      get_seed:
        method_id: 0x8001
  se_hsm:
    type: unconfigured
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, SecondApplicationNameIsRejected) {
    // One process uses exactly one vsomeip application (CCU-SEC-DSN-CR-005 §5.4).
    writeFile(secPath(), R"(
sec:
  someip:
    application_name: ccu-sec-client
  se_hsm:
    type: unconfigured
)");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, InvalidEndpointProtocolIsRejected) {
    writeUnified("0x0001", "SCTP");

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}

TEST_F(ConfigLoaderTest, MissingSecRootIsRejected) {
    writeFile(secPath(), "log:\n  level: INFO\n");
    writeCommon();

    EXPECT_THROW(ConfigLoader::loadUnifiedConfig(secPath().string(), commonPath().string()),
                 std::runtime_error);
}
