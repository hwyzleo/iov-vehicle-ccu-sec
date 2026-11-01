#include <gtest/gtest.h>
#include "config_loader.h"
#include <fstream>
#include <filesystem>

using namespace ccu_sec;

class ConfigLoaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::filesystem::create_directories("/tmp/ccu_sec_test");

        std::ofstream secConfig("/tmp/ccu_sec_test/sec_config.yaml");
        secConfig << "se_hsm_type: software\n";
        secConfig << "default_security_level: 1\n";
        secConfig << "seed_expiration_ms: 30000\n";
        secConfig << "max_seed_pool_size: 100\n";
        secConfig.close();

        std::ofstream someipConfig("/tmp/ccu_sec_test/someip_config.yaml");
        someipConfig << "service_id: 0x1234\n";
        someipConfig << "instance_id: 0x5678\n";
        someipConfig << "get_seed_method_id: 0x0001\n";
        someipConfig << "verify_key_method_id: 0x0002\n";
        someipConfig << "derive_ota_session_method_id: 0x0003\n";
        someipConfig << "derive_by_uid_method_id: 0x0004\n";
        someipConfig << "wrap_by_uid_method_id: 0x0005\n";
        someipConfig.close();

        std::ofstream seHsmConfig("/tmp/ccu_sec_test/se_hsm_config.yaml");
        seHsmConfig << "type: software\n";
        seHsmConfig << "storage_path: /tmp/ccu_sec_se_hsm\n";
        seHsmConfig << "key_files:\n";
        seHsmConfig << "  OTA_VEHICLE_ROOT: keys/ota_vehicle_root.bin\n";
        seHsmConfig << "  CCU_DEVICE_ROOT: keys/ccu_device_root.bin\n";
        seHsmConfig << "  DIAG_SEEDKEY_SECRET: keys/diag_seedkey_secret.bin\n";
        seHsmConfig.close();
    }

    void TearDown() override {
        std::filesystem::remove_all("/tmp/ccu_sec_test");
    }
};

TEST_F(ConfigLoaderTest, LoadSecConfig) {
    SecConfig config = ConfigLoader::loadSecConfig("/tmp/ccu_sec_test/sec_config.yaml");
    EXPECT_EQ(config.seHsmType, "software");
    EXPECT_EQ(config.defaultSecurityLevel, 1);
    EXPECT_EQ(config.seedExpirationMs, 30000);
    EXPECT_EQ(config.maxSeedPoolSize, 100);
}

TEST_F(ConfigLoaderTest, LoadSomeipConfig) {
    SomeipConfig config = ConfigLoader::loadSomeipConfig("/tmp/ccu_sec_test/someip_config.yaml");
    EXPECT_EQ(config.serviceId, 0x1234);
    EXPECT_EQ(config.instanceId, 0x5678);
    EXPECT_EQ(config.getSeedMethodId, 0x0001);
    EXPECT_EQ(config.verifyKeyMethodId, 0x0002);
    EXPECT_EQ(config.deriveOtaSessionMethodId, 0x0003);
    EXPECT_EQ(config.deriveByUidMethodId, 0x0004);
    EXPECT_EQ(config.wrapByUidMethodId, 0x0005);
}

TEST_F(ConfigLoaderTest, LoadSeHsmConfig) {
    SeHsmConfig config = ConfigLoader::loadSeHsmConfig("/tmp/ccu_sec_test/se_hsm_config.yaml");
    EXPECT_EQ(config.type, "software");
    EXPECT_EQ(config.storagePath, "/tmp/ccu_sec_se_hsm");
    EXPECT_EQ(config.keyFiles.size(), 3);
    EXPECT_EQ(config.keyFiles["OTA_VEHICLE_ROOT"], "keys/ota_vehicle_root.bin");
    EXPECT_EQ(config.keyFiles["CCU_DEVICE_ROOT"], "keys/ccu_device_root.bin");
    EXPECT_EQ(config.keyFiles["DIAG_SEEDKEY_SECRET"], "keys/diag_seedkey_secret.bin");
}

TEST_F(ConfigLoaderTest, LoadNonexistentConfig) {
    EXPECT_THROW(ConfigLoader::loadSecConfig("/tmp/nonexistent.yaml"), std::runtime_error);
    EXPECT_THROW(ConfigLoader::loadSomeipConfig("/tmp/nonexistent.yaml"), std::runtime_error);
    EXPECT_THROW(ConfigLoader::loadSeHsmConfig("/tmp/nonexistent.yaml"), std::runtime_error);
}
