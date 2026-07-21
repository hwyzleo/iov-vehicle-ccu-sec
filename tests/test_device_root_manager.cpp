#include <gtest/gtest.h>
#include "device_root_manager.h"
#include "software_se_hsm.h"
#include "se_hsm_factory.h"
#include "constants.h"
#include "error_codes.h"

using namespace cgw_sec;

class DeviceRootManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        SeHsmConfig config;
        config.type = "software";
        config.storagePath = "/tmp/test_device_root_mgr";
        hsm = std::shared_ptr<SeHsmInterface>(SeHsmFactory::create(config).release());

        std::vector<uint8_t> deviceRootKey = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };
        hsm->storeKey(CGW_DEVICE_ROOT_KEY_NAME, deviceRootKey);

        manager = std::make_unique<DeviceRootManager>(hsm);
    }

    std::shared_ptr<SeHsmInterface> hsm;
    std::unique_ptr<DeviceRootManager> manager;
};

TEST_F(DeviceRootManagerTest, IsDeviceRootAvailableTrue) {
    EXPECT_TRUE(manager->isDeviceRootAvailable());
}

TEST_F(DeviceRootManagerTest, IsDeviceRootAvailableFalse) {
    SeHsmConfig config;
    config.type = "software";
    config.storagePath = "/tmp/test_device_no_root";
    std::shared_ptr<SeHsmInterface> emptyHsm(SeHsmFactory::create(config).release());

    DeviceRootManager emptyManager(emptyHsm);
    EXPECT_FALSE(emptyManager.isDeviceRootAvailable());
}

TEST_F(DeviceRootManagerTest, DeriveSubKeySuccess) {
    std::vector<uint8_t> context = {0x01, 0x02, 0x03, 0x04};
    auto result = manager->deriveSubKey("SUB_KEY_1", context);
    EXPECT_EQ(result.error, CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(result.key.size(), SESSION_KEY_SIZE);
}

TEST_F(DeviceRootManagerTest, DeriveSubKeyDifferentContexts) {
    std::vector<uint8_t> context1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> context2 = {0x05, 0x06, 0x07, 0x08};

    auto result1 = manager->deriveSubKey("SUB_KEY_A", context1);
    auto result2 = manager->deriveSubKey("SUB_KEY_B", context2);

    EXPECT_EQ(result1.error, CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(result2.error, CgwSecErrorCode::SUCCESS);
    EXPECT_NE(result1.key, result2.key);
}

TEST_F(DeviceRootManagerTest, DeriveSubKeyMissingRoot) {
    SeHsmConfig config;
    config.type = "software";
    config.storagePath = "/tmp/test_device_no_root2";
    std::shared_ptr<SeHsmInterface> emptyHsm(SeHsmFactory::create(config).release());

    DeviceRootManager emptyManager(emptyHsm);

    std::vector<uint8_t> context = {0x01, 0x02, 0x03, 0x04};
    auto result = emptyManager.deriveSubKey("SUB_KEY", context);
    EXPECT_EQ(result.error, CgwSecErrorCode::DEVICE_ROOT_MISSING);
}

TEST_F(DeviceRootManagerTest, WrapDataSuccess) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    auto result = manager->wrapData(data);
    EXPECT_EQ(result.error, CgwSecErrorCode::SUCCESS);
}

TEST_F(DeviceRootManagerTest, WrapDataMissingRoot) {
    SeHsmConfig config;
    config.type = "software";
    config.storagePath = "/tmp/test_device_no_root3";
    std::shared_ptr<SeHsmInterface> emptyHsm(SeHsmFactory::create(config).release());

    DeviceRootManager emptyManager(emptyHsm);

    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
    auto result = emptyManager.wrapData(data);
    EXPECT_EQ(result.error, CgwSecErrorCode::DEVICE_ROOT_MISSING);
}

TEST_F(DeviceRootManagerTest, UnwrapDataSuccess) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    auto wrapResult = manager->wrapData(data);
    ASSERT_EQ(wrapResult.error, CgwSecErrorCode::SUCCESS);

    auto unwrapResult = manager->unwrapData(data);
    EXPECT_EQ(unwrapResult.error, CgwSecErrorCode::SUCCESS);
}

TEST_F(DeviceRootManagerTest, UnwrapDataMissingRoot) {
    SeHsmConfig config;
    config.type = "software";
    config.storagePath = "/tmp/test_device_no_root4";
    std::shared_ptr<SeHsmInterface> emptyHsm(SeHsmFactory::create(config).release());

    DeviceRootManager emptyManager(emptyHsm);

    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
    auto result = emptyManager.unwrapData(data);
    EXPECT_EQ(result.error, CgwSecErrorCode::DEVICE_ROOT_MISSING);
}

TEST_F(DeviceRootManagerTest, MultipleDeriveSubKeys) {
    std::vector<uint8_t> context1 = {0x01, 0x02};
    std::vector<uint8_t> context2 = {0x03, 0x04};
    std::vector<uint8_t> context3 = {0x05, 0x06};

    auto result1 = manager->deriveSubKey("KEY_A", context1);
    auto result2 = manager->deriveSubKey("KEY_B", context2);
    auto result3 = manager->deriveSubKey("KEY_C", context3);

    EXPECT_EQ(result1.error, CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(result2.error, CgwSecErrorCode::SUCCESS);
    EXPECT_EQ(result3.error, CgwSecErrorCode::SUCCESS);
}
