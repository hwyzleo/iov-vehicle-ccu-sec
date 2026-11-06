#include <gtest/gtest.h>
#include "sec_someip_service.h"
#include "se_hsm_factory.h"
#include "constants.h"
#include "error_codes.h"
#include <stdexcept>
#include <vector>

using namespace ccu_sec;

// Fail-closed contract (CCU-SEC-DSN-CR-005 §5.2/§6.2, BUILD-REQ-005):
//   * unconfigured / unknown adapter never resolves to a software fallback
//   * production initialization never generates or fills fixed key material
//   * only the explicit NON_PRODUCTION software fixture can serve, and it
//     never reports security capability as ready
class FailClosedTest : public ::testing::Test {
protected:
    SecConfig security_;
    SomeipConfig someip_;
    SeHsmConfig seHsm_;

    void SetUp() override {
        security_.defaultSecurityLevel = SECURITY_LEVEL_1;
        security_.seedExpirationMs = SEED_EXPIRATION_MS;
        security_.maxSeedPoolSize = MAX_SEED_POOL_SIZE;
        someip_.applicationName = SEC_APPLICATION_NAME;
        someip_.serviceId = SEC_SERVICE_ID;
        someip_.instanceId = SEC_INSTANCE_ID;
    }
};

TEST_F(FailClosedTest, UnconfiguredAdapterHasNoSoftwareFallback) {
    seHsm_.type = "unconfigured";
    EXPECT_EQ(SeHsmFactory::create(seHsm_).get(), nullptr);
}

TEST_F(FailClosedTest, UnknownAdapterHasNoSoftwareFallback) {
    seHsm_.type = "approved-se";
    EXPECT_EQ(SeHsmFactory::create(seHsm_).get(), nullptr);
}

TEST_F(FailClosedTest, UnconfiguredAdapterRefusesToStart) {
    seHsm_.type = "unconfigured";
    EXPECT_THROW(SecSomeipService(security_, someip_, seHsm_), std::runtime_error);
}

TEST_F(FailClosedTest, UnknownAdapterRefusesToStart) {
    seHsm_.type = "approved-se";
    EXPECT_THROW(SecSomeipService(security_, someip_, seHsm_), std::runtime_error);
}

TEST_F(FailClosedTest, EmptyAdapterTypeRefusesToStart) {
    seHsm_.type.clear();
    EXPECT_THROW(SecSomeipService(security_, someip_, seHsm_), std::runtime_error);
}

TEST_F(FailClosedTest, SoftwareFixtureNeverReportsSecurityReady) {
    seHsm_.type = "software";
    SecSomeipService service(security_, someip_, seHsm_);
    EXPECT_FALSE(service.securityReady());
}

TEST_F(FailClosedTest, StartupDoesNotGenerateFixedKeyMaterial) {
    // CCU-SEC-DSN-CR-005 §5.2: production init must not turn configuration
    // into 0x42 test material. Before any explicit test provisioning, the
    // OTA root is genuinely absent.
    seHsm_.type = "software";
    SecSomeipService service(security_, someip_, seHsm_);

    OtaSessionContext context;
    context.campaignId = "CAMP-001";
    context.vin = "VIN00000000000000";
    context.direction = "authorize";
    context.nonce = std::vector<uint8_t>(NONCE_SIZE, 0x11);
    context.timestamp = 1234567890;

    auto ota = service.deriveOtaSession(context, SECURITY_LEVEL_1);
    EXPECT_EQ(ota.error, CcuSecErrorCode::OTA_ROOT_MISSING);

    auto device = service.deriveByUid("SUB_KEY", {0x01, 0x02}, SECURITY_LEVEL_1);
    EXPECT_EQ(device.error, CcuSecErrorCode::DEVICE_ROOT_MISSING);
}

TEST_F(FailClosedTest, ExplicitTestProvisioningIsTheOnlyKeyPath) {
    // The software fixture only receives roots through the guarded
    // provisionTestKey() entry (test/dev code), never through config.
    seHsm_.type = "software";
    SecSomeipService service(security_, someip_, seHsm_);

    const std::vector<uint8_t> ota_root(32, 0x42);
    EXPECT_EQ(service.provisionTestKey(OTA_VEHICLE_ROOT_KEY_NAME, ota_root),
              CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(service.provisionTestKey(CCU_DEVICE_ROOT_KEY_NAME, ota_root),
              CcuSecErrorCode::SUCCESS);

    OtaSessionContext context;
    context.campaignId = "CAMP-001";
    context.vin = "VIN00000000000000";
    context.direction = "authorize";
    context.nonce = std::vector<uint8_t>(NONCE_SIZE, 0x11);
    context.timestamp = 1234567890;

    auto ota = service.deriveOtaSession(context, SECURITY_LEVEL_1);
    EXPECT_EQ(ota.error, CcuSecErrorCode::SUCCESS);
    EXPECT_EQ(ota.nonce.size(), NONCE_SIZE);

    // The fixture is still not production-ready after provisioning.
    EXPECT_FALSE(service.securityReady());
}
