# =============================================================================
# CCU-SEC - CMake build (CCU-SEC-DSN-CR-005 §3.2/§4)
#
# Contract:
#   * Standard configure -> build -> install with GNUInstallDirs.
#   * No compiler / sysroot / target triple / host absolute path is set here.
#     OpenSSL and every other TARGET package resolve only from CCU-BUILD
#     controlled find roots / sysroot / dependency staging.
#   * Framework is consumed only through the installed CCUFramework package
#     (find_package CONFIG + imported targets); no source/build-tree usage.
#   * Production target stays ccu_sec. The single rootfs install component is
#     ccu-sec-runtime and installs exactly:
#         usr/bin/ccu_sec
#         usr/lib/systemd/system/ccu-sec.service
#         etc/ccu/conf.d/sec.yaml                      (from sec.default.yaml)
#         usr/share/ccu-sec/schema/sec.schema.yaml
#     Internal lib / headers / tests / examples / dev fixtures / legacy config
#     / software-HSM key files are NOT installed.
#   * BUILD_TESTING=OFF must not find GTest or create test/example targets.
#   * USE_MOCK_SOMEIP and CCU_SEC_ENABLE_SOFTWARE_HSM are explicit inputs;
#     TARGET production builds pass OFF for both. No HOST auto-detection.
# =============================================================================
cmake_minimum_required(VERSION 3.24)
project(CcuSecService VERSION 1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(SecWarnings)

# ----------------------------------------------------------------------------
# Options (explicit only)
# ----------------------------------------------------------------------------
option(USE_MOCK_SOMEIP
       "Use mock SOME/IP backend (HOST/dev/CI only; production passes OFF)"
       OFF)
option(CCU_SEC_ENABLE_SOFTWARE_HSM
       "Compile the NON_PRODUCTION software SE/HSM fixture (HOST/test only)"
       OFF)

# A HOST/test build (BUILD_TESTING=ON) is explicitly non-production: the test
# suite needs the software HSM fixture. Release presets pass BUILD_TESTING=OFF,
# so this can never be enabled implicitly for a release profile.
if(BUILD_TESTING AND NOT CCU_SEC_ENABLE_SOFTWARE_HSM)
    message(STATUS
        "BUILD_TESTING=ON (HOST/test) -> enabling NON_PRODUCTION software SE/HSM fixture")
    set(CCU_SEC_ENABLE_SOFTWARE_HSM ON CACHE BOOL "" FORCE)
endif()

# ----------------------------------------------------------------------------
# Dependency classification (CCU-SEC-DSN-CR-005 §4.2)
#   framework       : service dependency, installed SDK only
#   yaml-cpp        : direct TARGET dependency (BUILD lock ID: yaml-cpp)
#   nlohmann_json   : direct TARGET dependency (BUILD lock ID: nlohmann-json)
#   OpenSSL         : direct TARGET dependency (controlled find roots only)
#   vsomeip3/Boost  : production backend direct dependency (real backend only)
#   GTest           : HOST/test-only (BUILD_TESTING)
# ----------------------------------------------------------------------------
find_package(Threads REQUIRED)
find_package(CCUFramework CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

if(NOT USE_MOCK_SOMEIP)
    message(STATUS "Using real vsomeip SOME/IP backend")
    find_package(vsomeip3 REQUIRED)
    # vsomeip3 只传递 system/thread；本仓库源码不使用 boost/log，
    # 且 Orin sysroot 未提供 libboost_log（TARGET readiness 修正）。
    find_package(Boost REQUIRED COMPONENTS system thread)
else()
    message(STATUS "Using mock SOME/IP backend (NON_PRODUCTION)")
endif()

# ----------------------------------------------------------------------------
# Sources
# ----------------------------------------------------------------------------
set(LIB_SOURCES
    src/error_codes.cpp
    src/data_models.cpp
    src/config_loader.cpp
    src/se_hsm_interface.cpp
    src/se_hsm_factory.cpp
    src/seed_key_manager.cpp
    src/ota_session_manager.cpp
    src/device_root_manager.cpp
    src/security_guard.cpp
    src/sec_someip_service.cpp
    src/sec_someip_server.cpp
    src/sec_someip_proxy.cpp
    src/sec_someip_client.cpp
    src/mock_someip_network.cpp
    src/sec_log_adapter.cpp
    src/sec_log_context.cpp
)

if(CCU_SEC_ENABLE_SOFTWARE_HSM)
    list(APPEND LIB_SOURCES src/software_se_hsm.cpp)
endif()

# Internal object collection. Never installed, never exported.
add_library(ccu_sec_lib STATIC ${LIB_SOURCES})
target_include_directories(ccu_sec_lib
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_features(ccu_sec_lib PUBLIC cxx_std_17)
target_link_libraries(ccu_sec_lib
    PUBLIC
        CCUFramework::ccu-framework-log
        yaml-cpp::yaml-cpp
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads)
if(USE_MOCK_SOMEIP)
    target_compile_definitions(ccu_sec_lib PUBLIC USE_MOCK_SOMEIP)
else()
    # Include dirs come from the controlled vsomeip3/Boost packages/sysroot.
    target_include_directories(ccu_sec_lib PUBLIC
        ${vsomeip3_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})
    target_link_libraries(ccu_sec_lib PUBLIC vsomeip3 ${Boost_LIBRARIES})
endif()
if(CCU_SEC_ENABLE_SOFTWARE_HSM)
    target_compile_definitions(ccu_sec_lib PUBLIC CCU_SEC_ENABLE_SOFTWARE_HSM)
endif()
sec_apply_warnings(ccu_sec_lib)

# Production daemon target (fixed name ccu_sec).
add_executable(ccu_sec src/main.cpp)
target_link_libraries(ccu_sec PRIVATE ccu_sec_lib)
target_compile_features(ccu_sec PRIVATE cxx_std_17)
sec_apply_warnings(ccu_sec)

# ----------------------------------------------------------------------------
# Tests and examples: HOST-only, non-installed. Never configured with
# BUILD_TESTING=OFF (CCU-SEC-DSN-CR-005 §4.1).
# ----------------------------------------------------------------------------
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest REQUIRED)

    add_executable(CcuSecTests
        tests/test_error_codes.cpp
        tests/test_data_models.cpp
        tests/test_config_loader.cpp
        tests/test_unified_config.cpp
        tests/test_fail_closed.cpp
        tests/test_software_se_hsm.cpp
        tests/test_seed_key_manager.cpp
        tests/test_ota_session_manager.cpp
        tests/test_device_root_manager.cpp
        tests/test_security_guard.cpp
        tests/test_sec_someip_service.cpp
        tests/test_sec_someip_proxy.cpp
        tests/test_integration.cpp
        tests/test_sec_someip_server.cpp
        tests/test_sec_someip_client.cpp
        tests/test_integration_someip.cpp
        tests/test_log_adapter.cpp
        tests/test_log_events.cpp
        tests/test_log_integration.cpp
    )
    target_include_directories(CcuSecTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(CcuSecTests
        PRIVATE SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(CcuSecTests
        PRIVATE ccu_sec_lib GTest::GTest GTest::gmock GTest::Main)
    sec_apply_warnings(CcuSecTests)
    add_test(NAME CcuSecTests COMMAND CcuSecTests)

    # Non-production example client (dev/CI only, never installed).
    add_executable(simple_client examples/simple_client.cpp)
    target_include_directories(simple_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(simple_client PRIVATE ccu_sec_lib)
    sec_apply_warnings(simple_client)
endif()

# ----------------------------------------------------------------------------
# Install: ccu-sec-runtime rootfs component only (CCU-SEC-DSN-CR-005 §3.2).
# Supports CMAKE_INSTALL_PREFIX=/usr + BUILD-managed DESTDIR. No install-time
# network/device access, no key generation/injection, no service start/stop,
# no install-time provisioning.
# ----------------------------------------------------------------------------
install(TARGETS ccu_sec
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT ccu-sec-runtime)

install(FILES packaging/systemd/ccu-sec.service
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
    COMPONENT ccu-sec-runtime)

# FULL_SYSCONFDIR gives /etc when PREFIX=/usr (FHS special case), matching the
# BUILD rootfs staging layout (etc/ at install-root root) and main.cpp's
# production default /etc/ccu/conf.d/sec.yaml.
install(FILES config/sec.default.yaml
    DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/ccu/conf.d
    RENAME sec.yaml
    COMPONENT ccu-sec-runtime)

install(FILES config/schema/sec.schema.yaml
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ccu-sec/schema
    COMPONENT ccu-sec-runtime)
