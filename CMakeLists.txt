cmake_minimum_required(VERSION 3.10)
project(CgwSecService)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -g)

# LIB_DIR: reserved for platform-specific third-party libraries
if (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    if (APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/arm64-apple-darwin)
    elseif (UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/aarch64-linux-gnu)
    endif ()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    if (APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-apple-darwin)
    elseif (UNIX AND NOT APPLE)
        set(LIB_DIR ${PROJECT_SOURCE_DIR}/third_party/lib/x86_64-linux-gnu)
    endif ()
endif ()

find_package(yaml-cpp REQUIRED)
include_directories(${YAML_CPP_INCLUDE_DIRS})

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(nlohmann_json REQUIRED)

find_package(OpenSSL REQUIRED)

set(LIB_SOURCES
    src/error_codes.cpp
    src/data_models.cpp
    src/config_loader.cpp
    src/se_hsm_interface.cpp
    src/software_se_hsm.cpp
    src/se_hsm_factory.cpp
    src/seed_key_manager.cpp
    src/ota_session_manager.cpp
    src/device_root_manager.cpp
    src/security_guard.cpp
    src/sec_someip_service.cpp
    src/sec_someip_proxy.cpp
    src/someip_config_loader.cpp
)

# Create cgw_sec library
add_library(cgw_sec_lib STATIC ${LIB_SOURCES})
target_include_directories(cgw_sec_lib PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(cgw_sec_lib PUBLIC yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)

# Main application executable
add_executable(cgw_sec src/main.cpp)
target_include_directories(cgw_sec PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(cgw_sec PRIVATE cgw_sec_lib)

enable_testing()
add_executable(CgwSecTests
    tests/test_error_codes.cpp
    tests/test_data_models.cpp
    tests/test_config_loader.cpp
    tests/test_software_se_hsm.cpp
    tests/test_seed_key_manager.cpp
    tests/test_ota_session_manager.cpp
    tests/test_device_root_manager.cpp
    tests/test_security_guard.cpp
    tests/test_sec_someip_service.cpp
    tests/test_sec_someip_proxy.cpp
    tests/test_integration.cpp
)
target_include_directories(CgwSecTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(CgwSecTests PRIVATE cgw_sec_lib GTest::GTest GTest::gmock GTest::Main)
add_test(NAME CgwSecTests COMMAND CgwSecTests)
