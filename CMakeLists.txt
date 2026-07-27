cmake_minimum_required(VERSION 3.10)
project(CgwSecService)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -g)

# SOME/IP 实现选项
option(USE_MOCK_SOMEIP "Use mock SOME/IP implementation (TCP) instead of vsomeip" ON)

if(USE_MOCK_SOMEIP)
    message(STATUS "Using mock SOME/IP implementation (TCP)")
    add_definitions(-DUSE_MOCK_SOMEIP)
else()
    message(STATUS "Using real vsomeip implementation")
    
    # 查找 vsomeip
    find_package(vsomeip3 REQUIRED)
    if(vsomeip3_FOUND)
        message(STATUS "Found vsomeip: ${vsomeip3_DIR}")
        include_directories(${vsomeip3_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "vsomeip3 not found. Please install vsomeip.")
    endif()
    
    # 查找 Boost（vsomeip 依赖）
    find_package(Boost REQUIRED COMPONENTS system thread log)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

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

# CGW Framework (provides cgw-framework-log: Logger, ContextScope, structured fields)
# CGW-SEC-DSN-CR-004
find_package(CGWFramework REQUIRED)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(nlohmann_json REQUIRED)

# OpenSSL - 设置提示路径帮助 CMake 找到 Homebrew 安装的 OpenSSL
if(APPLE)
    set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl)
    set(OPENSSL_CRYPTO_LIBRARY /opt/homebrew/opt/openssl/lib/libcrypto.dylib)
    set(OPENSSL_SSL_LIBRARY /opt/homebrew/opt/openssl/lib/libssl.dylib)
endif()
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
    src/sec_someip_server.cpp
    src/sec_someip_proxy.cpp
    src/sec_someip_client.cpp
    src/someip_config_loader.cpp
    src/mock_someip_network.cpp
    src/sec_log_adapter.cpp
    src/sec_log_context.cpp
)



# Create cgw_sec library
add_library(cgw_sec_lib STATIC ${LIB_SOURCES})
target_include_directories(cgw_sec_lib PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(cgw_sec_lib PUBLIC yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto CGWFramework::cgw-framework)

# 根据 SOME/IP 实现添加链接库
if(USE_MOCK_SOMEIP)
    # mock实现需要socket库
    if(NOT WIN32)
        target_link_libraries(cgw_sec_lib PUBLIC pthread)
    endif()
else()
    target_link_libraries(cgw_sec_lib PUBLIC 
        vsomeip3
        ${Boost_LIBRARIES}
    )
endif()

# Main application executable
add_executable(cgw_sec src/main.cpp)
target_include_directories(cgw_sec PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(cgw_sec PRIVATE cgw_sec_lib)

# Example executables
add_executable(simple_client examples/simple_client.cpp)
target_include_directories(simple_client PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(simple_client PRIVATE cgw_sec_lib)

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
    tests/test_sec_someip_server.cpp
    tests/test_sec_someip_client.cpp
    tests/test_integration_someip.cpp
    tests/test_log_adapter.cpp
    tests/test_log_events.cpp
    tests/test_log_integration.cpp
)
target_include_directories(CgwSecTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(CgwSecTests PRIVATE cgw_sec_lib GTest::GTest GTest::gmock GTest::Main)

# 根据 SOME/IP 实现添加链接库
if(USE_MOCK_SOMEIP)
    # mock实现需要socket库
    if(NOT WIN32)
        target_link_libraries(CgwSecTests PRIVATE pthread)
    endif()
else()
    target_link_libraries(CgwSecTests PRIVATE 
        vsomeip3
        ${Boost_LIBRARIES}
    )
endif()
add_test(NAME CgwSecTests COMMAND CgwSecTests)

# 为测试提供源目录路径
target_compile_definitions(CgwSecTests PRIVATE SOURCE_DIR="${PROJECT_SOURCE_DIR}")
