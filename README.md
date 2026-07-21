# CGW-SEC

中央网关（CGW）车端安全服务

## 概述

CGW-SEC 是 CGW 上的车端安全服务，为 CGW-DIAG 和 OTA master 提供诊断安全访问的密码学后端与车端信任根托管。

## 功能

- 0x27 seed/key 校验后端
- OTA 车辆根车端托管与会话密钥派生
- 网关设备根车端持有
- 安全存储与 fail-closed

## 构建

```bash
./scripts/build.sh
```

## 测试

```bash
cd build
ctest --output-on-failure
```

## 配置

- `config/sec_config.yaml` - CGW-SEC 主配置
- `config/someip_config.yaml` - SOME/IP 服务配置
- `config/se_hsm_config.yaml` - SE/HSM 配置

## 架构

CGW-SEC 采用分层架构：

- SE/HSM 抽象层：提供硬件抽象（开发阶段使用软件模拟）
- SOME/IP 服务层：提供对外接口
- 业务逻辑层：实现核心功能（SeedKeyManager、OtaSessionManager、DeviceRootManager、SecurityGuard）

## 依赖

- C++17
- CMake 3.10+
- yaml-cpp
- nlohmann_json
- OpenSSL
- Google Test
