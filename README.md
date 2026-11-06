# CCU-SEC

中央计算单元（CCU）车端安全服务

## 概述

CCU-SEC 是 CCU 上的车端安全服务，为 CCU-DIAG 和 OTA master 提供诊断安全访问的密码学后端与车端信任根托管。

## 功能

- 0x27 seed/key 校验后端
- OTA 车辆根车端托管与会话密钥派生
- 设备根车端持有
- 安全存储与 fail-closed

## 构建

```bash
./scripts/build.sh            # HOST/dev：mock SOME/IP + 软件 SE/HSM 夹具
```

生产 TARGET 构建由 CCU-BUILD 驱动（`BUILD_TESTING=OFF`、`USE_MOCK_SOMEIP=OFF`、
`CCU_SEC_ENABLE_SOFTWARE_HSM=OFF`），详见 `docs/build-and-verify.md`。

## 测试

```bash
cd build && ctest --output-on-failure
OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl bash ci/run-ci-gates.sh
```

## 配置

- `config/sec.default.yaml` - 安全默认模板，安装为 `/etc/ccu/conf.d/sec.yaml`
- `config/schema/sec.schema.yaml` - 统一 `sec:` 子树 schema（BUILD 校验输入）
- `config/dev/` - 开发夹具（软件 SE/HSM、平台网络值），永不安装
- `config/dev/legacy/` - 迁移前旧三份配置，仅作映射回归夹具

公共 `common.log.*` 由 CCU-BUILD 的 `/etc/ccu/common.yaml` 提供，服务配置内不内联
`common:`；`se_hsm.type: unconfigured` 是安全安装占位，未平台化时 fail-closed。

## 架构

CCU-SEC 采用分层架构：

- SE/HSM 抽象层：提供硬件抽象（开发阶段使用软件模拟）
- SOME/IP 服务层：提供对外接口
- 业务逻辑层：实现核心功能（SeedKeyManager、OtaSessionManager、DeviceRootManager、SecurityGuard）

## 依赖

- C++17
- CMake 3.24+
- yaml-cpp
- nlohmann_json
- OpenSSL
- Google Test
