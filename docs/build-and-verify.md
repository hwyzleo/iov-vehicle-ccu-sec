# 构建和验证

对应设计：CCU-SEC-DSN-CR-005 §3、§4、§5、§9。

## 前置依赖

- CMake 3.24+
- C++17 编译器（GCC 7+, Clang 5+）
- yaml-cpp
- nlohmann_json
- OpenSSL（只允许来自 BUILD 控制的 find root / sysroot / vendor SDK）
- Google Test（仅 HOST/test，`BUILD_TESTING=OFF` 时不查找）
- CCU-Framework 已安装 SDK（`find_package(CCUFramework CONFIG)`）

### macOS (Homebrew)

```bash
brew install cmake yaml-cpp nlohmann-json openssl googletest
```

OpenSSL 在 macOS 上是 keg-only：由 **BUILD 侧**传入 `OPENSSL_ROOT_DIR`
（项目 CMake 不写任何宿主路径）：

```bash
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl
```

### Ubuntu/Debian

```bash
sudo apt-get install cmake libyaml-cpp-dev nlohmann-json3-dev libssl-dev libgtest-dev
```

## HOST / 开发构建（非生产）

```bash
./scripts/build.sh
# 等价手动命令：
cmake -S . -B build \
      -DBUILD_TESTING=ON \
      -DUSE_MOCK_SOMEIP=ON \
      -DCCU_SEC_ENABLE_SOFTWARE_HSM=ON \
      -DCMAKE_PREFIX_PATH="$HOME/.local"
cmake --build build -j
ctest --test-dir build --output-on-failure
```

- `USE_MOCK_SOMEIP=ON`、`CCU_SEC_ENABLE_SOFTWARE_HSM=ON` 都是 **显式非生产**输入：
  mock SOME/IP 后端与软件 SE/HSM（模拟算法 + 内存 keyStore）不满足生产秘密边界。
- `BUILD_TESTING=ON` 视为显式 HOST/test 构建，CMake 会打开软件 SE/HSM 夹具并给出
  STATUS 提示；release preset 使用 `BUILD_TESTING=OFF`，因此不存在隐式开启。
- 软件 SE/HSM 的 `security_ready=false`：进程存活不等于安全能力 ready。

## TARGET / 生产构建（由 CCU-BUILD 驱动）

```bash
cmake -S . -B build-target \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DCMAKE_INSTALL_SYSCONFDIR=/etc \
      -DCMAKE_INSTALL_LOCALSTATEDIR=/var \
      -DBUILD_TESTING=OFF \
      -DUSE_MOCK_SOMEIP=OFF \
      -DCCU_SEC_ENABLE_SOFTWARE_HSM=OFF
cmake --build build-target --target ccu_sec -j
DESTDIR=<root> cmake --install build-target --prefix /usr \
      --component ccu-sec-runtime
```

`ccu-sec-runtime` 精确安装 4 个文件：

```plain text
usr/bin/ccu_sec
usr/lib/systemd/system/ccu-sec.service
etc/ccu/conf.d/sec.yaml
usr/share/ccu-sec/schema/sec.schema.yaml
```

不安装 `ccu_sec_lib`、头文件、tests、examples、开发夹具、旧三份配置、
软件 HSM key files 或任何 provisioning 内容。

## 配置布局

| 路径 | 责任方 | 说明 |
|---|---|---|
| `/etc/ccu/common.yaml` | CCU-BUILD | 公共 `common.log.*`，服务模板内不内联 |
| `/etc/ccu/conf.d/sec.yaml` | CCU-BUILD 整文件覆盖 | 唯一服务根 `sec:`；ID/端口以 Service Registry 为 SSOT |
| `config/sec.default.yaml` | CCU-SEC | 安全默认占位（`se_hsm.type: unconfigured`），安装为 `sec.yaml` |
| `config/schema/sec.schema.yaml` | CCU-SEC | Draft-07 schema，BUILD 与服务侧同一锁定版本校验 |
| `config/dev/*` | CCU-SEC | 开发夹具（software HSM、平台网络值），永不安装 |
| `config/dev/legacy/*` | CCU-SEC | 迁移前旧三份配置，仅作映射回归夹具，永不安装 |

生产 daemon 默认只读正式路径；`--sec-config` / `--common-config` /
`--vsomeip-config` 仅用于开发与测试（`--vsomeip-config` 仅 mock 后端构建需要）。

## 运行开发守护进程

```bash
./build/ccu_sec --sec-config config/dev/sec.yaml \
                --common-config config/dev/common.yaml \
                --vsomeip-config config/dev/vsomeip.json
```

未提供 `--sec-config` 时进程读取 `/etc/ccu/conf.d/sec.yaml`；默认模板
`unconfigured` 会在 ready/offer 前 fail-closed 退出（非 0）。

## CI 门禁

```bash
OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl bash ci/run-ci-gates.sh
```

依次执行 9 个门禁（提交级 HOST 验证，不替代 CCU-BUILD 的 TARGET 验收）：

1. `ci/verify-cmake-lint.sh` — 构建契约静态检查
2. `ci/verify-systemd-unit.sh` — baseline unit 契约
3. `ci/verify-config-schema.py` — 统一 `sec.yaml` schema、交叉字段、
   秘密/`/tmp` 扫描、负例与 release profile 拒绝
4. HOST configure/build/`ctest`
5. `ci/verify-installed-framework.cmake` — 已安装 SDK 可消费
6. 生产 configure（`BUILD_TESTING=OFF`、软件 HSM `OFF`）不含 GTest、
   测试 target 与软件 SE/HSM 目标文件
7. `ci/verify-install-manifest.py` — DESTDIR 精确文件集 + 重复安装摘要一致
8. `tests/smoke/smoke-sec.sh` — 临时配置根启动、mock Provider offer、
   SIGTERM 有界退出、零泄露日志扫描
9. fail-closed：无批准 adapter / `unconfigured` / 未编译 `software` 均拒绝启动

TARGET 交叉编译、ELF machine/ABI/NEEDED/RPATH、宿主污染检查、目标机
批准 SE/HSM 安全 smoke、provisioning preserve/rollback 由 CCU-BUILD 执行。

## 验证

1. 构建成功且 `ctest` 全部通过
2. `ci/run-ci-gates.sh` 全部 PASS
3. `build/ccu_sec` 生成；`DESTDIR` 安装文件集与上表一致
4. 无批准 SE/HSM adapter 时进程 fail-closed，不生成固定测试密钥
