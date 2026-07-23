# CGW-SEC-DSN-CR-002 Method ID 分配设计规格

## 概述

本设计规格对应 **CGW-SEC-DSN-CR-002**，将 CGW-SEC 对外 SOME/IP 服务的能力落实到具体 Method ID 并标准化命名。

### 变更摘要

- §3 由「草案」转正并新增 §3.1「方法清单与 Method ID 分配」
- 为现有 5 个方法指派 service-scoped Method ID（`0x0001–0x0005`）
- 统一 `METHOD_<动作>` 标准命名
- 明确 Method ID 分配约定
- Service ID: `0x7726`，Instance ID: `0x0001`

### 关联文档

- 设计文档：CGW-SEC-SPEC设计 §3 / §3.1、§8
- 需求依据：CGW-SEC-SPEC需求 US-001～US-003、US-005
- 配对需求：CGW-SEC-REQ-CR-002
- 前序 CR：CGW-SEC-DSN-CR-001

---

## 1. 设计目标

### 1.1 目标

- 将 CGW-SEC 对外 SOME/IP 方法标准化命名并分配 Method ID
- 建立 Method ID 分配约定，为后续扩展提供规范
- 更新 Service ID / Instance ID 为 CGW 模块库 SSOT 分配值

### 1.2 非目标

- 不新增/删除方法
- 不改变方法语义与方向
- 不涉及代码逻辑改动（纯接口口径定案）

---

## 2. Method ID 分配约定

### 2.1 Service ID 与 Instance ID

| 参数 | 值 | 来源 |
|------|-----|------|
| Service ID | `0x7726` | CGW 模块库 SSOT |
| Instance ID | `0x0001` | CGW 模块库 SSOT |
| SOME/IP 端口 | `30502` | CGW 模块库属性 |

### 2.2 Method ID 段位约定

| 段位 | 范围 | 用途 | 说明 |
|------|------|------|------|
| Method 段 | `0x0001–0x7FFF` | request/response | 本服务当前使用 |
| Event 段 | `0x8000–0xFFFF` | event/notification | 配合 Eventgroup，本期预留 |

### 2.3 命名规范

- 标准命名：`METHOD_<动作>` 大写蛇形
- 一经分配不复用、不重编号
- 后续新增 method/event 按本约定顺延分配并另开 CR

### 2.4 寻址方式

```
Message ID = Service ID << 16 | Method ID
本服务方法：0x7726_xxxx
```

---

## 3. 方法清单（§3.1）

| Method ID | 标准名 | 方法签名 | 方向 | 对应需求 |
|-----------|--------|----------|------|----------|
| 0x0001 | METHOD_GET_SEED | `getSeed(level)` | CGW-DIAG → SEC | US-001 |
| 0x0002 | METHOD_VERIFY_KEY | `verifyKey(level, seedId, key)` | CGW-DIAG → SEC | US-001 |
| 0x0003 | METHOD_DERIVE_OTA_SESSION | `deriveOtaSession(context)` | FOTA/OTA master → SEC | US-002 |
| 0x0004 | METHOD_DERIVE_BY_UID | `deriveByUid(keyName, info)` | 设备级调用方 → SEC | US-003 |
| 0x0005 | METHOD_WRAP_BY_UID | `wrapByUid(keyName, plaintext)` | 设备级调用方 → SEC | US-003 |

---

## 4. 实现方案

### 4.1 方案选择

采用 **方案 1：最小改动**，理由：

1. 符合 CR-002「纯接口口径定案、无代码改动」精神
2. 配置文件已有正确 Method ID，只需更新 Service/Instance ID
3. 常量定义集中，易于维护

### 4.2 改动清单

#### 4.2.1 include/constants.h

添加以下常量定义：

```cpp
// ====================================================================
// SOME/IP Service & Instance ID 定义
// 来源：CGW 模块库 SSOT（已分配）
// ====================================================================
constexpr uint16_t SEC_SERVICE_ID = 0x7726;
constexpr uint16_t SEC_INSTANCE_ID = 0x0001;
constexpr uint16_t SEC_SOMEIP_PORT = 30502;

// ====================================================================
// Method ID 分配约定
// ====================================================================
// - Method ID 为 service-scoped（仅需在本 Service 内唯一）
// - 0x0001–0x7FFF 用于 method（request/response）
// - 0x8000–0xFFFF 预留 event/notification（配合 Eventgroup）
// - 标准命名统一采用 METHOD_<动作> 大写蛇形
// - 一经分配不复用、不重编号
// ====================================================================

// Method ID 常量（service-scoped）
constexpr uint16_t METHOD_GET_SEED = 0x0001;
constexpr uint16_t METHOD_VERIFY_KEY = 0x0002;
constexpr uint16_t METHOD_DERIVE_OTA_SESSION = 0x0003;
constexpr uint16_t METHOD_DERIVE_BY_UID = 0x0004;
constexpr uint16_t METHOD_WRAP_BY_UID = 0x0005;

// Method ID 范围约定
constexpr uint16_t METHOD_ID_MIN = 0x0001;
constexpr uint16_t METHOD_ID_MAX = 0x7FFF;
constexpr uint16_t EVENT_ID_MIN = 0x8000;
constexpr uint16_t EVENT_ID_MAX = 0xFFFF;
```

#### 4.2.2 config/someip_config.yaml

更新 Service ID 和 Instance ID：

```yaml
service_id: 0x7726
instance_id: 0x0001
```

#### 4.2.3 config/vsomeip.json

更新 Service ID 和 Instance ID：

```json
{
    "applications": [
        {
            "name": "cgw-sec",
            "id": "0x7726"
        }
    ],
    "services": [
        {
            "service": "0x7726",
            "instance": "0x0001"
        }
    ],
    "payload-sizes": [
        {
            "service": "0x7726",
            "instance": "0x0001"
        }
    ]
}
```

### 4.3 不改动的文件

| 文件 | 原因 |
|------|------|
| `data_models.h` | SomeipConfig 结构体保持不变，Method ID 通过配置加载 |
| `sec_someip_server.cpp` | 方法处理器已使用 config_ 中的 Method ID |
| `sec_someip_client.cpp` | 客户端已使用 config_ 中的 Method ID |
| `sec_someip_proxy.cpp` | 代理类保持不变 |

---

## 5. 影响分析

### 5.1 接口影响

- 纯接口标准化：不新增/删除方法，不改方法语义与方向
- Event 段（`0x8000+`）为空，仅预留
- §3 标题由「草案」转正

### 5.2 兼容性

- Method ID 值未改变（仍为 `0x0001-0x0005`）
- 仅 Service ID / Instance ID 从临时值更新为正式值
- 需要同步更新所有使用临时值的配置文件

### 5.3 依赖关系

- CGW 模块库 SSOT 已分配 Service ID `0x7726`
- Instance ID `0x0001` 已在模块库中分配
- 与 CGW-SEC-REQ-CR-002 配对

---

## 6. 测试策略

### 6.1 单元测试

- 验证常量值正确性
- 验证配置文件解析正确性

### 6.2 集成测试

- 验证 SOME/IP 服务注册使用正确 ID
- 验证客户端连接使用正确 ID

### 6.3 回归测试

- 确保现有功能不受影响

---

## 7. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| Service ID 冲突 | 服务注册失败 | 使用 CGW 模块库 SSOT 分配值 |
| 配置文件不同步 | 运行时错误 | 统一更新所有配置文件 |
| 常量值与配置不一致 | 逻辑错误 | 配置优先，常量作为文档参考 |

---

## 8. Changelog

- **v1.0**（2026-07-23）：初始设计，对应 CGW-SEC-DSN-CR-002
  - §3 转正并新增 §3.1「方法清单与 Method ID 分配」
  - 为 getSeed/verifyKey/deriveOtaSession/deriveByUid/wrapByUid 指派 Method ID `0x0001–0x0005`
  - 统一 `METHOD_*` 标准命名
  - 明确 service-scoped 分配约定
  - Service ID `0x7726` / Instance ID `0x0001`（SSOT）
  - 纯接口口径定案，无代码改动
