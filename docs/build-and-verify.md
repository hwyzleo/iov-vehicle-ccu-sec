# 构建和验证

## 前置依赖

确保安装了以下依赖：

- CMake 3.10+
- C++17 编译器（GCC 7+, Clang 5+）
- yaml-cpp
- nlohmann_json
- OpenSSL
- Google Test

### macOS (Homebrew)

```bash
brew install cmake yaml-cpp nlohmann-json openssl googletest
```

### Ubuntu/Debian

```bash
sudo apt-get install cmake libyaml-cpp-dev nlohmann-json3-dev libssl-dev libgtest-dev
```

## 构建步骤

运行构建脚本：

```bash
./scripts/build.sh
```

该脚本会：
1. 清理并创建 build 目录
2. 运行 CMake 配置
3. 编译项目
4. 运行所有测试

## 手动构建

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

## 运行测试

```bash
cd build
ctest --output-on-failure
```

## 验证

1. 构建成功完成
2. 所有测试通过
3. 可执行文件 `ccu_sec` 生成于 build 目录

## 故障排除

### 依赖未找到

确保通过包管理器安装了所有依赖，且 CMake 能找到它们。

### 构建失败

1. 删除 build 目录重新构建
2. 检查编译器版本是否支持 C++17
3. 查看构建日志定位错误

### 测试失败

1. 使用 `ctest --output-on-failure` 查看详细输出
2. 单独运行失败的测试进行调试
