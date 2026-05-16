# OpenCL AES-256 & SHA-256 加速演示

[![平台](https://img.shields.io/badge/平台-Windows%2010%2F11-blue)](https://www.microsoft.com/windows)
[![Visual Studio](https://img.shields.io/badge/VS-2022-purple)](https://visualstudio.microsoft.com/)
[![C++](https://img.shields.io/badge/C%2B%2B-17-blue)](https://isocpp.org/)
[![OpenCL](https://img.shields.io/badge/OpenCL-3.0-green)](https://www.khronos.org/opencl/)
[![许可证](https://img.shields.io/badge/license-MIT-green)](LICENSE)

一个 Windows 桌面应用程序，演示基于 OpenCL 的 **GPU 加速 AES-256（ECB 模式）和 SHA-256** 运算，实时对比 CPU 与 GPU 性能。纯 Win32 界面，vcpkg 管理依赖。

## 功能特性

- **AES-256 加密/解密（ECB 模式）** — GPU 按 16 字节块并行处理
- **SHA-256 哈希运算** — GPU 并行执行 262,144 次独立哈希
- **CPU 回退** — 完整的 CPU 实现，用于对比和正确性验证
- **自动检测 GPU** — 兼容 NVIDIA、AMD、Intel 显卡
- **手动切换设备** — 运行时在可用 OpenCL 设备间切换
- **DPI 自适应界面** — 高 DPI 缩放（125% / 150% / 200%）下清晰显示
- **持久 GPU 缓冲池** — 复用显存，减少每次操作的分配开销
- **结果校验** — GPU 结果自动与 CPU 对比，确保一致性

## 界面预览

```
 ┌──────────────────────────────────────────────────────────────┐
 │  OpenCL AES-256 & SHA-256 Demo                               │
 ├──────────────────────────────────────────────────────────────┤
 │  GPU Device: NVIDIA GeForce RTX 3070 | Compute Units: 46     │
 │                                                              │
 │  AES 明文 / 密文（解密时输入十六进制）:                       │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ Hello, OpenCL World!                                  │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  AES 密钥（32 字符，自动填充/截断）:                         │
 │  ┌────────────────────────────────┐                          │
 │  │ ThisIsA32ByteKeyForAES256Demo! │                          │
 │  └────────────────────────────────┘                          │
 │  SHA-256 输入文本:                                           │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ Hello, OpenCL Accelerated SHA-256!                   │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  [AES 加密 (GPU)] [AES 解密 (GPU)] [AES 加密 (CPU)]          │
 │  [SHA256 哈希 (GPU)] [SHA256 哈希 (CPU)]                     │
 │                                                              │
 │  选择设备: [▼ NVIDIA GeForce RTX 3070 (46 CU)] [刷新]        │
 │                                                              │
 │  AES 结果:                                                   │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ a1b2c3d4...                                          │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  SHA-256 哈希结果:                                           │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ e3b0c44298fc1c14...                                   │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  性能对比:                                                   │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ === AES-256 加密性能 ===                             │   │
 │  │ GPU 耗时: 2.315 ms                                    │   │
 │  │ CPU 耗时: 45.872 ms                                   │   │
 │  │ 加速比: 19.8x                                         │   │
 │  │ 数据量: 8192 字节 (512 块)                            │   │
 │  │ GPU-CPU 结果一致: 是                                  │   │
 │  └──────────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────┘
```

## 环境要求

| 项目 | 版本 | 说明 |
|------|------|------|
| Windows | 10 或 11（64 位） | |
| Visual Studio | 2022（或 2019） | 需安装 C++ 桌面开发工作负载 |
| vcpkg | ≥ 2023.04.15 | [安装指南](https://github.com/Microsoft/vcpkg#quick-start-windows) |
| GPU 驱动 | 最新 | NVIDIA / AMD / Intel，需支持 OpenCL |
| Windows SDK | 10.0 | VS2022 自带 |

## 快速开始

### 1. 安装 vcpkg（如已安装可跳过）

```powershell
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
```

### 2. 安装 OpenCL 依赖

```powershell
vcpkg install opencl --triplet x64-windows
vcpkg integrate install
```

### 3. 打开并编译

1. 用 Visual Studio 2022 打开 `OpenCL_AES_SHA256_Demo.sln`
2. 选择配置：**Release | x64**
3. 按 **F7** 编译
4. 输出路径：`x64\Release\OpenCL_AES_SHA256_Demo.exe`

### 4. 运行

`.cl` 内核文件会在编译时自动复制到输出目录。直接运行可执行文件，程序会自动检测 GPU。

## 工程结构

```
OpenCL_AES_SHA256_Demo/
├── OpenCL_AES_SHA256_Demo.h      # Win32 界面头文件、控件 ID、AppData
├── OpenCL_AES_SHA256_Demo.cpp    # WinMain、WndProc、事件处理
├── OpenCLManager.h               # OpenCL 资源管理器头文件
├── OpenCLManager.cpp             # 设备枚举、内核编译、缓冲池
├── AES256.h                      # AES-256 算法声明
├── AES256.cpp                    # AES-256 CPU + GPU（ECB 模式）
├── SHA256.h                      # SHA-256 算法声明
├── SHA256.cpp                    # SHA-256 CPU + GPU
├── AES256Kernel.cl               # AES-256 OpenCL 内核（加密 + 解密）
├── SHA256Kernel.cl               # SHA-256 OpenCL 内核（并行哈希）
├── vcpkg.json                    # vcpkg 依赖清单
├── OpenCL_AES_SHA256_Demo.vcxproj
└── OpenCL_AES_SHA256_Demo.sln
```

## 架构设计

### OpenCLManager

管理 OpenCL 资源全生命周期：

- **设备枚举** — 扫描所有平台，列出 GPU 和 CPU 设备
- **设备切换** — 运行时重新初始化到选定设备
- **内核编译** — 读取 `.cl` 文件并在目标设备上编译
- **持久缓冲池** — 复用 GPU 显存，避免每次操作调用 `clCreateBuffer`/`clReleaseMemObject`

### AES-256 ECB

- **CPU**：标准 FIPS-197 实现（S 盒、列混淆、密钥扩展）
- **GPU**：每个 work-item 独立处理一个 16 字节块
- **密钥**：256 位，CPU 扩展为 15 轮密钥（240 字节），一次性上传
- **填充**：PKCS#7

### SHA-256

- **CPU**：标准 FIPS-180-4 实现
- **GPU**：262,144 次并行独立哈希（基础输入 + work-item 索引后缀）
- **哈希结果**：始终返回原始输入的确定性哈希值

### GPU 与 CPU 对比策略

| 运算 | GPU 策略 | CPU 策略 |
|------|---------|---------|
| AES 加密 | 按块并行 | 逐块顺序 |
| AES 解密 | 按块并行 | 逐块顺序 |
| SHA-256 | 262K 并行哈希 | 262K 顺序哈希 |

## 常见问题

### "未找到 OpenCL 平台"

运行 `vcpkg list opencl` 确认包已安装。若未安装：

```powershell
vcpkg install opencl --triplet x64-windows
vcpkg integrate install
```

安装后重启 Visual Studio。

### 检测不到 GPU

- 确保显卡驱动已更新（NVIDIA GeForce / AMD Adrenalin / Intel DCH 驱动）
- Intel 集成显卡需安装 **Intel OpenCL 驱动**（DCH 驱动自带）
- 无 GPU 时程序自动回退到 CPU 模式

### 内核编译失败

状态栏会显示编译日志。常见原因：
- GPU 驱动过旧
- OpenCL 运行时不匹配 — 确保 vcpkg 的 OpenCL 与系统 ICD 加载器一致

### 高 DPI 下界面模糊

程序已声明 Per-Monitor V2 DPI 感知，所有控件和字体按 DPI 比例缩放。如仍有问题，请确保使用 Windows 10 1703 及以上版本。

## 许可证

MIT
