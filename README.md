# OpenCL AES-256 & SHA-256 Demo

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)](https://www.microsoft.com/windows)
[![Visual Studio](https://img.shields.io/badge/VS-2022-purple)](https://visualstudio.microsoft.com/)
[![C++](https://img.shields.io/badge/C%2B%2B-17-blue)](https://isocpp.org/)
[![OpenCL](https://img.shields.io/badge/OpenCL-3.0-green)](https://www.khronos.org/opencl/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Windows desktop application demonstrating **GPU-accelerated AES-256 (ECB) and SHA-256** using OpenCL, with real-time CPU-vs-GPU performance comparison. Built with pure Win32 API and managed by vcpkg.

## Features

- **AES-256 Encryption/Decryption (ECB mode)** — GPU parallelized per 16-byte block
- **SHA-256 Hashing** — GPU parallelized across 262,144 independent hashes
- **CPU fallback** — Full CPU implementation for comparison and correctness verification
- **Automatic GPU detection** — Works with NVIDIA, AMD, and Intel GPUs
- **Manual device switching** — Switch between available OpenCL devices at runtime
- **DPI-aware UI** — Proper scaling on high-DPI displays (125% / 150% / 200%)
- **Persistent GPU buffer pool** — Reuses GPU memory across calls to minimize allocation overhead
- **Result verification** — GPU results automatically compared against CPU for correctness

## Screenshot

```
 ┌──────────────────────────────────────────────────────────────┐
 │  OpenCL AES-256 & SHA-256 Demo                               │
 ├──────────────────────────────────────────────────────────────┤
 │  GPU Device: NVIDIA GeForce RTX 3070 | Compute Units: 46     │
 │                                                              │
 │  AES Plaintext / Ciphertext (hex for decrypt):               │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ Hello, OpenCL World!                                  │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  AES Key (32 chars, auto-padded/truncated):                  │
 │  ┌────────────────────────────────┐                          │
 │  │ ThisIsA32ByteKeyForAES256Demo! │                          │
 │  └────────────────────────────────┘                          │
 │  SHA-256 Input Text:                                         │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ Hello, OpenCL Accelerated SHA-256!                   │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  [AES Encrypt (GPU)] [AES Decrypt (GPU)] [AES Encrypt (CPU)]│
 │  [SHA256 Hash (GPU)] [SHA256 Hash (CPU)]                     │
 │                                                              │
 │  Select Device: [▼ NVIDIA GeForce RTX 3070 (46 CU)] [Refresh]│
 │                                                              │
 │  AES Result:                                                 │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ a1b2c3d4...                                          │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  SHA-256 Hash Result:                                        │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ e3b0c44298fc1c14...                                   │   │
 │  └──────────────────────────────────────────────────────┘   │
 │  Performance Comparison:                                     │
 │  ┌──────────────────────────────────────────────────────┐   │
 │  │ === AES-256 Encryption Performance ===               │   │
 │  │ GPU Time: 2.315 ms                                    │   │
 │  │ CPU Time: 45.872 ms                                   │   │
 │  │ Speedup: 19.8x                                        │   │
 │  │ Data Size: 8192 bytes (512 blocks)                    │   │
 │  │ GPU-CPU Result Match: YES                             │   │
 │  └──────────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────┘
```

## Prerequisites

| Requirement | Version | Notes |
|------------|---------|-------|
| Windows | 10 or 11 (64-bit) | |
| Visual Studio | 2022 (or 2019) | Desktop C++ workload |
| vcpkg | ≥ 2023.04.15 | [Installation guide](https://github.com/Microsoft/vcpkg#quick-start-windows) |
| GPU Drivers | Latest | NVIDIA / AMD / Intel with OpenCL support |
| Windows SDK | 10.0 | Included with VS2022 |

## Quick Start

### 1. Install vcpkg (if not already)

```powershell
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
```

### 2. Install OpenCL dependency

```powershell
vcpkg install opencl --triplet x64-windows
vcpkg integrate install
```

### 3. Open and build

1. Open `OpenCL_AES_SHA256_Demo.sln` in Visual Studio 2022
2. Select configuration: **Release | x64**
3. Press **F7** to build
4. Output: `x64\Release\OpenCL_AES_SHA256_Demo.exe`

### 4. Run

The `.cl` kernel files are automatically copied to the output directory during build. Launch the executable — the UI will auto-detect your GPU.

## Project Structure

```
OpenCL_AES_SHA256_Demo/
├── OpenCL_AES_SHA256_Demo.h      # Win32 UI header, control IDs, AppData
├── OpenCL_AES_SHA256_Demo.cpp    # WinMain, WndProc, event handlers
├── OpenCLManager.h               # OpenCL resource manager header
├── OpenCLManager.cpp             # Device enumeration, kernel compilation, buffer pool
├── AES256.h                      # AES-256 algorithm declarations
├── AES256.cpp                    # AES-256 CPU + GPU (ECB mode)
├── SHA256.h                      # SHA-256 algorithm declarations
├── SHA256.cpp                    # SHA-256 CPU + GPU
├── AES256Kernel.cl               # AES-256 OpenCL kernel (encrypt + decrypt)
├── SHA256Kernel.cl               # SHA-256 OpenCL kernel (parallel hashing)
├── vcpkg.json                    # vcpkg dependency manifest
├── OpenCL_AES_SHA256_Demo.vcxproj
└── OpenCL_AES_SHA256_Demo.sln
```

## Architecture

### OpenCLManager

Handles all OpenCL resource lifecycle:

- **Device enumeration** — scans platforms for all GPU and CPU devices
- **Device switching** — runtime reinitialization with a selected device
- **Kernel compilation** — loads `.cl` files and builds kernels on the target device
- **Persistent buffer pool** — reuses GPU memory across calls, avoiding per-operation `clCreateBuffer`/`clReleaseMemObject` overhead

### AES-256 ECB

- **CPU**: Standard FIPS-197 implementation with S-box, MixColumns, KeyExpansion
- **GPU**: Each work-item processes one 16-byte block independently
- **Key**: 256-bit, expanded to 15 round keys (240 bytes) on CPU, uploaded once
- **Padding**: PKCS#7

### SHA-256

- **CPU**: Standard FIPS-180-4 implementation
- **GPU**: 262,144 parallel independent hashes (base input + work-item index as suffix)
- **Hash result**: Always returns the single deterministic hash of the original input

### GPU vs CPU comparison

| Operation | GPU Strategy | CPU Strategy |
|-----------|-------------|-------------|
| AES Encrypt | Parallel per-block | Sequential per-block |
| AES Decrypt | Parallel per-block | Sequential per-block |
| SHA-256 | 262K parallel hashes | 262K sequential hashes |

## Troubleshooting

### "No OpenCL platform found"

Run `vcpkg list opencl` to verify the package is installed. If not:

```powershell
vcpkg install opencl --triplet x64-windows
vcpkg integrate install
```

Restart Visual Studio after integration.

### GPU not detected

- Ensure GPU drivers are up to date (NVIDIA GeForce / AMD Adrenalin / Intel DCH drivers)
- Intel integrated GPUs require the **Intel OpenCL driver** (included with DCH drivers)
- The app will automatically fall back to CPU mode if no GPU is found

### Kernel compilation fails

The build log is captured in the status message. Common causes:
- Outdated GPU drivers
- OpenCL runtime mismatch — ensure vcpkg's OpenCL matches your system's ICD loader

### Blurry UI on high-DPI

The app declares Per-Monitor V2 DPI awareness and scales all controls/fonts by the DPI ratio. If issues persist, ensure you're running Windows 10 1703+.

## License

MIT
