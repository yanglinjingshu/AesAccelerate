#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cstdint>

#include "OpenCL_AES_SHA256_Demo.h"
#include "OpenCLManager.h"
#include "AES256.h"
#include "SHA256.h"

// Global instance handle
static HINSTANCE g_hInst = nullptr;

// ============================================================================
// Helper Functions
// ============================================================================

std::string GetEditText(HWND hEdit)
{
    int len = GetWindowTextLengthA(hEdit);
    if (len <= 0) return "";
    std::string text(len, '\0');
    GetWindowTextA(hEdit, &text[0], len + 1);
    text.resize(strlen(text.c_str()));
    return text;
}

void SetEditText(HWND hEdit, const std::string& text)
{
    SetWindowTextA(hEdit, text.c_str());
}

std::string BytesToHex(const unsigned char* data, size_t len)
{
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

std::vector<unsigned char> HexToBytes(const std::string& hex)
{
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2)
    {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        bytes.push_back((unsigned char)byte);
    }
    return bytes;
}

std::string PadKey(const std::string& key)
{
    if (key.length() >= 32)
        return key.substr(0, 32);
    std::string padded = key;
    padded.append(32 - padded.length(), '0');
    return padded;
}

void UpdateStatus(HWND hStatus, const std::string& msg)
{
    SetWindowTextA(hStatus, msg.c_str());
}

void SetGpuButtonsEnabled(AppData* pData, bool enabled)
{
    if (!pData) return;
    EnableWindow(pData->hButtonAesEncGpu, enabled ? TRUE : FALSE);
    EnableWindow(pData->hButtonAesDecGpu, enabled ? TRUE : FALSE);
    EnableWindow(pData->hButtonSha256Gpu, enabled ? TRUE : FALSE);
}

// ============================================================================
// Button Click Handlers
// ============================================================================

void OnAesEncryptGpu(AppData* pData)
{
    if (!pData || !pData->pOpenCL || !pData->pOpenCL->IsInitialized())
    {
        MessageBoxA(nullptr, "OpenCL not initialized. GPU acceleration unavailable.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string plainText = GetEditText(pData->hEditAesData);
    std::string keyText = GetEditText(pData->hEditAesKey);

    if (plainText.empty())
    {
        MessageBoxA(nullptr, "Please enter plaintext to encrypt.", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }
    if (keyText.empty())
    {
        MessageBoxA(nullptr, "Please enter an AES key (32 characters).", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }

    std::string paddedKey = PadKey(keyText);

    try
    {
        std::vector<uint8_t> plainBytes(plainText.begin(), plainText.end());
        std::vector<uint8_t> keyBytes(paddedKey.begin(), paddedKey.end());
        std::vector<uint8_t> cipherBytes;

        double gpuTime = AES256::GpuEncrypt(plainBytes, keyBytes, cipherBytes, *pData->pOpenCL);

        std::string hexResult = BytesToHex(cipherBytes.data(), cipherBytes.size());
        SetEditText(pData->hEditAesResult, hexResult);

        // Compare with CPU for the same data
        std::vector<uint8_t> cpuCipher;
        double cpuTime = AES256::CpuEncrypt(plainBytes, keyBytes, cpuCipher);

        // Verify correctness
        bool match = (cipherBytes == cpuCipher);

        std::ostringstream timing;
        timing << "=== AES-256 Encryption Performance ===\n"
               << "GPU Time: " << std::fixed << std::setprecision(3) << gpuTime << " ms\n"
               << "CPU Time: " << std::fixed << std::setprecision(3) << cpuTime << " ms\n"
               << "Speedup: " << std::fixed << std::setprecision(1) << (cpuTime / gpuTime) << "x\n"
               << "Data Size: " << plainBytes.size() << " bytes (" << (plainBytes.size() + 15) / 16 << " blocks)\n"
               << "GPU-CPU Result Match: " << (match ? "YES" : "NO - MISMATCH!");
        if (!match)
            timing << "\nWARNING: GPU and CPU results differ!";

        SetEditText(pData->hStaticTiming, timing.str());
        UpdateStatus(pData->hStaticStatus, "AES GPU encryption completed. " +
                    std::to_string((int)(cpuTime / gpuTime)) + "x speedup vs CPU.");
    }
    catch (const std::exception& e)
    {
        MessageBoxA(nullptr, e.what(), "AES GPU Encryption Error", MB_OK | MB_ICONERROR);
        UpdateStatus(pData->hStaticStatus, "AES GPU encryption failed.");
    }
}

void OnAesDecryptGpu(AppData* pData)
{
    if (!pData || !pData->pOpenCL || !pData->pOpenCL->IsInitialized())
    {
        MessageBoxA(nullptr, "OpenCL not initialized. GPU acceleration unavailable.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string hexCipherText = GetEditText(pData->hEditAesData);
    std::string keyText = GetEditText(pData->hEditAesKey);

    if (hexCipherText.empty())
    {
        MessageBoxA(nullptr, "Please enter ciphertext (hex) to decrypt.", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }
    if (keyText.empty())
    {
        MessageBoxA(nullptr, "Please enter an AES key (32 characters).", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }

    std::string paddedKey = PadKey(keyText);

    try
    {
        // Try to interpret input as hex
        std::vector<uint8_t> cipherBytes = HexToBytes(hexCipherText);
        if (cipherBytes.empty() || cipherBytes.size() % 16 != 0)
        {
            MessageBoxA(nullptr, "Invalid ciphertext. Must be hexadecimal and multiple of 16 bytes.",
                       "Input Error", MB_OK | MB_ICONWARNING);
            return;
        }

        std::vector<uint8_t> keyBytes(paddedKey.begin(), paddedKey.end());
        std::vector<uint8_t> plainBytes;

        double gpuTime = AES256::GpuDecrypt(cipherBytes, keyBytes, plainBytes, *pData->pOpenCL);

        std::string plainText(plainBytes.begin(), plainBytes.end());
        SetEditText(pData->hEditAesResult, plainText);

        // Compare with CPU
        std::vector<uint8_t> cpuPlain;
        double cpuTime = AES256::CpuDecrypt(cipherBytes, keyBytes, cpuPlain);

        bool match = (plainBytes == cpuPlain);

        std::ostringstream timing;
        timing << "=== AES-256 Decryption Performance ===\n"
               << "GPU Time: " << std::fixed << std::setprecision(3) << gpuTime << " ms\n"
               << "CPU Time: " << std::fixed << std::setprecision(3) << cpuTime << " ms\n"
               << "Speedup: " << std::fixed << std::setprecision(1) << (cpuTime / std::max(gpuTime, 0.001)) << "x\n"
               << "Data Size: " << cipherBytes.size() << " bytes (" << cipherBytes.size() / 16 << " blocks)\n"
               << "GPU-CPU Result Match: " << (match ? "YES" : "NO - MISMATCH!");
        if (!match)
            timing << "\nWARNING: GPU and CPU results differ!";

        SetEditText(pData->hStaticTiming, timing.str());
        UpdateStatus(pData->hStaticStatus, "AES GPU decryption completed.");
    }
    catch (const std::exception& e)
    {
        MessageBoxA(nullptr, e.what(), "AES GPU Decryption Error", MB_OK | MB_ICONERROR);
        UpdateStatus(pData->hStaticStatus, "AES GPU decryption failed.");
    }
}

void OnSha256Gpu(AppData* pData)
{
    if (!pData || !pData->pOpenCL || !pData->pOpenCL->IsInitialized())
    {
        MessageBoxA(nullptr, "OpenCL not initialized. GPU acceleration unavailable.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string inputText = GetEditText(pData->hEditSha256Data);
    if (inputText.empty())
    {
        MessageBoxA(nullptr, "Please enter text to hash.", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }

    try
    {
        unsigned int numHashes = 262144; // 256K parallel hashes
        std::string hashHex;

        double gpuTime = SHA256::GpuHash(inputText, hashHex, *pData->pOpenCL, numHashes);
        SetEditText(pData->hEditSha256Result, hashHex);

        // CPU comparison
        std::string cpuHashHex;
        double cpuTime = SHA256::CpuHash(inputText, cpuHashHex, numHashes);

        std::ostringstream timing;
        timing << "=== SHA-256 Hash Performance ===\n"
               << "GPU Time: " << std::fixed << std::setprecision(3) << gpuTime << " ms ("
               << numHashes << " parallel hashes)\n"
               << "CPU Time: " << std::fixed << std::setprecision(3) << cpuTime << " ms ("
               << numHashes << " sequential hashes)\n"
               << "Speedup: " << std::fixed << std::setprecision(1) << (cpuTime / gpuTime) << "x\n"
               << "Per-Hash GPU: " << std::fixed << std::setprecision(3) << (gpuTime / numHashes * 1000.0) << " us\n"
               << "Per-Hash CPU: " << std::fixed << std::setprecision(3) << (cpuTime / numHashes * 1000.0) << " us\n"
               << "Hash Result: " << hashHex;

        SetEditText(pData->hStaticTiming, timing.str());
        UpdateStatus(pData->hStaticStatus, "SHA256 GPU hash completed. " +
                    std::to_string((int)(cpuTime / gpuTime)) + "x speedup vs CPU.");
    }
    catch (const std::exception& e)
    {
        MessageBoxA(nullptr, e.what(), "SHA256 GPU Error", MB_OK | MB_ICONERROR);
        UpdateStatus(pData->hStaticStatus, "SHA256 GPU hash failed.");
    }
}

void OnAesEncryptCpu(AppData* pData)
{
    std::string plainText = GetEditText(pData->hEditAesData);
    std::string keyText = GetEditText(pData->hEditAesKey);

    if (plainText.empty())
    {
        MessageBoxA(nullptr, "Please enter plaintext to encrypt.", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }
    if (keyText.empty())
    {
        MessageBoxA(nullptr, "Please enter an AES key (32 characters).", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }

    std::string paddedKey = PadKey(keyText);

    try
    {
        std::vector<uint8_t> plainBytes(plainText.begin(), plainText.end());
        std::vector<uint8_t> keyBytes(paddedKey.begin(), paddedKey.end());
        std::vector<uint8_t> cipherBytes;

        double cpuTime = AES256::CpuEncrypt(plainBytes, keyBytes, cipherBytes);

        std::string hexResult = BytesToHex(cipherBytes.data(), cipherBytes.size());
        SetEditText(pData->hEditAesResult, hexResult);

        std::ostringstream timing;
        timing << "=== AES-256 CPU Encryption ===\n"
               << "CPU Time: " << std::fixed << std::setprecision(3) << cpuTime << " ms\n"
               << "Data Size: " << plainBytes.size() << " bytes\n"
               << "Result (hex): " << hexResult;

        SetEditText(pData->hStaticTiming, timing.str());
        UpdateStatus(pData->hStaticStatus, "AES CPU encryption completed.");
    }
    catch (const std::exception& e)
    {
        MessageBoxA(nullptr, e.what(), "AES CPU Encryption Error", MB_OK | MB_ICONERROR);
        UpdateStatus(pData->hStaticStatus, "AES CPU encryption failed.");
    }
}

void OnSha256Cpu(AppData* pData)
{
    std::string inputText = GetEditText(pData->hEditSha256Data);
    if (inputText.empty())
    {
        MessageBoxA(nullptr, "Please enter text to hash.", "Input Required", MB_OK | MB_ICONWARNING);
        return;
    }

    try
    {
        std::string hashHex = SHA256::Hash(inputText);
        SetEditText(pData->hEditSha256Result, hashHex);

        // Also measure 256K hashes timing for comparison
        unsigned int numHashes = 262144;
        std::string dummyHash;
        auto start = std::chrono::high_resolution_clock::now();
        for (unsigned int i = 0; i < numHashes; i++)
        {
            std::string indexed = inputText + std::to_string(i);
            dummyHash = SHA256::Hash(indexed);
        }
        auto end = std::chrono::high_resolution_clock::now();
        double cpuTime = std::chrono::duration<double, std::milli>(end - start).count();

        std::ostringstream timing;
        timing << "=== SHA-256 CPU Hash ===\n"
               << "CPU Time (" << numHashes << " hashes): " << std::fixed << std::setprecision(3) << cpuTime << " ms\n"
               << "Per-Hash CPU: " << std::fixed << std::setprecision(3) << (cpuTime / numHashes * 1000.0) << " us\n"
               << "Hash Result (input): " << hashHex;

        SetEditText(pData->hStaticTiming, timing.str());
        UpdateStatus(pData->hStaticStatus, "SHA256 CPU hash completed.");
    }
    catch (const std::exception& e)
    {
        MessageBoxA(nullptr, e.what(), "SHA256 CPU Error", MB_OK | MB_ICONERROR);
        UpdateStatus(pData->hStaticStatus, "SHA256 CPU hash failed.");
    }
}

// ============================================================================
// Device Switching Helpers
// ============================================================================

void PopulateDeviceCombo(AppData* pData)
{
    if (!pData || !pData->hComboDevice) return;

    SendMessage(pData->hComboDevice, CB_RESETCONTENT, 0, 0);

    pData->deviceList = OpenCLManager::EnumerateDevices();

    int selIdx = 0;
    for (size_t i = 0; i < pData->deviceList.size(); i++)
    {
        const auto& d = pData->deviceList[i];
        std::string item = "[" + d.GetTypeStr() + "] " + d.name +
                          " (" + std::to_string(d.computeUnits) + " CU, " +
                          std::to_string(d.globalMemSize) + " MB) [" + d.platformName + "]";
        SendMessageA(pData->hComboDevice, CB_ADDSTRING, 0, (LPARAM)item.c_str());

        // Select the currently active device
        if (pData->pOpenCL && pData->pOpenCL->IsInitialized() &&
            pData->pOpenCL->GetDeviceName() == d.name)
        {
            selIdx = (int)i;
        }
    }

    if (pData->deviceList.empty())
    {
        SendMessageA(pData->hComboDevice, CB_ADDSTRING, 0, (LPARAM)"No OpenCL devices found");
    }

    SendMessage(pData->hComboDevice, CB_SETCURSEL, (WPARAM)selIdx, 0);
}

void SwitchToSelectedDevice(HWND hWnd, AppData* pData)
{
    if (!pData || !pData->hComboDevice) return;

    int selIdx = (int)SendMessage(pData->hComboDevice, CB_GETCURSEL, 0, 0);
    if (selIdx < 0 || selIdx >= (int)pData->deviceList.size())
        return;

    const DeviceInfo& di = pData->deviceList[selIdx];

    // Check if already using this device
    if (pData->pOpenCL && pData->pOpenCL->IsInitialized() &&
        pData->pOpenCL->GetDeviceName() == di.name)
    {
        UpdateStatus(pData->hStaticStatus, "Already using: " + di.name);
        return;
    }

    UpdateStatus(pData->hStaticStatus, "Switching to: " + di.name + "...");

    if (!pData->pOpenCL->InitWithDevice(di))
    {
        std::string err = "Failed to switch device: " + pData->pOpenCL->GetStatusMessage();
        UpdateStatus(pData->hStaticStatus, err);
        MessageBoxA(hWnd, err.c_str(), "Device Switch Failed", MB_OK | MB_ICONERROR);
        SetGpuButtonsEnabled(pData, false);
        return;
    }

    SetGpuButtonsEnabled(pData, true);

    std::string msg = "Device: " + di.name +
                      " | Compute Units: " + std::to_string(di.computeUnits) +
                      " | Type: " + di.GetTypeStr();
    UpdateStatus(pData->hStaticStatus, msg);
}

// ============================================================================
// DPI Scaling Helpers
// ============================================================================

float GetDpiScale(HWND hWnd)
{
    if (hWnd)
    {
        UINT dpi = GetDpiForWindow(hWnd);
        return dpi / 96.0f;
    }
    HDC hdc = GetDC(nullptr);
    float scale = GetDeviceCaps(hdc, LOGPIXELSX) / 96.0f;
    ReleaseDC(nullptr, hdc);
    return scale;
}

// ============================================================================
// Win32 Window Creation and Control Layout
// ============================================================================

void CreateControls(HWND hWnd, AppData* pData)
{
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE);
    float s = pData->dpiScale;

    auto S = [s](int v) -> int { return (int)(v * s); };

    int y = S(5);
    int leftMargin = S(10);
    int labelHeight = S(20);
    int editSingleHeight = S(24);
    int gap = S(5);
    int btnHeight = S(34);
    int btnWidth = S(160);
    int clientWidth = S(840);

    // Title / Status
    pData->hStaticStatus = CreateWindowExA(0, "STATIC",
        "Initializing...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, S(24),
        hWnd, (HMENU)IDC_STATIC_STATUS, hInst, nullptr);
    y += S(24) + gap;

    // AES Data label
    CreateWindowExA(0, "STATIC", "AES Plaintext / Ciphertext (hex for decrypt):",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, labelHeight,
        hWnd, nullptr, hInst, nullptr);
    y += labelHeight;

    pData->hEditAesData = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
        leftMargin, y, clientWidth - 2 * leftMargin, S(72),
        hWnd, (HMENU)IDC_EDIT_AES_DATA, hInst, nullptr);
    y += S(72) + gap;

    // AES Key label
    CreateWindowExA(0, "STATIC", "AES Key (32 chars, auto-padded/truncated):",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, labelHeight,
        hWnd, nullptr, hInst, nullptr);
    y += labelHeight;

    pData->hEditAesKey = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "ThisIsA32ByteKeyForAES256Demo!",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        leftMargin, y, S(420), editSingleHeight,
        hWnd, (HMENU)IDC_EDIT_AES_KEY, hInst, nullptr);
    y += editSingleHeight + gap;

    // SHA256 Data label
    CreateWindowExA(0, "STATIC", "SHA-256 Input Text:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, labelHeight,
        hWnd, nullptr, hInst, nullptr);
    y += labelHeight;

    pData->hEditSha256Data = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT",
        "Hello, OpenCL Accelerated SHA-256!",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
        leftMargin, y, clientWidth - 2 * leftMargin, S(48),
        hWnd, (HMENU)IDC_EDIT_SHA256_DATA, hInst, nullptr);
    y += S(48) + gap;

    // Buttons row
    pData->hButtonAesEncGpu = CreateWindowExA(0, "BUTTON", "AES Encrypt (GPU)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftMargin, y, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BUTTON_AES_ENC_GPU, hInst, nullptr);

    pData->hButtonAesDecGpu = CreateWindowExA(0, "BUTTON", "AES Decrypt (GPU)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftMargin + btnWidth + S(5), y, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BUTTON_AES_DEC_GPU, hInst, nullptr);

    pData->hButtonAesEncCpu = CreateWindowExA(0, "BUTTON", "AES Encrypt (CPU)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftMargin + 2 * (btnWidth + S(5)), y, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BUTTON_AES_ENC_CPU, hInst, nullptr);

    pData->hButtonSha256Gpu = CreateWindowExA(0, "BUTTON", "SHA256 Hash (GPU)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftMargin + 3 * (btnWidth + S(5)), y, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BUTTON_SHA256_GPU, hInst, nullptr);

    pData->hButtonSha256Cpu = CreateWindowExA(0, "BUTTON", "SHA256 Hash (CPU)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftMargin + 4 * (btnWidth + S(5)), y, btnWidth, btnHeight,
        hWnd, (HMENU)IDC_BUTTON_SHA256_CPU, hInst, nullptr);
    y += btnHeight + gap;

    // Device selector row
    CreateWindowExA(0, "STATIC", "Select Device:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, S(120), labelHeight,
        hWnd, nullptr, hInst, nullptr);

    pData->hComboDevice = CreateWindowExA(0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        leftMargin, y + labelHeight, S(620), 200,
        hWnd, (HMENU)IDC_COMBO_DEVICE, hInst, nullptr);

    pData->hButtonRefreshDev = CreateWindowExA(0, "BUTTON", "Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftMargin + S(630), y + labelHeight, S(85), editSingleHeight,
        hWnd, (HMENU)IDC_BUTTON_REFRESH_DEV, hInst, nullptr);
    y += labelHeight + editSingleHeight + gap;

    // AES Result label
    CreateWindowExA(0, "STATIC", "AES Result (hex or decrypted text):",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, labelHeight,
        hWnd, nullptr, hInst, nullptr);
    y += labelHeight;

    pData->hEditAesResult = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        leftMargin, y, clientWidth - 2 * leftMargin, S(72),
        hWnd, (HMENU)IDC_EDIT_AES_RESULT, hInst, nullptr);
    y += S(72) + gap;

    // SHA256 Result label
    CreateWindowExA(0, "STATIC", "SHA-256 Hash Result (64 hex chars):",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, labelHeight,
        hWnd, nullptr, hInst, nullptr);
    y += labelHeight;

    pData->hEditSha256Result = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        leftMargin, y, clientWidth - 2 * leftMargin, editSingleHeight,
        hWnd, (HMENU)IDC_EDIT_SHA256_RESULT, hInst, nullptr);
    y += editSingleHeight + gap;

    // Timing info label
    CreateWindowExA(0, "STATIC", "Performance Comparison:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, labelHeight,
        hWnd, nullptr, hInst, nullptr);
    y += labelHeight;

    pData->hStaticTiming = CreateWindowExA(WS_EX_CLIENTEDGE, "STATIC",
        "Click a button to start benchmarking...",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftMargin, y, clientWidth - 2 * leftMargin, S(120),
        hWnd, (HMENU)IDC_STATIC_TIMING, hInst, nullptr);

    // Set scaled font for all controls
    int fontSize = (int)(15 * s);
    pData->hFont = CreateFontA(fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Consolas");

    HWND hChild = GetWindow(hWnd, GW_CHILD);
    while (hChild)
    {
        SendMessage(hChild, WM_SETFONT, (WPARAM)pData->hFont, TRUE);
        hChild = GetWindow(hChild, GW_HWNDNEXT);
    }
}

void RepositionControls(HWND hWnd, AppData* pData)
{
    float s = pData->dpiScale;
    auto S = [s](int v) -> int { return (int)(v * s); };

    int leftMargin = S(10);
    int labelHeight = S(20);
    int editSingleHeight = S(24);
    int gap = S(5);
    int btnHeight = S(34);
    int btnWidth = S(160);
    int clientWidth = S(840);

    int y = S(5);

    // Status
    SetWindowPos(pData->hStaticStatus, nullptr,
        leftMargin, y, clientWidth - 2 * leftMargin, S(24),
        SWP_NOZORDER | SWP_NOACTIVATE);
    y += S(24) + gap;

    // AES Data label
    HWND hLabel = GetWindow(hWnd, GW_CHILD);
    while (hLabel)
    {
        char cls[32];
        GetClassNameA(hLabel, cls, sizeof(cls));
        if (strcmp(cls, "Static") != 0 && strcmp(cls, "STATIC") != 0)
        {
            hLabel = GetWindow(hLabel, GW_HWNDNEXT);
            continue;
        }
        char txt[256];
        GetWindowTextA(hLabel, txt, sizeof(txt));
        if (strstr(txt, "AES Plaintext"))
            break;
        hLabel = GetWindow(hLabel, GW_HWNDNEXT);
    }
    // Fallback: just set sizes for all known controls
    SetWindowPos(pData->hEditAesData, nullptr,
        leftMargin, S(400), clientWidth - 2 * leftMargin, S(72),
        SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hEditAesKey, nullptr,
        leftMargin, S(400), S(420), editSingleHeight,
        SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hEditSha256Data, nullptr,
        leftMargin, S(400), clientWidth - 2 * leftMargin, S(48),
        SWP_NOZORDER | SWP_NOACTIVATE);

    // Buttons
    SetWindowPos(pData->hButtonAesEncGpu, nullptr,
        leftMargin, S(400), btnWidth, btnHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hButtonAesDecGpu, nullptr,
        leftMargin + btnWidth + S(5), S(400), btnWidth, btnHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hButtonAesEncCpu, nullptr,
        leftMargin + 2 * (btnWidth + S(5)), S(400), btnWidth, btnHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hButtonSha256Gpu, nullptr,
        leftMargin + 3 * (btnWidth + S(5)), S(400), btnWidth, btnHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hButtonSha256Cpu, nullptr,
        leftMargin + 4 * (btnWidth + S(5)), S(400), btnWidth, btnHeight, SWP_NOZORDER | SWP_NOACTIVATE);

    // Combo + Refresh
    SetWindowPos(pData->hComboDevice, nullptr,
        leftMargin, S(400), S(620), 200, SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hButtonRefreshDev, nullptr,
        leftMargin + S(630), S(400), S(85), editSingleHeight, SWP_NOZORDER | SWP_NOACTIVATE);

    // Result edits
    SetWindowPos(pData->hEditAesResult, nullptr,
        leftMargin, S(400), clientWidth - 2 * leftMargin, S(72), SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hEditSha256Result, nullptr,
        leftMargin, S(400), clientWidth - 2 * leftMargin, editSingleHeight, SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(pData->hStaticTiming, nullptr,
        leftMargin, S(400), clientWidth - 2 * leftMargin, S(120), SWP_NOZORDER | SWP_NOACTIVATE);

    // Recreate scaled font
    if (pData->hFont)
        DeleteObject(pData->hFont);
    int fontSize = (int)(15 * s);
    pData->hFont = CreateFontA(fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Consolas");

    HWND hChild = GetWindow(hWnd, GW_CHILD);
    while (hChild)
    {
        SendMessage(hChild, WM_SETFONT, (WPARAM)pData->hFont, TRUE);
        hChild = GetWindow(hChild, GW_HWNDNEXT);
    }
}

// ============================================================================
// Window Procedure
// ============================================================================

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    AppData* pData = (AppData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

    switch (msg)
    {
    case WM_CREATE:
    {
        // Allocate application data
        pData = new AppData();
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pData);

        // Compute DPI scale before creating controls
        pData->dpiScale = GetDpiScale(hWnd);

        // Create all UI controls (uses dpiScale)
        CreateControls(hWnd, pData);

        // Initialize OpenCL
        pData->pOpenCL = new OpenCLManager();
        UpdateStatus(pData->hStaticStatus, "Detecting OpenCL devices...");

        if (pData->pOpenCL->Init())
        {
            std::string msg = "GPU Device: " + pData->pOpenCL->GetDeviceName() +
                              " | Compute Units: " + std::to_string(pData->pOpenCL->GetComputeUnits());
            UpdateStatus(pData->hStaticStatus, msg);
        }
        else
        {
            std::string errMsg = pData->pOpenCL->GetStatusMessage();
            UpdateStatus(pData->hStaticStatus, errMsg + " - GPU buttons disabled. CPU mode available.");
            SetGpuButtonsEnabled(pData, false);
            MessageBoxA(hWnd,
                (errMsg + "\n\nPlease install OpenCL dependencies via vcpkg:\n"
                 "  vcpkg install opencl --triplet x64-windows\n"
                 "  vcpkg integrate install\n\n"
                 "CPU encryption/hashing is still available.").c_str(),
                "OpenCL Initialization Failed", MB_OK | MB_ICONWARNING);
        }

        // Populate device combo box after initialization
        PopulateDeviceCombo(pData);

        return 0;
    }

    case WM_COMMAND:
    {
        int ctrlId = LOWORD(wParam);
        int notifyCode = HIWORD(wParam);

        // Handle combo box device selection change
        if (notifyCode == CBN_SELCHANGE && ctrlId == IDC_COMBO_DEVICE && pData)
        {
            SwitchToSelectedDevice(hWnd, pData);
            return 0;
        }

        if (notifyCode == BN_CLICKED && pData)
        {
            switch (ctrlId)
            {
            case IDC_BUTTON_AES_ENC_GPU:
                UpdateStatus(pData->hStaticStatus, "Running AES GPU encryption...");
                OnAesEncryptGpu(pData);
                break;

            case IDC_BUTTON_AES_DEC_GPU:
                UpdateStatus(pData->hStaticStatus, "Running AES GPU decryption...");
                OnAesDecryptGpu(pData);
                break;

            case IDC_BUTTON_SHA256_GPU:
                UpdateStatus(pData->hStaticStatus, "Running SHA256 GPU hash...");
                OnSha256Gpu(pData);
                break;

            case IDC_BUTTON_AES_ENC_CPU:
                UpdateStatus(pData->hStaticStatus, "Running AES CPU encryption...");
                OnAesEncryptCpu(pData);
                break;

            case IDC_BUTTON_SHA256_CPU:
                UpdateStatus(pData->hStaticStatus, "Running SHA256 CPU hash...");
                OnSha256Cpu(pData);
                break;

            case IDC_BUTTON_REFRESH_DEV:
                UpdateStatus(pData->hStaticStatus, "Refreshing device list...");
                PopulateDeviceCombo(pData);
                UpdateStatus(pData->hStaticStatus, "Device list refreshed.");
                break;
            }
        }
        return 0;
    }

    case WM_DPICHANGED:
    {
        if (pData)
        {
            pData->dpiScale = GetDpiScale(hWnd);
            RepositionControls(hWnd, pData);

            // Resize window to match new DPI
            RECT* pRect = (RECT*)lParam;
            SetWindowPos(hWnd, nullptr,
                pRect->left, pRect->top,
                pRect->right - pRect->left,
                pRect->bottom - pRect->top,
                SWP_NOZORDER | SWP_NOACTIVATE);
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;

    case WM_NCDESTROY:
    {
        // Cleanup application data
        if (pData)
        {
            if (pData->pOpenCL)
            {
                pData->pOpenCL->Release();
                delete pData->pOpenCL;
                pData->pOpenCL = nullptr;
            }
            if (pData->hFont)
            {
                DeleteObject(pData->hFont);
                pData->hFont = nullptr;
            }
            delete pData;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, 0);
        }
        return 0;
    }
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ============================================================================
// WinMain Entry Point
// ============================================================================

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Set DPI awareness to prevent blurry UI on high-DPI displays
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    g_hInst = hInstance;

    // Compute scaled window size from system DPI
    UINT sysDpi = GetDpiForSystem();
    float initScale = sysDpi / 96.0f;
    int clientW = (int)(840 * initScale);
    int clientH = (int)(735 * initScale);

    // Register window class
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconA(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = "OpenCL_AES_SHA256_Demo";
    wc.hIconSm = LoadIconA(nullptr, IDI_APPLICATION);

    if (!RegisterClassExA(&wc))
    {
        MessageBoxA(nullptr, "Window registration failed.", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }

    // Compute window size from desired client area
    RECT rc = { 0, 0, clientW, clientH };
    DWORD style = WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME;
    AdjustWindowRectEx(&rc, style, FALSE, 0);

    // Create main window
    HWND hWnd = CreateWindowExA(0, "OpenCL_AES_SHA256_Demo",
        "OpenCL AES-256 & SHA-256 Demo",
        style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        MessageBoxA(nullptr, "Window creation failed.", "Error", MB_OK | MB_ICONERROR);
        return -1;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
