#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>

// Control IDs
#define IDC_EDIT_AES_DATA       1001
#define IDC_EDIT_AES_KEY        1002
#define IDC_EDIT_SHA256_DATA    1003
#define IDC_EDIT_AES_RESULT     1004
#define IDC_EDIT_SHA256_RESULT  1005
#define IDC_STATIC_STATUS       1006
#define IDC_STATIC_TIMING       1007
#define IDC_BUTTON_AES_ENC_GPU  1008
#define IDC_BUTTON_AES_DEC_GPU  1009
#define IDC_BUTTON_SHA256_GPU   1010
#define IDC_BUTTON_AES_ENC_CPU  1011
#define IDC_BUTTON_SHA256_CPU   1012
#define IDC_COMBO_DEVICE        1013
#define IDC_BUTTON_REFRESH_DEV  1014

// Forward declarations
class OpenCLManager;
struct DeviceInfo;

struct AppData
{
    OpenCLManager* pOpenCL;
    std::vector<DeviceInfo> deviceList;

    HWND hEditAesData;
    HWND hEditAesKey;
    HWND hEditSha256Data;
    HWND hEditAesResult;
    HWND hEditSha256Result;
    HWND hStaticStatus;
    HWND hStaticTiming;
    HWND hButtonAesEncGpu;
    HWND hButtonAesDecGpu;
    HWND hButtonSha256Gpu;
    HWND hButtonAesEncCpu;
    HWND hButtonSha256Cpu;
    HWND hComboDevice;
    HWND hButtonRefreshDev;
    HFONT hFont;

    float dpiScale;       // current DPI scale (96 DPI = 1.0)
    int baseClientW;      // unscaled client width (840)
    int baseClientH;      // unscaled client height (735)

    AppData() : pOpenCL(nullptr), hEditAesData(nullptr), hEditAesKey(nullptr),
                hEditSha256Data(nullptr), hEditAesResult(nullptr), hEditSha256Result(nullptr),
                hStaticStatus(nullptr), hStaticTiming(nullptr),
                hButtonAesEncGpu(nullptr), hButtonAesDecGpu(nullptr), hButtonSha256Gpu(nullptr),
                hButtonAesEncCpu(nullptr), hButtonSha256Cpu(nullptr),
                hComboDevice(nullptr), hButtonRefreshDev(nullptr), hFont(nullptr),
                dpiScale(1.0f), baseClientW(840), baseClientH(735) {}
};

// Window procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Helper functions
std::string GetEditText(HWND hEdit);
void SetEditText(HWND hEdit, const std::string& text);
std::string BytesToHex(const unsigned char* data, size_t len);
std::vector<unsigned char> HexToBytes(const std::string& hex);
std::string PadKey(const std::string& key);
void UpdateStatus(HWND hStatus, const std::string& msg);
void SetGpuButtonsEnabled(AppData* pData, bool enabled);

// Populate device combo box and select current device
void PopulateDeviceCombo(AppData* pData);
// Switch to device selected in combo box
void SwitchToSelectedDevice(HWND hWnd, AppData* pData);

// DPI scaling
float GetDpiScale(HWND hWnd);
void CreateControls(HWND hWnd, AppData* pData);
void RepositionControls(HWND hWnd, AppData* pData);
