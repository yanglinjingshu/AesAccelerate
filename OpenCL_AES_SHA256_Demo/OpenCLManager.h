#pragma once

#include <CL/cl.h>
#include <string>
#include <vector>
#include <map>

struct DeviceInfo
{
    std::string name;
    std::string platformName;
    cl_platform_id platform;
    cl_device_id device;
    cl_device_type type;
    unsigned int computeUnits;
    size_t globalMemSize;

    std::string GetTypeStr() const
    {
        if (type == CL_DEVICE_TYPE_GPU) return "GPU";
        if (type == CL_DEVICE_TYPE_CPU) return "CPU";
        return "Other";
    }
};

class OpenCLManager
{
public:
    OpenCLManager();
    ~OpenCLManager();

    static std::vector<DeviceInfo> EnumerateDevices();

    bool Init();
    bool InitWithDevice(const DeviceInfo& deviceInfo);

    bool IsInitialized() const { return m_initialized; }
    const std::string& GetDeviceName() const { return m_deviceName; }
    unsigned int GetComputeUnits() const { return m_computeUnits; }
    const std::string& GetStatusMessage() const { return m_statusMessage; }

    bool CreateKernelFromFile(const std::string& kernelName, const std::string& filePath);
    cl_kernel GetKernel(const std::string& kernelName);

    // Direct buffer operations (create/destroy per use)
    cl_mem GpuMalloc(size_t size, cl_mem_flags flags);
    bool CpuToGpu(cl_mem buffer, const void* data, size_t size);
    bool GpuToCpu(cl_mem buffer, void* data, size_t size);
    void ReleaseBuffer(cl_mem buffer);

    // Persistent buffer pool — reuse across calls to avoid alloc/free overhead
    // Returns a buffer guaranteed to be >= requiredSize. Enlarges if needed.
    cl_mem GetPersistDataBufRW(size_t requiredSize);
    cl_mem GetPersistKeyBuf();    // fixed 240 bytes for AES round keys
    cl_mem GetPersistOutBuf(size_t requiredSize);  // large output for SHA256 / AES results

    cl_command_queue GetQueue() const { return m_queue; }
    cl_context GetContext() const { return m_context; }
    cl_device_id GetDevice() const { return m_device; }

    void Release();

private:
    bool LoadKernelSource(const std::string& filePath, std::string& source);
    std::string GetCLErrorString(cl_int err);
    cl_mem EnsureBufferSize(cl_mem& buf, size_t& curSize, size_t required, cl_mem_flags flags);

    bool m_initialized;
    std::string m_statusMessage;

    cl_platform_id m_platform;
    cl_device_id m_device;
    cl_context m_context;
    cl_command_queue m_queue;
    std::string m_deviceName;
    unsigned int m_computeUnits;

    std::map<std::string, cl_kernel> m_kernels;
    std::map<std::string, cl_program> m_programs;

    // Persistent buffer pool
    cl_mem m_persistDataBuf;     // used for AES plain/cipher data and SHA input
    size_t m_persistDataBufSize;
    cl_mem m_persistKeyBuf;      // AES expanded round keys (240 bytes)
    size_t m_persistKeyBufSize;
    cl_mem m_persistOutBuf;      // SHA256 result buffer / AES result buffer
    size_t m_persistOutBufSize;
};
