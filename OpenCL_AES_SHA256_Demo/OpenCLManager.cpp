#include "OpenCLManager.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <algorithm>

OpenCLManager::OpenCLManager()
    : m_initialized(false)
    , m_platform(nullptr)
    , m_device(nullptr)
    , m_context(nullptr)
    , m_queue(nullptr)
    , m_computeUnits(0)
    , m_persistDataBuf(nullptr)
    , m_persistDataBufSize(0)
    , m_persistKeyBuf(nullptr)
    , m_persistKeyBufSize(0)
    , m_persistOutBuf(nullptr)
    , m_persistOutBufSize(0)
{
}

OpenCLManager::~OpenCLManager()
{
    Release();
}

std::string OpenCLManager::GetCLErrorString(cl_int err)
{
    switch (err)
    {
    case CL_SUCCESS:                            return "CL_SUCCESS";
    case CL_DEVICE_NOT_FOUND:                   return "CL_DEVICE_NOT_FOUND";
    case CL_DEVICE_NOT_AVAILABLE:               return "CL_DEVICE_NOT_AVAILABLE";
    case CL_COMPILER_NOT_AVAILABLE:             return "CL_COMPILER_NOT_AVAILABLE";
    case CL_MEM_OBJECT_ALLOCATION_FAILURE:      return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    case CL_OUT_OF_RESOURCES:                   return "CL_OUT_OF_RESOURCES";
    case CL_OUT_OF_HOST_MEMORY:                 return "CL_OUT_OF_HOST_MEMORY";
    case CL_PROFILING_INFO_NOT_AVAILABLE:       return "CL_PROFILING_INFO_NOT_AVAILABLE";
    case CL_MEM_COPY_OVERLAP:                   return "CL_MEM_COPY_OVERLAP";
    case CL_IMAGE_FORMAT_MISMATCH:              return "CL_IMAGE_FORMAT_MISMATCH";
    case CL_IMAGE_FORMAT_NOT_SUPPORTED:         return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
    case CL_BUILD_PROGRAM_FAILURE:              return "CL_BUILD_PROGRAM_FAILURE";
    case CL_MAP_FAILURE:                        return "CL_MAP_FAILURE";
    case CL_INVALID_VALUE:                      return "CL_INVALID_VALUE";
    case CL_INVALID_DEVICE_TYPE:                return "CL_INVALID_DEVICE_TYPE";
    case CL_INVALID_PLATFORM:                   return "CL_INVALID_PLATFORM";
    case CL_INVALID_DEVICE:                     return "CL_INVALID_DEVICE";
    case CL_INVALID_CONTEXT:                    return "CL_INVALID_CONTEXT";
    case CL_INVALID_QUEUE_PROPERTIES:           return "CL_INVALID_QUEUE_PROPERTIES";
    case CL_INVALID_COMMAND_QUEUE:              return "CL_INVALID_COMMAND_QUEUE";
    case CL_INVALID_HOST_PTR:                   return "CL_INVALID_HOST_PTR";
    case CL_INVALID_MEM_OBJECT:                 return "CL_INVALID_MEM_OBJECT";
    case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR:    return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
    case CL_INVALID_IMAGE_SIZE:                 return "CL_INVALID_IMAGE_SIZE";
    case CL_INVALID_KERNEL:                     return "CL_INVALID_KERNEL";
    case CL_INVALID_ARG_INDEX:                  return "CL_INVALID_ARG_INDEX";
    case CL_INVALID_ARG_VALUE:                  return "CL_INVALID_ARG_VALUE";
    case CL_INVALID_ARG_SIZE:                   return "CL_INVALID_ARG_SIZE";
    case CL_INVALID_KERNEL_ARGS:                return "CL_INVALID_KERNEL_ARGS";
    case CL_INVALID_WORK_DIMENSION:             return "CL_INVALID_WORK_DIMENSION";
    case CL_INVALID_WORK_GROUP_SIZE:            return "CL_INVALID_WORK_GROUP_SIZE";
    case CL_INVALID_WORK_ITEM_SIZE:             return "CL_INVALID_WORK_ITEM_SIZE";
    case CL_INVALID_GLOBAL_OFFSET:              return "CL_INVALID_GLOBAL_OFFSET";
    case CL_INVALID_PROGRAM:                    return "CL_INVALID_PROGRAM";
    case CL_INVALID_PROGRAM_EXECUTABLE:         return "CL_INVALID_PROGRAM_EXECUTABLE";
    case CL_INVALID_KERNEL_NAME:                return "CL_INVALID_KERNEL_NAME";
    case CL_INVALID_KERNEL_DEFINITION:          return "CL_INVALID_KERNEL_DEFINITION";
    default:                                    return "UNKNOWN_ERROR";
    }
}

bool OpenCLManager::LoadKernelSource(const std::string& filePath, std::string& source)
{
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open())
    {
        m_statusMessage = "Failed to open kernel file: " + filePath;
        return false;
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    source = oss.str();

    if (source.empty())
    {
        m_statusMessage = "Kernel file is empty: " + filePath;
        return false;
    }

    return true;
}

std::vector<DeviceInfo> OpenCLManager::EnumerateDevices()
{
    std::vector<DeviceInfo> result;
    cl_int err;
    cl_uint numPlatforms;

    err = clGetPlatformIDs(0, nullptr, &numPlatforms);
    if (err != CL_SUCCESS || numPlatforms == 0)
        return result;

    std::vector<cl_platform_id> platforms(numPlatforms);
    clGetPlatformIDs(numPlatforms, platforms.data(), nullptr);

    // Enumerate GPU first, then CPU
    for (cl_uint p = 0; p < numPlatforms; p++)
    {
        // Get platform name
        char platName[256] = {0};
        clGetPlatformInfo(platforms[p], CL_PLATFORM_NAME, sizeof(platName), platName, nullptr);

        // Enumerate GPU devices
        cl_uint numGpu;
        if (clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 0, nullptr, &numGpu) == CL_SUCCESS && numGpu > 0)
        {
            std::vector<cl_device_id> gpuDevices(numGpu);
            clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, numGpu, gpuDevices.data(), nullptr);
            for (cl_uint d = 0; d < numGpu; d++)
            {
                DeviceInfo info;
                info.platform = platforms[p];
                info.device = gpuDevices[d];
                info.type = CL_DEVICE_TYPE_GPU;
                info.platformName = platName;

                char name[256] = {0};
                clGetDeviceInfo(gpuDevices[d], CL_DEVICE_NAME, sizeof(name), name, nullptr);
                info.name = name;

                clGetDeviceInfo(gpuDevices[d], CL_DEVICE_MAX_COMPUTE_UNITS,
                               sizeof(info.computeUnits), &info.computeUnits, nullptr);

                cl_ulong memSize;
                clGetDeviceInfo(gpuDevices[d], CL_DEVICE_GLOBAL_MEM_SIZE,
                               sizeof(memSize), &memSize, nullptr);
                info.globalMemSize = (size_t)(memSize / (1024 * 1024));

                result.push_back(info);
            }
        }

        // Enumerate CPU devices
        cl_uint numCpu;
        if (clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_CPU, 0, nullptr, &numCpu) == CL_SUCCESS && numCpu > 0)
        {
            std::vector<cl_device_id> cpuDevices(numCpu);
            clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_CPU, numCpu, cpuDevices.data(), nullptr);
            for (cl_uint d = 0; d < numCpu; d++)
            {
                DeviceInfo info;
                info.platform = platforms[p];
                info.device = cpuDevices[d];
                info.type = CL_DEVICE_TYPE_CPU;
                info.platformName = platName;

                char name[256] = {0};
                clGetDeviceInfo(cpuDevices[d], CL_DEVICE_NAME, sizeof(name), name, nullptr);
                info.name = name;

                clGetDeviceInfo(cpuDevices[d], CL_DEVICE_MAX_COMPUTE_UNITS,
                               sizeof(info.computeUnits), &info.computeUnits, nullptr);

                cl_ulong memSize;
                clGetDeviceInfo(cpuDevices[d], CL_DEVICE_GLOBAL_MEM_SIZE,
                               sizeof(memSize), &memSize, nullptr);
                info.globalMemSize = (size_t)(memSize / (1024 * 1024));

                result.push_back(info);
            }
        }
    }

    return result;
}

bool OpenCLManager::Init()
{
    std::vector<DeviceInfo> devices = EnumerateDevices();

    // Find first GPU
    for (const auto& d : devices)
    {
        if (d.type == CL_DEVICE_TYPE_GPU)
            return InitWithDevice(d);
    }

    // Fallback to first CPU
    for (const auto& d : devices)
    {
        if (d.type == CL_DEVICE_TYPE_CPU)
            return InitWithDevice(d);
    }

    m_statusMessage = "No OpenCL device (GPU or CPU) found.";
    return false;
}

bool OpenCLManager::InitWithDevice(const DeviceInfo& deviceInfo)
{
    // Release previous resources first
    Release();

    m_platform = deviceInfo.platform;
    m_device = deviceInfo.device;
    m_deviceName = deviceInfo.name;
    m_computeUnits = deviceInfo.computeUnits;

    cl_int err;

    // Create context
    cl_context_properties props[] = { CL_CONTEXT_PLATFORM, (cl_context_properties)m_platform, 0 };
    m_context = clCreateContext(props, 1, &m_device, nullptr, nullptr, &err);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "Failed to create OpenCL context: " + GetCLErrorString(err);
        return false;
    }

    // Create command queue (OpenCL 2.0+ API)
    m_queue = clCreateCommandQueueWithProperties(m_context, m_device, NULL, &err);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "Failed to create command queue: " + GetCLErrorString(err);
        clReleaseContext(m_context);
        m_context = nullptr;
        return false;
    }

    m_initialized = true;
    m_statusMessage = "OpenCL initialized successfully. Device: " + m_deviceName;
    return true;
}

bool OpenCLManager::CreateKernelFromFile(const std::string& kernelName, const std::string& filePath)
{
    if (!m_initialized)
    {
        m_statusMessage = "OpenCL not initialized";
        return false;
    }

    std::string source;
    if (!LoadKernelSource(filePath, source))
        return false;

    const char* sourceStr = source.c_str();
    size_t sourceLen = source.size();
    cl_int err;

    cl_program program = clCreateProgramWithSource(m_context, 1, &sourceStr, &sourceLen, &err);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "Failed to create program: " + GetCLErrorString(err);
        return false;
    }

    err = clBuildProgram(program, 1, &m_device, nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS)
    {
        size_t logSize;
        clGetProgramBuildInfo(program, m_device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &logSize);
        std::string buildLog(logSize, '\0');
        clGetProgramBuildInfo(program, m_device, CL_PROGRAM_BUILD_LOG, logSize, &buildLog[0], nullptr);
        m_statusMessage = "Kernel build failed: " + buildLog;
        clReleaseProgram(program);
        return false;
    }

    cl_kernel kernel = clCreateKernel(program, kernelName.c_str(), &err);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "Failed to create kernel '" + kernelName + "': " + GetCLErrorString(err);
        clReleaseProgram(program);
        return false;
    }

    if (m_kernels.find(kernelName) != m_kernels.end())
    {
        clReleaseKernel(m_kernels[kernelName]);
        clReleaseProgram(m_programs[kernelName]);
    }

    m_kernels[kernelName] = kernel;
    m_programs[kernelName] = program;

    return true;
}

cl_kernel OpenCLManager::GetKernel(const std::string& kernelName)
{
    auto it = m_kernels.find(kernelName);
    if (it != m_kernels.end())
        return it->second;
    return nullptr;
}

// ============================================================================
// Persistent Buffer Pool — reuse GPU memory across calls
// ============================================================================

cl_mem OpenCLManager::EnsureBufferSize(cl_mem& buf, size_t& curSize, size_t required, cl_mem_flags flags)
{
    if (buf && curSize >= required)
        return buf;

    // Release old buffer if exists
    if (buf)
    {
        clReleaseMemObject(buf);
        buf = nullptr;
    }

    cl_int err;
    buf = clCreateBuffer(m_context, flags, required, nullptr, &err);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "Buffer pool allocation failed: " + GetCLErrorString(err);
        buf = nullptr;
        curSize = 0;
        return nullptr;
    }

    curSize = required;
    return buf;
}

cl_mem OpenCLManager::GetPersistDataBufRW(size_t requiredSize)
{
    return EnsureBufferSize(m_persistDataBuf, m_persistDataBufSize,
                            requiredSize, CL_MEM_READ_WRITE);
}

cl_mem OpenCLManager::GetPersistKeyBuf()
{
    return EnsureBufferSize(m_persistKeyBuf, m_persistKeyBufSize, 240, CL_MEM_READ_ONLY);
}

cl_mem OpenCLManager::GetPersistOutBuf(size_t requiredSize)
{
    return EnsureBufferSize(m_persistOutBuf, m_persistOutBufSize,
                            requiredSize, CL_MEM_READ_WRITE);
}

// ============================================================================
// Direct buffer operations (one-shot create/destroy)
// ============================================================================

cl_mem OpenCLManager::GpuMalloc(size_t size, cl_mem_flags flags)
{
    cl_int err;
    cl_mem buffer = clCreateBuffer(m_context, flags, size, nullptr, &err);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "GPU memory allocation failed: " + GetCLErrorString(err);
    }
    return buffer;
}

bool OpenCLManager::CpuToGpu(cl_mem buffer, const void* data, size_t size)
{
    cl_int err = clEnqueueWriteBuffer(m_queue, buffer, CL_TRUE, 0, size, data, 0, nullptr, nullptr);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "CPU-to-GPU transfer failed: " + GetCLErrorString(err);
        return false;
    }
    return true;
}

bool OpenCLManager::GpuToCpu(cl_mem buffer, void* data, size_t size)
{
    cl_int err = clEnqueueReadBuffer(m_queue, buffer, CL_TRUE, 0, size, data, 0, nullptr, nullptr);
    if (err != CL_SUCCESS)
    {
        m_statusMessage = "GPU-to-CPU transfer failed: " + GetCLErrorString(err);
        return false;
    }
    return true;
}

void OpenCLManager::ReleaseBuffer(cl_mem buffer)
{
    if (buffer)
        clReleaseMemObject(buffer);
}

void OpenCLManager::Release()
{
    for (auto& pair : m_kernels)
    {
        if (pair.second)
            clReleaseKernel(pair.second);
    }
    m_kernels.clear();

    for (auto& pair : m_programs)
    {
        if (pair.second)
            clReleaseProgram(pair.second);
    }
    m_programs.clear();

    if (m_queue)
    {
        clReleaseCommandQueue(m_queue);
        m_queue = nullptr;
    }

    if (m_context)
    {
        clReleaseContext(m_context);
        m_context = nullptr;
    }

    // Release persistent buffer pool
    if (m_persistDataBuf)  { clReleaseMemObject(m_persistDataBuf);  m_persistDataBuf = nullptr;  }
    if (m_persistKeyBuf)   { clReleaseMemObject(m_persistKeyBuf);   m_persistKeyBuf = nullptr;   }
    if (m_persistOutBuf)   { clReleaseMemObject(m_persistOutBuf);   m_persistOutBuf = nullptr;   }
    m_persistDataBufSize = 0;
    m_persistKeyBufSize = 0;
    m_persistOutBufSize = 0;

    m_initialized = false;
}
