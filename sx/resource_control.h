/**
 * @file resource_control.h
 * @brief 资源控制模块头文件
 * 
 * 该文件定义了Windows轻量级沙箱的资源控制模块接口，
 * 负责限制沙箱内进程的CPU、内存、I/O和网络资源使用。
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace LightSandbox {

/**
 * @brief CPU限制配置
 */
struct CpuLimitConfig {
    double maxCpuPercentage;    ///< 最大CPU使用率百分比 (0.0-100.0)
    int affinityMask;           ///< CPU亲和性掩码，0表示不设置
    int priority;               ///< 进程优先级
    
    CpuLimitConfig() : maxCpuPercentage(3.0), affinityMask(0), priority(BELOW_NORMAL_PRIORITY_CLASS) {}
};

/**
 * @brief 内存限制配置
 */
struct MemoryLimitConfig {
    SIZE_T maxWorkingSetSize;   ///< 最大工作集大小（字节）
    SIZE_T minWorkingSetSize;   ///< 最小工作集大小（字节）
    bool enableCompression;     ///< 是否启用内存压缩
    
    MemoryLimitConfig() : maxWorkingSetSize(0), minWorkingSetSize(0), enableCompression(true) {}
};

/**
 * @brief I/O限制配置
 */
struct IoLimitConfig {
    DWORD maxReadBytesPerSec;   ///< 最大读取速率（字节/秒）
    DWORD maxWriteBytesPerSec;  ///< 最大写入速率（字节/秒）
    DWORD maxIoOperationsPerSec; ///< 最大I/O操作数（操作/秒）
    
    IoLimitConfig() : maxReadBytesPerSec(0), maxWriteBytesPerSec(0), maxIoOperationsPerSec(0) {}
};

/**
 * @brief 网络限制配置
 */
struct NetworkLimitConfig {
    DWORD maxInboundBytesPerSec;  ///< 最大入站速率（字节/秒）
    DWORD maxOutboundBytesPerSec; ///< 最大出站速率（字节/秒）
    DWORD maxConnections;         ///< 最大连接数
    std::vector<std::wstring> allowedHosts; ///< 允许连接的主机列表
    
    NetworkLimitConfig() : maxInboundBytesPerSec(0), maxOutboundBytesPerSec(0), maxConnections(0) {}
};

/**
 * @brief 资源控制模块接口
 */
class ResourceControl {
public:
    /**
     * @brief 初始化资源控制模块
     * @return 是否成功初始化
     */
    static bool Initialize();
    
    /**
     * @brief 清理资源控制模块
     */
    static void Cleanup();
    
    /**
     * @brief 应用CPU限制
     * @param hProcess 目标进程句柄
     * @param config CPU限制配置
     * @return 是否成功应用限制
     */
    static bool ApplyCpuLimit(HANDLE hProcess, const CpuLimitConfig& config);
    
    /**
     * @brief 应用内存限制
     * @param hProcess 目标进程句柄
     * @param config 内存限制配置
     * @return 是否成功应用限制
     */
    static bool ApplyMemoryLimit(HANDLE hProcess, const MemoryLimitConfig& config);
    
    /**
     * @brief 应用I/O限制
     * @param hProcess 目标进程句柄
     * @param config I/O限制配置
     * @return 是否成功应用限制
     */
    static bool ApplyIoLimit(HANDLE hProcess, const IoLimitConfig& config);
    
    /**
     * @brief 应用网络限制
     * @param hProcess 目标进程句柄
     * @param config 网络限制配置
     * @return 是否成功应用限制
     */
    static bool ApplyNetworkLimit(HANDLE hProcess, const NetworkLimitConfig& config);
    
    /**
     * @brief 更新CPU限制
     * @param hProcess 目标进程句柄
     * @param config 新的CPU限制配置
     * @return 是否成功更新限制
     */
    static bool UpdateCpuLimit(HANDLE hProcess, const CpuLimitConfig& config);
    
    /**
     * @brief 更新内存限制
     * @param hProcess 目标进程句柄
     * @param config 新的内存限制配置
     * @return 是否成功更新限制
     */
    static bool UpdateMemoryLimit(HANDLE hProcess, const MemoryLimitConfig& config);
    
    /**
     * @brief 更新I/O限制
     * @param hProcess 目标进程句柄
     * @param config 新的I/O限制配置
     * @return 是否成功更新限制
     */
    static bool UpdateIoLimit(HANDLE hProcess, const IoLimitConfig& config);
    
    /**
     * @brief 更新网络限制
     * @param hProcess 目标进程句柄
     * @param config 新的网络限制配置
     * @return 是否成功更新限制
     */
    static bool UpdateNetworkLimit(HANDLE hProcess, const NetworkLimitConfig& config);
    
    /**
     * @brief 获取进程资源使用情况
     * @param hProcess 目标进程句柄
     * @param cpuUsage 输出参数，CPU使用率
     * @param memoryUsage 输出参数，内存使用量（字节）
     * @param ioReadBytes 输出参数，I/O读取字节数
     * @param ioWriteBytes 输出参数，I/O写入字节数
     * @param networkInBytes 输出参数，网络入站字节数
     * @param networkOutBytes 输出参数，网络出站字节数
     * @return 是否成功获取资源使用情况
     */
    static bool GetResourceUsage(
        HANDLE hProcess,
        double& cpuUsage,
        SIZE_T& memoryUsage,
        DWORD& ioReadBytes,
        DWORD& ioWriteBytes,
        DWORD& networkInBytes,
        DWORD& networkOutBytes
    );
};

} // namespace LightSandbox
