/**
 * @file resource_control.cpp
 * @brief 资源控制模块实现
 * 
 * 该文件实现了Windows轻量级沙箱的资源控制模块，
 * 负责限制沙箱内进程的CPU、内存、I/O和网络资源使用。
 */

#include "resource_control.h"
#include "logging.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

namespace LightSandbox {

// 资源监控线程控制
static std::atomic<bool> g_MonitorThreadRunning(false);
static std::thread g_MonitorThread;
static std::mutex g_ProcessMapMutex;

// 进程资源限制映射表
struct ProcessResourceLimits {
    HANDLE hProcess;
    DWORD processId;
    CpuLimitConfig cpuLimit;
    MemoryLimitConfig memoryLimit;
    IoLimitConfig ioLimit;
    NetworkLimitConfig networkLimit;
    
    // 资源使用统计
    struct {
        double cpuUsage;
        SIZE_T memoryUsage;
        DWORD ioReadBytes;
        DWORD ioWriteBytes;
        DWORD networkInBytes;
        DWORD networkOutBytes;
        
        // 上次测量时间点
        ULARGE_INTEGER lastCpuTime;
        ULARGE_INTEGER lastSystemTime;
        DWORD lastIoReadBytes;
        DWORD lastIoWriteBytes;
        DWORD lastNetworkInBytes;
        DWORD lastNetworkOutBytes;
    } stats;
};

static std::unordered_map<DWORD, ProcessResourceLimits> g_ProcessResourceMap;

// 前向声明
static void ResourceMonitorThread();
static bool UpdateProcessStats(ProcessResourceLimits& process);
static bool EnforceCpuLimit(ProcessResourceLimits& process);
static bool EnforceMemoryLimit(ProcessResourceLimits& process);
static bool EnforceIoLimit(ProcessResourceLimits& process);
static bool EnforceNetworkLimit(ProcessResourceLimits& process);

bool ResourceControl::Initialize() {
    Logger::Info("Initializing ResourceControl module");
    
    // 启动资源监控线程
    if (!g_MonitorThreadRunning.exchange(true)) {
        g_MonitorThread = std::thread(ResourceMonitorThread);
        Logger::Info("Resource monitor thread started");
    }
    
    return true;
}

void ResourceControl::Cleanup() {
    Logger::Info("Cleaning up ResourceControl module");
    
    // 停止资源监控线程
    if (g_MonitorThreadRunning.exchange(false) && g_MonitorThread.joinable()) {
        g_MonitorThread.join();
        Logger::Info("Resource monitor thread stopped");
    }
    
    // 清理进程资源映射表
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    g_ProcessResourceMap.clear();
}

bool ResourceControl::ApplyCpuLimit(HANDLE hProcess, const CpuLimitConfig& config) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        Logger::Error("Invalid process handle in ApplyCpuLimit");
        return false;
    }
    
    DWORD processId = GetProcessId(hProcess);
    if (processId == 0) {
        Logger::Error("Failed to get process ID, error: %d", GetLastError());
        return false;
    }
    
    Logger::Info("Applying CPU limit to process %d: %.1f%%, affinity: 0x%X, priority: %d",
        processId, config.maxCpuPercentage, config.affinityMask, config.priority);
    
    // 设置进程优先级
    if (!SetPriorityClass(hProcess, config.priority)) {
        Logger::Warning("Failed to set process priority, error: %d", GetLastError());
        // 继续执行，不视为致命错误
    }
    
    // 设置CPU亲和性
    if (config.affinityMask != 0) {
        if (!SetProcessAffinityMask(hProcess, config.affinityMask)) {
            Logger::Warning("Failed to set process affinity mask, error: %d", GetLastError());
            // 继续执行，不视为致命错误
        }
    }
    
    // 添加到资源映射表
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    
    auto it = g_ProcessResourceMap.find(processId);
    if (it == g_ProcessResourceMap.end()) {
        ProcessResourceLimits limits;
        limits.hProcess = hProcess;
        limits.processId = processId;
        limits.cpuLimit = config;
        
        // 初始化统计数据
        memset(&limits.stats, 0, sizeof(limits.stats));
        
        g_ProcessResourceMap[processId] = limits;
    } else {
        it->second.cpuLimit = config;
    }
    
    return true;
}

bool ResourceControl::ApplyMemoryLimit(HANDLE hProcess, const MemoryLimitConfig& config) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        Logger::Error("Invalid process handle in ApplyMemoryLimit");
        return false;
    }
    
    DWORD processId = GetProcessId(hProcess);
    if (processId == 0) {
        Logger::Error("Failed to get process ID, error: %d", GetLastError());
        return false;
    }
    
    Logger::Info("Applying memory limit to process %d: max=%llu bytes, min=%llu bytes, compression=%s",
        processId, config.maxWorkingSetSize, config.minWorkingSetSize, 
        config.enableCompression ? "enabled" : "disabled");
    
    // 设置工作集大小
    if (config.maxWorkingSetSize > 0) {
        SIZE_T minSize = config.minWorkingSetSize > 0 ? config.minWorkingSetSize : config.maxWorkingSetSize / 4;
        if (!SetProcessWorkingSetSize(hProcess, minSize, config.maxWorkingSetSize)) {
            Logger::Warning("Failed to set process working set size, error: %d", GetLastError());
            // 继续执行，不视为致命错误
        }
    }
    
    // 添加到资源映射表
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    
    auto it = g_ProcessResourceMap.find(processId);
    if (it == g_ProcessResourceMap.end()) {
        ProcessResourceLimits limits;
        limits.hProcess = hProcess;
        limits.processId = processId;
        limits.memoryLimit = config;
        
        // 初始化统计数据
        memset(&limits.stats, 0, sizeof(limits.stats));
        
        g_ProcessResourceMap[processId] = limits;
    } else {
        it->second.memoryLimit = config;
    }
    
    return true;
}

bool ResourceControl::ApplyIoLimit(HANDLE hProcess, const IoLimitConfig& config) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        Logger::Error("Invalid process handle in ApplyIoLimit");
        return false;
    }
    
    DWORD processId = GetProcessId(hProcess);
    if (processId == 0) {
        Logger::Error("Failed to get process ID, error: %d", GetLastError());
        return false;
    }
    
    Logger::Info("Applying I/O limit to process %d: read=%d B/s, write=%d B/s, ops=%d/s",
        processId, config.maxReadBytesPerSec, config.maxWriteBytesPerSec, config.maxIoOperationsPerSec);
    
    // I/O限制需要通过监控线程实现
    // 这里只是将配置添加到映射表中
    
    // 添加到资源映射表
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    
    auto it = g_ProcessResourceMap.find(processId);
    if (it == g_ProcessResourceMap.end()) {
        ProcessResourceLimits limits;
        limits.hProcess = hProcess;
        limits.processId = processId;
        limits.ioLimit = config;
        
        // 初始化统计数据
        memset(&limits.stats, 0, sizeof(limits.stats));
        
        g_ProcessResourceMap[processId] = limits;
    } else {
        it->second.ioLimit = config;
    }
    
    return true;
}

bool ResourceControl::ApplyNetworkLimit(HANDLE hProcess, const NetworkLimitConfig& config) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        Logger::Error("Invalid process handle in ApplyNetworkLimit");
        return false;
    }
    
    DWORD processId = GetProcessId(hProcess);
    if (processId == 0) {
        Logger::Error("Failed to get process ID, error: %d", GetLastError());
        return false;
    }
    
    Logger::Info("Applying network limit to process %d: in=%d B/s, out=%d B/s, max_conn=%d",
        processId, config.maxInboundBytesPerSec, config.maxOutboundBytesPerSec, config.maxConnections);
    
    // 网络限制需要通过监控线程和网络过滤驱动实现
    // 这里只是将配置添加到映射表中
    
    // 添加到资源映射表
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    
    auto it = g_ProcessResourceMap.find(processId);
    if (it == g_ProcessResourceMap.end()) {
        ProcessResourceLimits limits;
        limits.hProcess = hProcess;
        limits.processId = processId;
        limits.networkLimit = config;
        
        // 初始化统计数据
        memset(&limits.stats, 0, sizeof(limits.stats));
        
        g_ProcessResourceMap[processId] = limits;
    } else {
        it->second.networkLimit = config;
    }
    
    return true;
}

bool ResourceControl::UpdateCpuLimit(HANDLE hProcess, const CpuLimitConfig& config) {
    // 更新CPU限制实际上就是重新应用CPU限制
    return ApplyCpuLimit(hProcess, config);
}

bool ResourceControl::UpdateMemoryLimit(HANDLE hProcess, const MemoryLimitConfig& config) {
    // 更新内存限制实际上就是重新应用内存限制
    return ApplyMemoryLimit(hProcess, config);
}

bool ResourceControl::UpdateIoLimit(HANDLE hProcess, const IoLimitConfig& config) {
    // 更新I/O限制实际上就是重新应用I/O限制
    return ApplyIoLimit(hProcess, config);
}

bool ResourceControl::UpdateNetworkLimit(HANDLE hProcess, const NetworkLimitConfig& config) {
    // 更新网络限制实际上就是重新应用网络限制
    return ApplyNetworkLimit(hProcess, config);
}

bool ResourceControl::GetResourceUsage(
    HANDLE hProcess,
    double& cpuUsage,
    SIZE_T& memoryUsage,
    DWORD& ioReadBytes,
    DWORD& ioWriteBytes,
    DWORD& networkInBytes,
    DWORD& networkOutBytes) {
    
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        Logger::Error("Invalid process handle in GetResourceUsage");
        return false;
    }
    
    DWORD processId = GetProcessId(hProcess);
    if (processId == 0) {
        Logger::Error("Failed to get process ID, error: %d", GetLastError());
        return false;
    }
    
    // 从资源映射表中获取统计数据
    std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
    
    auto it = g_ProcessResourceMap.find(processId);
    if (it == g_ProcessResourceMap.end()) {
        Logger::Error("Process %d not found in resource map", processId);
        return false;
    }
    
    // 返回统计数据
    cpuUsage = it->second.stats.cpuUsage;
    memoryUsage = it->second.stats.memoryUsage;
    ioReadBytes = it->second.stats.ioReadBytes;
    ioWriteBytes = it->second.stats.ioWriteBytes;
    networkInBytes = it->second.stats.networkInBytes;
    networkOutBytes = it->second.stats.networkOutBytes;
    
    return true;
}

// 资源监控线程实现
static void ResourceMonitorThread() {
    Logger::Info("Resource monitor thread started");
    
    const int MONITOR_INTERVAL_MS = 1000; // 监控间隔，毫秒
    
    while (g_MonitorThreadRunning) {
        // 复制进程列表，避免长时间持有锁
        std::vector<DWORD> processIds;
        {
            std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
            for (const auto& entry : g_ProcessResourceMap) {
                processIds.push_back(entry.first);
            }
        }
        
        // 更新每个进程的统计数据并执行限制
        for (DWORD processId : processIds) {
            ProcessResourceLimits process;
            
            // 获取进程信息
            {
                std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
                auto it = g_ProcessResourceMap.find(processId);
                if (it == g_ProcessResourceMap.end()) {
                    continue; // 进程可能已被移除
                }
                process = it->second;
            }
            
            // 检查进程是否仍然存在
            DWORD exitCode = 0;
            if (!GetExitCodeProcess(process.hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
                // 进程已退出，从映射表中移除
                std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
                g_ProcessResourceMap.erase(processId);
                Logger::Info("Process %d has exited, removed from resource map", processId);
                continue;
            }
            
            // 更新统计数据
            if (!UpdateProcessStats(process)) {
                Logger::Warning("Failed to update stats for process %d", processId);
                continue;
            }
            
            // 执行资源限制
            EnforceCpuLimit(process);
            EnforceMemoryLimit(process);
            EnforceIoLimit(process);
            EnforceNetworkLimit(process);
            
            // 更新映射表中的统计数据
            {
                std::lock_guard<std::mutex> lock(g_ProcessMapMutex);
                auto it = g_ProcessResourceMap.find(processId);
                if (it != g_ProcessResourceMap.end()) {
                    it->second.stats = process.stats;
                }
            }
        }
        
        // 等待下一个监控周期
        std::this_thread::sleep_for(std::chrono::milliseconds(MONITOR_INTERVAL_MS));
    }
    
    Logger::Info("Resource monitor thread stopped");
}

// 更新进程统计数据
static bool UpdateProcessStats(ProcessResourceLimits& process) {
    // 获取CPU使用率
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(process.hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        Logger::Warning("Failed to get process times for process %d, error: %d", 
            process.processId, GetLastError());
        return false;
    }
    
    ULARGE_INTEGER kernelTimeValue, userTimeValue;
    kernelTimeValue.LowPart = kernelTime.dwLowDateTime;
    kernelTimeValue.HighPart = kernelTime.dwHighDateTime;
    userTimeValue.LowPart = userTime.dwLowDateTime;
    userTimeValue.HighPart = userTime.dwHighDateTime;
    
    ULARGE_INTEGER currentCpuTime;
    currentCpuTime.QuadPart = kernelTimeValue.QuadPart + userTimeValue.QuadPart;
    
    FILETIME sysTime;
    GetSystemTimeAsFileTime(&sysTime);
    
    ULARGE_INTEGER currentSystemTime;
    currentSystemTime.LowPart = sysTime.dwLowDateTime;
    currentSystemTime.HighPart = sysTime.dwHighDateTime;
    
    if (process.stats.lastSystemTime.QuadPart > 0) {
        ULONGLONG cpuTimeDiff = currentCpuTime.QuadPart - process.stats.lastCpuTime.QuadPart;
        ULONGLONG systemTimeDiff = currentSystemTime.QuadPart - process.stats.lastSystemTime.QuadPart;
        
        if (systemTimeDiff > 0) {
            // CPU时间是100纳秒为单位，转换为百分比
            process.stats.cpuUsage = (cpuTimeDiff * 100.0) / systemTimeDiff;
            
            // 获取系统CPU核心数，调整百分比
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            process.stats.cpuUsage /= sysInfo.dwNumberOfProcessors;
        }
    }
    
    process.stats.lastCpuTime = currentCpuTime;
    process.stats.lastSystemTime = currentSystemTime;
    
    // 获取内存使用情况
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(process.hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        process.stats.memoryUsage = pmc.WorkingSetSize;
    } else {
        Logger::Warning("Failed to get process memory info for process %d, error: %d", 
            process.processId, GetLastError());
    }
    
    // 获取I/O统计信息
    IO_COUNTERS ioCounters;
    if (GetProcessIoCounters(process.hProcess, &ioCounters)) {
        // 计算I/O速率
        if (process.stats.lastIoReadBytes > 0) {
            process.stats.ioReadBytes = (DWORD)(ioCounters.ReadTransferCount - process.stats.lastIoReadBytes);
        }
        if (process.stats.lastIoWriteBytes > 0) {
            process.stats.ioWriteBytes = (DWORD)(ioCounters.WriteTransferCount - process.stats.lastIoWriteBytes);
        }
        
        process.stats.lastIoReadBytes = (DWORD)ioCounters.ReadTransferCount;
        process.stats.lastIoWriteBytes = (DWORD)ioCounters.WriteTransferCount;
    } else {
        Logger::Warning("Failed to get process I/O counters for process %d, error: %d", 
            process.processId, GetLastError());
    }
    
    // 获取网络统计信息
    // 注意：这需要特殊的网络监控组件，这里简化处理
    // 实际实现需要更复杂的网络监控机制
    
    return true;
}

// 执行CPU限制
static bool EnforceCpuLimit(ProcessResourceLimits& process) {
    // 如果CPU使用率超过限制，则降低进程优先级或暂停进程
    if (process.cpuLimit.maxCpuPercentage > 0 && 
        process.stats.cpuUsage > process.cpuLimit.maxCpuPercentage) {
        
        // 计算需要暂停的时间
        double overusage = process.stats.cpuUsage - process.cpuLimit.maxCpuPercentage;
        if (overusage > 1.0) { // 至少超过1%才采取行动
            // 暂停进程一小段时间
            DWORD pauseTime = (DWORD)(overusage * 10); // 根据超出比例计算暂停时间
            if (pauseTime > 0) {
                if (SuspendThread(process.hProcess) != (DWORD)-1) {
                    Sleep(pauseTime);
                    ResumeThread(process.hProcess);
                    
                    Logger::Debug("Process %d CPU usage %.1f%% exceeds limit %.1f%%, paused for %d ms",
                        process.processId, process.stats.cpuUsage, process.cpuLimit.maxCpuPercentage, pauseTime);
                }
            }
        }
    }
    
    return true;
}

// 执行内存限制
static bool EnforceMemoryLimit(ProcessResourceLimits& process) {
    // 如果内存使用量超过限制，则尝试回收内存
    if (process.memoryLimit.maxWorkingSetSize > 0 && 
        process.stats.memoryUsage > process.memoryLimit.maxWorkingSetSize) {
        
        // 尝试回收内存
        if (process.memoryLimit.enableCompression) {
            // 使用EmptyWorkingSet回收内存
            if (!EmptyWorkingSet(process.hProcess)) {
                Logger::Warning("Failed to empty working set for process %d, error: %d", 
                    process.processId, GetLastError());
            } else {
                Logger::Debug("Process %d memory usage %llu bytes exceeds limit %llu bytes, working set emptied",
                    process.processId, process.stats.memoryUsage, process.memoryLimit.maxWorkingSetSize);
            }
        }
        
        // 重新设置工作集大小
        SIZE_T minSize = process.memoryLimit.minWorkingSetSize > 0 ? 
            process.memoryLimit.minWorkingSetSize : process.memoryLimit.maxWorkingSetSize / 4;
            
        if (!SetProcessWorkingSetSize(process.hProcess, minSize, process.memoryLimit.maxWorkingSetSize)) {
            Logger::Warning("Failed to set process working set size, error: %d", GetLastError());
        }
    }
    
    return true;
}

// 执行I/O限制
static bool EnforceIoLimit(ProcessResourceLimits& process) {
    // I/O限制需要特殊的I/O过滤驱动
    // 这里简化处理，实际实现需要更复杂的机制
    
    // 如果I/O读取速率超过限制，则暂停进程一小段时间
    if (process.ioLimit.maxReadBytesPerSec > 0 && 
        process.stats.ioReadBytes > process.ioLimit.maxReadBytesPerSec) {
        
        // 计算需要暂停的时间
        double overusage = (double)process.stats.ioReadBytes / process.ioLimit.maxReadBytesPerSec;
        if (overusage > 1.1) { // 至少超过10%才采取行动
            // 暂停进程一小段时间
            DWORD pauseTime = (DWORD)((overusage - 1.0) * 100); // 根据超出比例计算暂停时间
            if (pauseTime > 0 && pauseTime < 1000) { // 最多暂停1秒
                if (SuspendThread(process.hProcess) != (DWORD)-1) {
                    Sleep(pauseTime);
                    ResumeThread(process.hProcess);
                    
                    Logger::Debug("Process %d I/O read rate %d B/s exceeds limit %d B/s, paused for %d ms",
                        process.processId, process.stats.ioReadBytes, process.ioLimit.maxReadBytesPerSec, pauseTime);
                }
            }
        }
    }
    
    // 如果I/O写入速率超过限制，则暂停进程一小段时间
    if (process.ioLimit.maxWriteBytesPerSec > 0 && 
        process.stats.ioWriteBytes > process.ioLimit.maxWriteBytesPerSec) {
        
        // 计算需要暂停的时间
        double overusage = (double)process.stats.ioWriteBytes / process.ioLimit.maxWriteBytesPerSec;
        if (overusage > 1.1) { // 至少超过10%才采取行动
            // 暂停进程一小段时间
            DWORD pauseTime = (DWORD)((overusage - 1.0) * 100); // 根据超出比例计算暂停时间
            if (pauseTime > 0 && pauseTime < 1000) { // 最多暂停1秒
                if (SuspendThread(process.hProcess) != (DWORD)-1) {
                    Sleep(pauseTime);
                    ResumeThread(process.hProcess);
                    
                    Logger::Debug("Process %d I/O write rate %d B/s exceeds limit %d B/s, paused for %d ms",
                        process.processId, process.stats.ioWriteBytes, process.ioLimit.maxWriteBytesPerSec, pauseTime);
                }
            }
        }
    }
    
    return true;
}

// 执行网络限制
static bool EnforceNetworkLimit(ProcessResourceLimits& process) {
    // 网络限制需要特殊的网络过滤驱动
    // 这里简化处理，实际实现需要更复杂的机制
    
    // 如果网络入站速率超过限制，则暂停进程一小段时间
    if (process.networkLimit.maxInboundBytesPerSec > 0 && 
        process.stats.networkInBytes > process.networkLimit.maxInboundBytesPerSec) {
        
        // 计算需要暂停的时间
        double overusage = (double)process.stats.networkInBytes / process.networkLimit.maxInboundBytesPerSec;
        if (overusage > 1.1) { // 至少超过10%才采取行动
            // 暂停进程一小段时间
            DWORD pauseTime = (DWORD)((overusage - 1.0) * 100); // 根据超出比例计算暂停时间
            if (pauseTime > 0 && pauseTime < 1000) { // 最多暂停1秒
                if (SuspendThread(process.hProcess) != (DWORD)-1) {
                    Sleep(pauseTime);
                    ResumeThread(process.hProcess);
                    
                    Logger::Debug("Process %d network inbound rate %d B/s exceeds limit %d B/s, paused for %d ms",
                        process.processId, process.stats.networkInBytes, 
                        process.networkLimit.maxInboundBytesPerSec, pauseTime);
                }
            }
        }
    }
    
    // 如果网络出站速率超过限制，则暂停进程一小段时间
    if (process.networkLimit.maxOutboundBytesPerSec > 0 && 
        process.stats.networkOutBytes > process.networkLimit.maxOutboundBytesPerSec) {
        
        // 计算需要暂停的时间
        double overusage = (double)process.stats.networkOutBytes / process.networkLimit.maxOutboundBytesPerSec;
        if (overusage > 1.1) { // 至少超过10%才采取行动
            // 暂停进程一小段时间
            DWORD pauseTime = (DWORD)((overusage - 1.0) * 100); // 根据超出比例计算暂停时间
            if (pauseTime > 0 && pauseTime < 1000) { // 最多暂停1秒
                if (SuspendThread(process.hProcess) != (DWORD)-1) {
                    Sleep(pauseTime);
                    ResumeThread(process.hProcess);
                    
                    Logger::Debug("Process %d network outbound rate %d B/s exceeds limit %d B/s, paused for %d ms",
                        process.processId, process.stats.networkOutBytes, 
                        process.networkLimit.maxOutboundBytesPerSec, pauseTime);
                }
            }
        }
    }
    
    return true;
}

} // namespace LightSandbox
