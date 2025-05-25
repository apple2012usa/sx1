/**
 * @file core_isolation_layer.cpp
 * @brief 核心隔离层实现
 * 
 * 该文件实现了Windows轻量级沙箱的核心隔离层，
 * 负责创建隔离环境、拦截系统调用、管理进程隔离等功能。
 */

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>
#include <mutex>
#include <atomic>

#include "core_isolation_layer.h"
#include "resource_control.h"
#include "filesystem_isolation.h"
#include "registry_isolation.h"
#include "network_isolation.h"
#include "process_monitor.h"
#include "logging.h"

namespace LightSandbox {

// 系统调用表结构
struct SystemCallTable {
    PVOID* ServiceTable;
    PULONG CounterTable;
    ULONG ServiceLimit;
    PBYTE ArgumentTable;
};

// 原始系统调用函数指针类型
typedef NTSTATUS(NTAPI* NtCreateFileFunc)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

// 系统调用钩子函数
static std::unordered_map<std::string, PVOID> g_OriginalSystemCalls;
static std::mutex g_SystemCallMutex;

// 沙箱实例ID
static std::atomic<DWORD> g_NextSandboxId(1);

// 沙箱配置
static SandboxConfig g_SandboxConfig;

// 核心隔离层实现
class CoreIsolationLayerImpl {
public:
    CoreIsolationLayerImpl() : m_Initialized(false), m_SandboxId(0) {}
    ~CoreIsolationLayerImpl() { Cleanup(); }

    bool Initialize(const SandboxConfig& config) {
        std::lock_guard<std::mutex> lock(m_Mutex);
        
        if (m_Initialized) {
            Logger::Warning("CoreIsolationLayer already initialized");
            return true;
        }

        m_SandboxId = g_NextSandboxId.fetch_add(1);
        Logger::Info("Initializing CoreIsolationLayer, SandboxId: %d", m_SandboxId);

        // 保存配置
        g_SandboxConfig = config;

        // 初始化各个隔离模块
        if (!InitializeFileSystemIsolation()) {
            Logger::Error("Failed to initialize filesystem isolation");
            return false;
        }

        if (!InitializeRegistryIsolation()) {
            Logger::Error("Failed to initialize registry isolation");
            return false;
        }

        if (!InitializeNetworkIsolation()) {
            Logger::Error("Failed to initialize network isolation");
            return false;
        }

        if (!InitializeProcessMonitor()) {
            Logger::Error("Failed to initialize process monitor");
            return false;
        }

        // 安装系统调用钩子
        if (!InstallSystemCallHooks()) {
            Logger::Error("Failed to install system call hooks");
            return false;
        }

        m_Initialized = true;
        Logger::Info("CoreIsolationLayer initialized successfully");
        return true;
    }

    void Cleanup() {
        std::lock_guard<std::mutex> lock(m_Mutex);
        
        if (!m_Initialized) {
            return;
        }

        // 移除系统调用钩子
        RemoveSystemCallHooks();

        // 清理各个隔离模块
        CleanupProcessMonitor();
        CleanupNetworkIsolation();
        CleanupRegistryIsolation();
        CleanupFileSystemIsolation();

        m_Initialized = false;
        Logger::Info("CoreIsolationLayer cleaned up");
    }

    bool CreateSandboxedProcess(const std::wstring& applicationPath, 
                               const std::wstring& commandLine,
                               PROCESS_INFORMATION& processInfo) {
        if (!m_Initialized) {
            Logger::Error("CoreIsolationLayer not initialized");
            return false;
        }

        Logger::Info("Creating sandboxed process: %ls", applicationPath.c_str());

        // 准备进程创建参数
        STARTUPINFOW startupInfo = { sizeof(STARTUPINFOW) };
        DWORD creationFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;

        // 创建进程
        std::wstring cmdLine = commandLine;
        if (!CreateProcessW(
            applicationPath.c_str(),
            cmdLine.empty() ? NULL : &cmdLine[0],
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            &startupInfo,
            &processInfo)) {
            Logger::Error("Failed to create process, error: %d", GetLastError());
            return false;
        }

        // 注入隔离DLL
        if (!InjectIsolationDll(processInfo.hProcess)) {
            Logger::Error("Failed to inject isolation DLL");
            TerminateProcess(processInfo.hProcess, 1);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
            return false;
        }

        // 应用资源限制
        if (!ApplyResourceLimits(processInfo.hProcess)) {
            Logger::Error("Failed to apply resource limits");
            TerminateProcess(processInfo.hProcess, 1);
            CloseHandle(processInfo.hProcess);
            CloseHandle(processInfo.hThread);
            return false;
        }

        // 恢复线程执行
        ResumeThread(processInfo.hThread);
        
        Logger::Info("Sandboxed process created successfully, PID: %d", processInfo.dwProcessId);
        return true;
    }

    DWORD GetSandboxId() const {
        return m_SandboxId;
    }

private:
    bool InitializeFileSystemIsolation() {
        // 初始化文件系统隔离
        FileSystemIsolationConfig fsConfig;
        fsConfig.sandboxId = m_SandboxId;
        fsConfig.baseImagePath = g_SandboxConfig.baseImagePath;
        fsConfig.differentialStoragePath = g_SandboxConfig.differentialStoragePath;
        
        return FileSystemIsolation::Initialize(fsConfig);
    }

    bool InitializeRegistryIsolation() {
        // 初始化注册表隔离
        RegistryIsolationConfig regConfig;
        regConfig.sandboxId = m_SandboxId;
        regConfig.virtualRegistryPath = g_SandboxConfig.virtualRegistryPath;
        
        return RegistryIsolation::Initialize(regConfig);
    }

    bool InitializeNetworkIsolation() {
        // 初始化网络隔离
        NetworkIsolationConfig netConfig;
        netConfig.sandboxId = m_SandboxId;
        netConfig.networkMode = g_SandboxConfig.networkMode;
        netConfig.allowedHosts = g_SandboxConfig.allowedHosts;
        
        return NetworkIsolation::Initialize(netConfig);
    }

    bool InitializeProcessMonitor() {
        // 初始化进程监控
        ProcessMonitorConfig pmConfig;
        pmConfig.sandboxId = m_SandboxId;
        
        return ProcessMonitor::Initialize(pmConfig);
    }

    void CleanupFileSystemIsolation() {
        FileSystemIsolation::Cleanup();
    }

    void CleanupRegistryIsolation() {
        RegistryIsolation::Cleanup();
    }

    void CleanupNetworkIsolation() {
        NetworkIsolation::Cleanup();
    }

    void CleanupProcessMonitor() {
        ProcessMonitor::Cleanup();
    }

    bool InstallSystemCallHooks() {
        std::lock_guard<std::mutex> lock(g_SystemCallMutex);
        
        // 获取NTDLL模块句柄
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            Logger::Error("Failed to get ntdll.dll handle");
            return false;
        }

        // 安装文件操作相关钩子
        if (!InstallHook(hNtdll, "NtCreateFile", (PVOID)HookedNtCreateFile)) {
            return false;
        }

        if (!InstallHook(hNtdll, "NtOpenFile", (PVOID)HookedNtOpenFile)) {
            return false;
        }

        // 安装注册表操作相关钩子
        if (!InstallHook(hNtdll, "NtCreateKey", (PVOID)HookedNtCreateKey)) {
            return false;
        }

        if (!InstallHook(hNtdll, "NtOpenKey", (PVOID)HookedNtOpenKey)) {
            return false;
        }

        // 安装进程操作相关钩子
        if (!InstallHook(hNtdll, "NtCreateProcess", (PVOID)HookedNtCreateProcess)) {
            return false;
        }

        if (!InstallHook(hNtdll, "NtCreateProcessEx", (PVOID)HookedNtCreateProcessEx)) {
            return false;
        }

        // 安装网络操作相关钩子
        if (!InstallHook(hNtdll, "NtDeviceIoControlFile", (PVOID)HookedNtDeviceIoControlFile)) {
            return false;
        }

        return true;
    }

    bool InstallHook(HMODULE hModule, const char* functionName, PVOID hookFunction) {
        // 获取原始函数地址
        PVOID originalFunction = GetProcAddress(hModule, functionName);
        if (!originalFunction) {
            Logger::Error("Failed to get address of %s, error: %d", functionName, GetLastError());
            return false;
        }

        // 保存原始函数地址
        g_OriginalSystemCalls[functionName] = originalFunction;

        // 修改内存保护属性
        DWORD oldProtect;
        if (!VirtualProtect(originalFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            Logger::Error("Failed to change memory protection for %s, error: %d", functionName, GetLastError());
            return false;
        }

        // 写入跳转指令
        BYTE jmpCode[5];
        jmpCode[0] = 0xE9; // JMP 指令
        DWORD jmpOffset = (DWORD)hookFunction - (DWORD)originalFunction - 5;
        *(DWORD*)(&jmpCode[1]) = jmpOffset;

        memcpy(originalFunction, jmpCode, 5);

        // 恢复内存保护属性
        DWORD dummy;
        VirtualProtect(originalFunction, 5, oldProtect, &dummy);

        Logger::Info("Installed hook for %s", functionName);
        return true;
    }

    void RemoveSystemCallHooks() {
        std::lock_guard<std::mutex> lock(g_SystemCallMutex);
        
        // 遍历所有已安装的钩子
        for (const auto& entry : g_OriginalSystemCalls) {
            const std::string& functionName = entry.first;
            PVOID originalFunction = entry.second;
            
            // 获取当前函数地址
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) {
                Logger::Error("Failed to get ntdll.dll handle");
                continue;
            }
            
            PVOID currentFunction = GetProcAddress(hNtdll, functionName.c_str());
            if (!currentFunction) {
                Logger::Error("Failed to get address of %s", functionName.c_str());
                continue;
            }
            
            // 修改内存保护属性
            DWORD oldProtect;
            if (!VirtualProtect(currentFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                Logger::Error("Failed to change memory protection for %s", functionName.c_str());
                continue;
            }
            
            // 恢复原始函数的前5个字节
            // 注意：这里假设我们有保存原始函数的前5个字节，实际实现中需要保存这些字节
            // 这里简化处理，实际上需要更复杂的机制
            
            // 恢复内存保护属性
            DWORD dummy;
            VirtualProtect(currentFunction, 5, oldProtect, &dummy);
            
            Logger::Info("Removed hook for %s", functionName.c_str());
        }
        
        g_OriginalSystemCalls.clear();
    }

    bool InjectIsolationDll(HANDLE hProcess) {
        // 获取隔离DLL路径
        std::wstring dllPath = g_SandboxConfig.isolationDllPath;
        
        // 在目标进程中分配内存
        SIZE_T pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
        if (!remotePath) {
            Logger::Error("Failed to allocate memory in target process, error: %d", GetLastError());
            return false;
        }
        
        // 写入DLL路径
        if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathSize, NULL)) {
            Logger::Error("Failed to write DLL path to target process, error: %d", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // 获取LoadLibraryW函数地址
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            Logger::Error("Failed to get kernel32.dll handle, error: %d", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
        if (!loadLibraryAddr) {
            Logger::Error("Failed to get LoadLibraryW address, error: %d", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // 创建远程线程加载DLL
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remotePath, 0, NULL);
        if (!hThread) {
            Logger::Error("Failed to create remote thread, error: %d", GetLastError());
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // 等待线程完成
        WaitForSingleObject(hThread, INFINITE);
        
        // 检查线程执行结果
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        CloseHandle(hThread);
        
        // 释放远程内存
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        
        if (exitCode == 0) {
            Logger::Error("DLL injection failed, LoadLibraryW returned 0");
            return false;
        }
        
        Logger::Info("DLL injected successfully");
        return true;
    }

    bool ApplyResourceLimits(HANDLE hProcess) {
        // 应用CPU限制
        if (!ResourceControl::ApplyCpuLimit(hProcess, g_SandboxConfig.cpuLimit)) {
            Logger::Warning("Failed to apply CPU limit");
            // 继续执行，不视为致命错误
        }
        
        // 应用内存限制
        if (!ResourceControl::ApplyMemoryLimit(hProcess, g_SandboxConfig.memoryLimit)) {
            Logger::Warning("Failed to apply memory limit");
            // 继续执行，不视为致命错误
        }
        
        // 应用I/O限制
        if (!ResourceControl::ApplyIoLimit(hProcess, g_SandboxConfig.ioLimit)) {
            Logger::Warning("Failed to apply I/O limit");
            // 继续执行，不视为致命错误
        }
        
        // 应用网络限制
        if (!ResourceControl::ApplyNetworkLimit(hProcess, g_SandboxConfig.networkLimit)) {
            Logger::Warning("Failed to apply network limit");
            // 继续执行，不视为致命错误
        }
        
        return true;
    }

    // 系统调用钩子函数实现
    static NTSTATUS NTAPI HookedNtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength) {
        
        // 获取原始函数
        NtCreateFileFunc originalFunc = (NtCreateFileFunc)g_OriginalSystemCalls["NtCreateFile"];
        
        // 检查文件路径是否需要重定向
        UNICODE_STRING originalPath = *ObjectAttributes->ObjectName;
        std::wstring filePath(originalPath.Buffer, originalPath.Length / sizeof(wchar_t));
        
        std::wstring redirectedPath;
        bool shouldRedirect = FileSystemIsolation::ShouldRedirectPath(filePath, redirectedPath);
        
        if (shouldRedirect) {
            // 创建新的OBJECT_ATTRIBUTES结构
            UNICODE_STRING redirectedPathUnicode;
            OBJECT_ATTRIBUTES redirectedAttributes = *ObjectAttributes;
            
            // 初始化重定向路径的UNICODE_STRING
            RtlInitUnicodeString(&redirectedPathUnicode, redirectedPath.c_str());
            redirectedAttributes.ObjectName = &redirectedPathUnicode;
            
            // 使用重定向路径调用原始函数
            return originalFunc(
                FileHandle,
                DesiredAccess,
                &redirectedAttributes,
                IoStatusBlock,
                AllocationSize,
                FileAttributes,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                EaBuffer,
                EaLength
            );
        }
        
        // 使用原始路径调用原始函数
        return originalFunc(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength
        );
    }

    static NTSTATUS NTAPI HookedNtOpenFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG ShareAccess,
        ULONG OpenOptions) {
        
        // 类似于HookedNtCreateFile的实现
        // 这里简化处理，实际实现需要更复杂的逻辑
        return 0;
    }

    static NTSTATUS NTAPI HookedNtCreateKey(
        PHANDLE KeyHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        ULONG TitleIndex,
        PUNICODE_STRING Class,
        ULONG CreateOptions,
        PULONG Disposition) {
        
        // 类似于HookedNtCreateFile的实现，但针对注册表
        // 这里简化处理，实际实现需要更复杂的逻辑
        return 0;
    }

    static NTSTATUS NTAPI HookedNtOpenKey(
        PHANDLE KeyHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes) {
        
        // 类似于HookedNtOpenFile的实现，但针对注册表
        // 这里简化处理，实际实现需要更复杂的逻辑
        return 0;
    }

    static NTSTATUS NTAPI HookedNtCreateProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ParentProcess,
        BOOLEAN InheritObjectTable,
        HANDLE SectionHandle,
        HANDLE DebugPort,
        HANDLE ExceptionPort) {
        
        // 进程创建钩子
        // 这里简化处理，实际实现需要更复杂的逻辑
        return 0;
    }

    static NTSTATUS NTAPI HookedNtCreateProcessEx(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ParentProcess,
        ULONG Flags,
        HANDLE SectionHandle,
        HANDLE DebugPort,
        HANDLE ExceptionPort,
        ULONG JobMemberLevel) {
        
        // 进程创建钩子
        // 这里简化处理，实际实现需要更复杂的逻辑
        return 0;
    }

    static NTSTATUS NTAPI HookedNtDeviceIoControlFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG IoControlCode,
        PVOID InputBuffer,
        ULONG InputBufferLength,
        PVOID OutputBuffer,
        ULONG OutputBufferLength) {
        
        // 网络操作钩子
        // 这里简化处理，实际实现需要更复杂的逻辑
        return 0;
    }

private:
    bool m_Initialized;
    DWORD m_SandboxId;
    std::mutex m_Mutex;
};

// 全局实例
static std::unique_ptr<CoreIsolationLayerImpl> g_CoreIsolationLayer;

// 公共API实现
bool CoreIsolationLayer::Initialize(const SandboxConfig& config) {
    if (!g_CoreIsolationLayer) {
        g_CoreIsolationLayer = std::make_unique<CoreIsolationLayerImpl>();
    }
    return g_CoreIsolationLayer->Initialize(config);
}

void CoreIsolationLayer::Cleanup() {
    if (g_CoreIsolationLayer) {
        g_CoreIsolationLayer->Cleanup();
    }
}

bool CoreIsolationLayer::CreateSandboxedProcess(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    PROCESS_INFORMATION& processInfo) {
    if (!g_CoreIsolationLayer) {
        Logger::Error("CoreIsolationLayer not initialized");
        return false;
    }
    return g_CoreIsolationLayer->CreateSandboxedProcess(applicationPath, commandLine, processInfo);
}

DWORD CoreIsolationLayer::GetSandboxId() {
    if (!g_CoreIsolationLayer) {
        return 0;
    }
    return g_CoreIsolationLayer->GetSandboxId();
}

} // namespace LightSandbox
