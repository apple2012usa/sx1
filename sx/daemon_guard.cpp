/**
 * @file daemon_guard.cpp
 * @brief 守护进程模块实现
 * 
 * 该文件实现了Windows轻量级沙箱的守护进程模块，
 * 负责防止沙箱被恶意程序关闭，并提供自我保护和恢复机制。
 */

#include "daemon_guard.h"
#include "logging.h"
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <TlHelp32.h>
#include <Psapi.h>

namespace LightSandbox {

// 守护进程配置
static DaemonGuardConfig g_Config;

// 守护进程状态
static std::atomic<DaemonGuardStatus> g_Status(DaemonGuardStatus::NotInstalled);

// 守护进程服务句柄
static SC_HANDLE g_ServiceHandle = NULL;
static SC_HANDLE g_SCMHandle = NULL;

// 守护进程监控线程
static std::thread g_MonitorThread;
static std::atomic<bool> g_MonitorThreadRunning(false);

// 受保护进程列表
static std::unordered_map<DWORD, SandboxProcessInfo> g_ProtectedProcesses;
static std::mutex g_ProcessesMutex;

// 回调函数
static std::function<void(DWORD)> g_ProcessTerminationCallback;
static std::function<void(DaemonGuardStatus)> g_StatusChangeCallback;

// 日志
static std::vector<std::wstring> g_DaemonLogs;
static std::mutex g_LogsMutex;
static const size_t MAX_LOG_ENTRIES = 1000;

// 前向声明
static void MonitorThreadFunc();
static bool IsProcessRunning(DWORD processId);
static bool RestartProcess(const SandboxProcessInfo& processInfo);
static void AddDaemonLog(const std::wstring& message);
static bool InstallProtectionDriver();
static bool UninstallProtectionDriver();
static bool SetProcessProtection(HANDLE hProcess, bool enable);
static bool CreateWatchdogProcess();
static bool RegisterWithWatchdog();
static DWORD WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context);

bool DaemonGuard::Initialize(const DaemonGuardConfig& config) {
    Logger::Info("Initializing DaemonGuard module, SandboxId: %d", config.sandboxId);
    
    // 保存配置
    g_Config = config;
    
    // 检查守护进程服务状态
    DaemonGuardStatus status = GetStatus();
    if (status == DaemonGuardStatus::NotInstalled) {
        Logger::Info("Daemon service not installed");
    } else if (status == DaemonGuardStatus::Stopped) {
        Logger::Info("Daemon service installed but stopped");
    } else if (status == DaemonGuardStatus::Running) {
        Logger::Info("Daemon service is running");
    } else {
        Logger::Warning("Daemon service is in failed state");
    }
    
    // 启动监控线程
    if (!g_MonitorThreadRunning.exchange(true)) {
        g_MonitorThread = std::thread(MonitorThreadFunc);
        Logger::Info("Monitor thread started");
    }
    
    // 如果配置了驱动级保护，则安装驱动
    if (g_Config.installDriverProtection) {
        if (!InstallDriverProtection()) {
            Logger::Warning("Failed to install driver protection");
        }
    }
    
    // 创建看门狗进程
    if (!CreateWatchdogProcess()) {
        Logger::Warning("Failed to create watchdog process");
    }
    
    // 注册到看门狗
    if (!RegisterWithWatchdog()) {
        Logger::Warning("Failed to register with watchdog");
    }
    
    Logger::Info("DaemonGuard initialized successfully");
    return true;
}

void DaemonGuard::Cleanup() {
    Logger::Info("Cleaning up DaemonGuard module");
    
    // 停止监控线程
    if (g_MonitorThreadRunning.exchange(false) && g_MonitorThread.joinable()) {
        g_MonitorThread.join();
        Logger::Info("Monitor thread stopped");
    }
    
    // 关闭服务句柄
    if (g_ServiceHandle != NULL) {
        CloseServiceHandle(g_ServiceHandle);
        g_ServiceHandle = NULL;
    }
    
    if (g_SCMHandle != NULL) {
        CloseServiceHandle(g_SCMHandle);
        g_SCMHandle = NULL;
    }
    
    // 清理受保护进程列表
    std::lock_guard<std::mutex> lock(g_ProcessesMutex);
    g_ProtectedProcesses.clear();
}

bool DaemonGuard::InstallService() {
    Logger::Info("Installing daemon service: %ls", g_Config.serviceName.c_str());
    
    // 获取当前可执行文件路径
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        Logger::Error("Failed to get module file name, error: %d", GetLastError());
        return false;
    }
    
    // 构建服务命令行
    std::wstring commandLine = std::wstring(exePath) + L" --daemon --sandbox-id=" + 
                              std::to_wstring(g_Config.sandboxId);
    
    // 打开服务控制管理器
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCM == NULL) {
        Logger::Error("Failed to open service control manager, error: %d", GetLastError());
        return false;
    }
    
    // 创建服务
    SC_HANDLE hService = CreateServiceW(
        hSCM,                       // SCM handle
        g_Config.serviceName.c_str(),      // Service name
        g_Config.serviceDisplayName.c_str(), // Display name
        SERVICE_ALL_ACCESS,         // Desired access
        SERVICE_WIN32_OWN_PROCESS,  // Service type
        SERVICE_AUTO_START,         // Start type
        SERVICE_ERROR_NORMAL,       // Error control
        commandLine.c_str(),        // Binary path
        NULL,                       // Load order group
        NULL,                       // Tag ID
        NULL,                       // Dependencies
        NULL,                       // Service start account
        NULL                        // Password
    );
    
    if (hService == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            Logger::Info("Service already exists");
            CloseServiceHandle(hSCM);
            return true;
        } else {
            Logger::Error("Failed to create service, error: %d", error);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    
    // 设置服务描述
    SERVICE_DESCRIPTION sd;
    sd.lpDescription = const_cast<LPWSTR>(g_Config.serviceDescription.c_str());
    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd)) {
        Logger::Warning("Failed to set service description, error: %d", GetLastError());
    }
    
    // 设置服务恢复选项
    SERVICE_FAILURE_ACTIONS sfa;
    SC_ACTION actions[3];
    
    // 第一次失败：1分钟后重启
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 60 * 1000; // 1分钟
    
    // 第二次失败：1分钟后重启
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 60 * 1000; // 1分钟
    
    // 后续失败：1分钟后重启
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 60 * 1000; // 1分钟
    
    sfa.dwResetPeriod = 86400; // 1天
    sfa.lpRebootMsg = NULL;
    sfa.lpCommand = NULL;
    sfa.cActions = 3;
    sfa.lpsaActions = actions;
    
    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)) {
        Logger::Warning("Failed to set service recovery options, error: %d", GetLastError());
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    Logger::Info("Daemon service installed successfully");
    
    // 更新状态
    g_Status = DaemonGuardStatus::Stopped;
    if (g_StatusChangeCallback) {
        g_StatusChangeCallback(g_Status);
    }
    
    return true;
}

bool DaemonGuard::UninstallService() {
    Logger::Info("Uninstalling daemon service: %ls", g_Config.serviceName.c_str());
    
    // 打开服务控制管理器
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) {
        Logger::Error("Failed to open service control manager, error: %d", GetLastError());
        return false;
    }
    
    // 打开服务
    SC_HANDLE hService = OpenServiceW(hSCM, g_Config.serviceName.c_str(), SERVICE_STOP | DELETE);
    if (hService == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            Logger::Info("Service does not exist");
            CloseServiceHandle(hSCM);
            return true;
        } else {
            Logger::Error("Failed to open service, error: %d", error);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    
    // 停止服务
    SERVICE_STATUS status;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        Logger::Info("Service stopped");
    }
    
    // 删除服务
    if (!DeleteService(hService)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
            Logger::Info("Service already marked for deletion");
        } else {
            Logger::Error("Failed to delete service, error: %d", error);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    Logger::Info("Daemon service uninstalled successfully");
    
    // 更新状态
    g_Status = DaemonGuardStatus::NotInstalled;
    if (g_StatusChangeCallback) {
        g_StatusChangeCallback(g_Status);
    }
    
    return true;
}

bool DaemonGuard::StartService() {
    Logger::Info("Starting daemon service: %ls", g_Config.serviceName.c_str());
    
    // 打开服务控制管理器
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) {
        Logger::Error("Failed to open service control manager, error: %d", GetLastError());
        return false;
    }
    
    // 打开服务
    SC_HANDLE hService = OpenServiceW(hSCM, g_Config.serviceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        Logger::Error("Failed to open service, error: %d", GetLastError());
        CloseServiceHandle(hSCM);
        return false;
    }
    
    // 检查服务状态
    SERVICE_STATUS status;
    if (!QueryServiceStatus(hService, &status)) {
        Logger::Error("Failed to query service status, error: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    if (status.dwCurrentState == SERVICE_RUNNING) {
        Logger::Info("Service is already running");
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true;
    }
    
    // 启动服务
    if (!::StartServiceW(hService, 0, NULL)) {
        Logger::Error("Failed to start service, error: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    // 等待服务启动
    int retries = 10;
    while (retries-- > 0) {
        if (!QueryServiceStatus(hService, &status)) {
            Logger::Error("Failed to query service status, error: %d", GetLastError());
            break;
        }
        
        if (status.dwCurrentState == SERVICE_RUNNING) {
            Logger::Info("Service started successfully");
            break;
        }
        
        if (status.dwCurrentState == SERVICE_STOPPED) {
            Logger::Error("Service failed to start");
            break;
        }
        
        Sleep(1000); // 等待1秒
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    // 更新状态
    if (status.dwCurrentState == SERVICE_RUNNING) {
        g_Status = DaemonGuardStatus::Running;
        if (g_StatusChangeCallback) {
            g_StatusChangeCallback(g_Status);
        }
        return true;
    } else {
        g_Status = DaemonGuardStatus::Failed;
        if (g_StatusChangeCallback) {
            g_StatusChangeCallback(g_Status);
        }
        return false;
    }
}

bool DaemonGuard::StopService() {
    Logger::Info("Stopping daemon service: %ls", g_Config.serviceName.c_str());
    
    // 打开服务控制管理器
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) {
        Logger::Error("Failed to open service control manager, error: %d", GetLastError());
        return false;
    }
    
    // 打开服务
    SC_HANDLE hService = OpenServiceW(hSCM, g_Config.serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        Logger::Error("Failed to open service, error: %d", GetLastError());
        CloseServiceHandle(hSCM);
        return false;
    }
    
    // 检查服务状态
    SERVICE_STATUS status;
    if (!QueryServiceStatus(hService, &status)) {
        Logger::Error("Failed to query service status, error: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    if (status.dwCurrentState == SERVICE_STOPPED) {
        Logger::Info("Service is already stopped");
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true;
    }
    
    // 停止服务
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        Logger::Error("Failed to stop service, error: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    // 等待服务停止
    int retries = 10;
    while (retries-- > 0) {
        if (!QueryServiceStatus(hService, &status)) {
            Logger::Error("Failed to query service status, error: %d", GetLastError());
            break;
        }
        
        if (status.dwCurrentState == SERVICE_STOPPED) {
            Logger::Info("Service stopped successfully");
            break;
        }
        
        Sleep(1000); // 等待1秒
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    // 更新状态
    if (status.dwCurrentState == SERVICE_STOPPED) {
        g_Status = DaemonGuardStatus::Stopped;
        if (g_StatusChangeCallback) {
            g_StatusChangeCallback(g_Status);
        }
        return true;
    } else {
        g_Status = DaemonGuardStatus::Failed;
        if (g_StatusChangeCallback) {
            g_StatusChangeCallback(g_Status);
        }
        return false;
    }
}

DaemonGuardStatus DaemonGuard::GetStatus() {
    // 打开服务控制管理器
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL) {
        Logger::Error("Failed to open service control manager, error: %d", GetLastError());
        return DaemonGuardStatus::Failed;
    }
    
    // 打开服务
    SC_HANDLE hService = OpenServiceW(hSCM, g_Config.serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            CloseServiceHandle(hSCM);
            return DaemonGuardStatus::NotInstalled;
        } else {
            Logger::Error("Failed to open service, error: %d", error);
            CloseServiceHandle(hSCM);
            return DaemonGuardStatus::Failed;
        }
    }
    
    // 查询服务状态
    SERVICE_STATUS status;
    if (!QueryServiceStatus(hService, &status)) {
        Logger::Error("Failed to query service status, error: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return DaemonGuardStatus::Failed;
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    // 返回状态
    switch (status.dwCurrentState) {
        case SERVICE_RUNNING:
            return DaemonGuardStatus::Running;
        case SERVICE_STOPPED:
            return DaemonGuardStatus::Stopped;
        default:
            return DaemonGuardStatus::Failed;
    }
}

bool DaemonGuard::RegisterSandboxProcess(DWORD processId, const std::wstring& executablePath, 
                                        const std::wstring& commandLine) {
    Logger::Info("Registering sandbox process: %d, %ls", processId, executablePath.c_str());
    
    // 检查进程是否存在
    if (!IsProcessRunning(processId)) {
        Logger::Error("Process %d does not exist", processId);
        return false;
    }
    
    // 创建进程信息
    SandboxProcessInfo processInfo;
    processInfo.processId = processId;
    processInfo.executablePath = executablePath;
    processInfo.commandLine = commandLine;
    GetSystemTimeAsFileTime(&processInfo.startTime);
    processInfo.isProtected = false;
    
    // 添加到受保护进程列表
    {
        std::lock_guard<std::mutex> lock(g_ProcessesMutex);
        g_ProtectedProcesses[processId] = processInfo;
    }
    
    // 尝试保护进程
    if (g_Config.protectAgainstTermination) {
        if (!ProtectSandboxProcess(processId)) {
            Logger::Warning("Failed to protect process %d", processId);
        }
    }
    
    AddDaemonLog(L"Registered process " + std::to_wstring(processId) + L": " + executablePath);
    return true;
}

bool DaemonGuard::UnregisterSandboxProcess(DWORD processId) {
    Logger::Info("Unregistering sandbox process: %d", processId);
    
    // 从受保护进程列表中移除
    {
        std::lock_guard<std::mutex> lock(g_ProcessesMutex);
        auto it = g_ProtectedProcesses.find(processId);
        if (it == g_ProtectedProcesses.end()) {
            Logger::Warning("Process %d not found in protected processes", processId);
            return false;
        }
        
        g_ProtectedProcesses.erase(it);
    }
    
    AddDaemonLog(L"Unregistered process " + std::to_wstring(processId));
    return true;
}

bool DaemonGuard::ProtectSandboxProcess(DWORD processId) {
    Logger::Info("Protecting sandbox process: %d", processId);
    
    // 检查进程是否存在
    if (!IsProcessRunning(processId)) {
        Logger::Error("Process %d does not exist", processId);
        return false;
    }
    
    // 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        Logger::Error("Failed to open process %d, error: %d", processId, GetLastError());
        return false;
    }
    
    // 设置进程保护
    bool success = SetProcessProtection(hProcess, true);
    
    // 更新进程信息
    if (success) {
        std::lock_guard<std::mutex> lock(g_ProcessesMutex);
        auto it = g_ProtectedProcesses.find(processId);
        if (it != g_ProtectedProcesses.end()) {
            it->second.isProtected = true;
        }
    }
    
    CloseHandle(hProcess);
    
    if (success) {
        AddDaemonLog(L"Protected process " + std::to_wstring(processId));
    } else {
        AddDaemonLog(L"Failed to protect process " + std::to_wstring(processId));
    }
    
    return success;
}

std::vector<SandboxProcessInfo> DaemonGuard::GetProtectedProcesses() {
    std::vector<SandboxProcessInfo> result;
    
    std::lock_guard<std::mutex> lock(g_ProcessesMutex);
    for (const auto& pair : g_ProtectedProcesses) {
        result.push_back(pair.second);
    }
    
    return result;
}

bool DaemonGuard::InstallDriverProtection() {
    Logger::Info("Installing driver protection");
    
    // 实际实现中，这里应该安装内核驱动
    // 这里简化处理，仅记录日志
    
    AddDaemonLog(L"Driver protection installed");
    return InstallProtectionDriver();
}

bool DaemonGuard::UninstallDriverProtection() {
    Logger::Info("Uninstalling driver protection");
    
    // 实际实现中，这里应该卸载内核驱动
    // 这里简化处理，仅记录日志
    
    AddDaemonLog(L"Driver protection uninstalled");
    return UninstallProtectionDriver();
}

void DaemonGuard::SetProcessTerminationCallback(std::function<void(DWORD)> callback) {
    g_ProcessTerminationCallback = callback;
}

void DaemonGuard::SetStatusChangeCallback(std::function<void(DaemonGuardStatus)> callback) {
    g_StatusChangeCallback = callback;
}

bool DaemonGuard::IsHealthy() {
    // 检查守护进程服务状态
    DaemonGuardStatus status = GetStatus();
    if (status != DaemonGuardStatus::Running) {
        return false;
    }
    
    // 检查监控线程是否运行
    if (!g_MonitorThreadRunning) {
        return false;
    }
    
    return true;
}

std::vector<std::wstring> DaemonGuard::GetLogs(int maxLines) {
    std::vector<std::wstring> result;
    
    std::lock_guard<std::mutex> lock(g_LogsMutex);
    
    // 计算起始索引
    size_t startIndex = 0;
    if (g_DaemonLogs.size() > static_cast<size_t>(maxLines)) {
        startIndex = g_DaemonLogs.size() - maxLines;
    }
    
    // 复制日志
    for (size_t i = startIndex; i < g_DaemonLogs.size(); i++) {
        result.push_back(g_DaemonLogs[i]);
    }
    
    return result;
}

// 监控线程函数
static void MonitorThreadFunc() {
    Logger::Info("Monitor thread started");
    AddDaemonLog(L"Monitor thread started");
    
    while (g_MonitorThreadRunning) {
        // 检查所有受保护的进程
        std::vector<DWORD> terminatedProcesses;
        std::vector<SandboxProcessInfo> processesToRestart;
        
        {
            std::lock_guard<std::mutex> lock(g_ProcessesMutex);
            for (const auto& pair : g_ProtectedProcesses) {
                DWORD processId = pair.first;
                const SandboxProcessInfo& processInfo = pair.second;
                
                // 检查进程是否仍在运行
                if (!IsProcessRunning(processId)) {
                    Logger::Warning("Protected process %d terminated unexpectedly", processId);
                    AddDaemonLog(L"Process " + std::to_wstring(processId) + L" terminated unexpectedly");
                    
                    // 记录终止的进程
                    terminatedProcesses.push_back(processId);
                    
                    // 如果配置了自动重启，则添加到重启列表
                    if (g_Config.autoRestart) {
                        processesToRestart.push_back(processInfo);
                    }
                }
            }
            
            // 从受保护进程列表中移除终止的进程
            for (DWORD processId : terminatedProcesses) {
                g_ProtectedProcesses.erase(processId);
            }
        }
        
        // 调用进程终止回调
        if (g_ProcessTerminationCallback) {
            for (DWORD processId : terminatedProcesses) {
                g_ProcessTerminationCallback(processId);
            }
        }
        
        // 重启进程
        for (const SandboxProcessInfo& processInfo : processesToRestart) {
            // 等待指定的重启延迟
            if (g_Config.restartDelay > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(g_Config.restartDelay));
            }
            
            // 重启进程
            if (RestartProcess(processInfo)) {
                Logger::Info("Process %d restarted successfully", processInfo.processId);
                AddDaemonLog(L"Process " + std::to_wstring(processInfo.processId) + L" restarted");
            } else {
                Logger::Error("Failed to restart process %d", processInfo.processId);
                AddDaemonLog(L"Failed to restart process " + std::to_wstring(processInfo.processId));
            }
        }
        
        // 检查守护进程服务状态
        DaemonGuardStatus currentStatus = GetStatus();
        if (currentStatus != g_Status) {
            g_Status = currentStatus;
            if (g_StatusChangeCallback) {
                g_StatusChangeCallback(g_Status);
            }
        }
        
        // 等待一段时间
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    Logger::Info("Monitor thread stopped");
    AddDaemonLog(L"Monitor thread stopped");
}

// 检查进程是否运行
static bool IsProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }
    
    DWORD exitCode = 0;
    bool result = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
    CloseHandle(hProcess);
    return result;
}

// 重启进程
static bool RestartProcess(const SandboxProcessInfo& processInfo) {
    // 创建进程
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;
    
    std::wstring commandLine = processInfo.commandLine;
    if (commandLine.empty()) {
        commandLine = L"\"" + processInfo.executablePath + L"\"";
    }
    
    if (!CreateProcessW(
        processInfo.executablePath.c_str(),
        commandLine.empty() ? NULL : &commandLine[0],
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi)) {
        Logger::Error("Failed to create process, error: %d", GetLastError());
        return false;
    }
    
    // 注册新进程
    RegisterSandboxProcess(pi.dwProcessId, processInfo.executablePath, processInfo.commandLine);
    
    // 关闭句柄
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return true;
}

// 添加守护进程日志
static void AddDaemonLog(const std::wstring& message) {
    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // 格式化时间戳
    wchar_t timeStr[64];
    swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    // 格式化日志条目
    std::wstring logEntry = std::wstring(timeStr) + L" [" + std::to_wstring(GetCurrentProcessId()) + L"] " + message;
    
    // 添加到日志列表
    std::lock_guard<std::mutex> lock(g_LogsMutex);
    g_DaemonLogs.push_back(logEntry);
    
    // 限制日志大小
    if (g_DaemonLogs.size() > MAX_LOG_ENTRIES) {
        g_DaemonLogs.erase(g_DaemonLogs.begin(), 
            g_DaemonLogs.begin() + (g_DaemonLogs.size() - MAX_LOG_ENTRIES));
    }
    
    // 写入日志文件
    try {
        std::wstring logDir = L"C:\\ProgramData\\LightSandbox\\Logs";
        std::error_code ec;
        std::filesystem::create_directories(logDir, ec);
        
        std::wstring logFile = logDir + L"\\DaemonGuard_" + std::to_wstring(g_Config.sandboxId) + L".log";
        std::wofstream logStream(logFile, std::ios::app);
        if (logStream.is_open()) {
            logStream << logEntry << std::endl;
            logStream.close();
        }
    } catch (const std::exception& e) {
        // 忽略日志文件写入错误
    }
}

// 安装保护驱动
static bool InstallProtectionDriver() {
    // 实际实现中，这里应该安装内核驱动
    // 这里简化处理，仅返回成功
    return true;
}

// 卸载保护驱动
static bool UninstallProtectionDriver() {
    // 实际实现中，这里应该卸载内核驱动
    // 这里简化处理，仅返回成功
    return true;
}

// 设置进程保护
static bool SetProcessProtection(HANDLE hProcess, bool enable) {
    // 设置进程保护标志
    // 注意：这需要特权操作，可能需要驱动支持
    // 这里使用Windows API的SetProcessMitigationPolicy函数
    
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };
    policy.MicrosoftSignedOnly = 0;
    
    if (enable) {
        // 设置进程不可终止标志
        // 注意：这是一个简化的实现，实际上Windows没有直接的API来防止进程被终止
        // 真正的实现需要使用内核驱动或其他高级技术
        
        // 这里使用SetHandleInformation来防止进程句柄被关闭
        if (!SetHandleInformation(hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE)) {
            Logger::Warning("Failed to set handle protection, error: %d", GetLastError());
        }
        
        // 设置进程优先级为高于正常
        if (!SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS)) {
            Logger::Warning("Failed to set process priority, error: %d", GetLastError());
        }
    } else {
        // 移除进程保护
        if (!SetHandleInformation(hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0)) {
            Logger::Warning("Failed to remove handle protection, error: %d", GetLastError());
        }
        
        // 恢复进程优先级为正常
        if (!SetPriorityClass(hProcess, NORMAL_PRIORITY_CLASS)) {
            Logger::Warning("Failed to restore process priority, error: %d", GetLastError());
        }
    }
    
    return true;
}

// 创建看门狗进程
static bool CreateWatchdogProcess() {
    // 获取当前可执行文件路径
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        Logger::Error("Failed to get module file name, error: %d", GetLastError());
        return false;
    }
    
    // 构建看门狗命令行
    std::wstring commandLine = std::wstring(exePath) + L" --watchdog --sandbox-id=" + 
                              std::to_wstring(g_Config.sandboxId);
    
    // 创建看门狗进程
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessW(
        NULL,
        &commandLine[0],
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi)) {
        Logger::Error("Failed to create watchdog process, error: %d", GetLastError());
        return false;
    }
    
    // 关闭句柄
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    Logger::Info("Watchdog process created, PID: %d", pi.dwProcessId);
    AddDaemonLog(L"Watchdog process created, PID: " + std::to_wstring(pi.dwProcessId));
    
    return true;
}

// 注册到看门狗
static bool RegisterWithWatchdog() {
    // 实际实现中，这里应该通过IPC与看门狗进程通信
    // 这里简化处理，仅返回成功
    return true;
}

// 服务主函数
static DWORD WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    // 初始化服务
    SERVICE_STATUS_HANDLE hStatus = RegisterServiceCtrlHandlerExW(
        g_Config.serviceName.c_str(),
        ServiceCtrlHandler,
        NULL);
    
    if (hStatus == NULL) {
        Logger::Error("Failed to register service control handler, error: %d", GetLastError());
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    
    // 报告服务状态
    SERVICE_STATUS status = { 0 };
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 1000;
    
    if (!SetServiceStatus(hStatus, &status)) {
        Logger::Error("Failed to set service status, error: %d", GetLastError());
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    
    // 初始化守护进程
    if (!DaemonGuard::Initialize(g_Config)) {
        Logger::Error("Failed to initialize daemon guard");
        
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        status.dwServiceSpecificExitCode = 1;
        SetServiceStatus(hStatus, &status);
        
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    
    // 报告服务已启动
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    
    if (!SetServiceStatus(hStatus, &status)) {
        Logger::Error("Failed to set service status, error: %d", GetLastError());
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    
    // 主循环
    while (g_Status == DaemonGuardStatus::Running) {
        Sleep(1000);
    }
    
    // 清理
    DaemonGuard::Cleanup();
    
    // 报告服务已停止
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    
    if (!SetServiceStatus(hStatus, &status)) {
        Logger::Error("Failed to set service status, error: %d", GetLastError());
        return ERROR_SERVICE_SPECIFIC_ERROR;
    }
    
    return NO_ERROR;
}

// 服务控制处理函数
static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context) {
    SERVICE_STATUS status = { 0 };
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            // 报告服务正在停止
            status.dwCurrentState = SERVICE_STOP_PENDING;
            status.dwWaitHint = 5000;
            SetServiceStatus(NULL, &status);
            
            // 更新状态
            g_Status = DaemonGuardStatus::Stopped;
            if (g_StatusChangeCallback) {
                g_StatusChangeCallback(g_Status);
            }
            
            // 停止监控线程
            if (g_MonitorThreadRunning.exchange(false) && g_MonitorThread.joinable()) {
                g_MonitorThread.join();
            }
            
            // 报告服务已停止
            status.dwCurrentState = SERVICE_STOPPED;
            status.dwWaitHint = 0;
            SetServiceStatus(NULL, &status);
            return NO_ERROR;
        
        case SERVICE_CONTROL_INTERROGATE:
            // 报告当前状态
            status.dwCurrentState = g_Status == DaemonGuardStatus::Running ? 
                SERVICE_RUNNING : SERVICE_STOPPED;
            SetServiceStatus(NULL, &status);
            return NO_ERROR;
        
        default:
            // 不支持的控制代码
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

} // namespace LightSandbox
