/**
 * @file main.cpp
 * @brief Windows轻量级沙箱主程序入口
 * 
 * 该文件实现了Windows轻量级沙箱的主程序入口点，
 * 负责初始化各个模块并启动用户界面。
 */

#include <Windows.h>
#include "logging.h"
#include "resource_control.h"
#include "filesystem_isolation.h"
#include "registry_isolation.h"
#include "daemon_guard.h"
#include "user_interface.h"
#include <string>
#include <vector>
#include <memory>

using namespace LightSandbox;

// 全局变量
static std::unique_ptr<UserInterface> g_pUI;
static bool g_IsDaemonMode = false;
static bool g_IsWatchdogMode = false;
static DWORD g_SandboxId = 1;

// 函数声明
bool ParseCommandLine(LPWSTR lpCmdLine);
bool InitializeModules();
void CleanupModules();
bool StartSandbox(DWORD sandboxId);
bool StopSandbox(DWORD sandboxId);
bool CreateSandbox(const SandboxInfo& sandboxInfo);
bool DeleteSandbox(DWORD sandboxId);
bool LaunchApplication(DWORD sandboxId, const std::wstring& appPath);
bool SaveSettings(const UserInterfaceConfig& config);
void UpdateSandboxList();
void UpdateApplicationList();
void UpdateResourceUsage();

// Windows程序入口点
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    // 解析命令行参数
    if (!ParseCommandLine(lpCmdLine)) {
        MessageBoxW(NULL, L"命令行参数无效", L"错误", MB_ICONERROR);
        return 1;
    }
    
    // 初始化日志系统
    LoggingConfig logConfig;
    logConfig.logFilePath = L"C:\\ProgramData\\LightSandbox\\Logs\\LightSandbox.log";
    if (!Logger::Initialize(logConfig)) {
        MessageBoxW(NULL, L"初始化日志系统失败", L"错误", MB_ICONERROR);
        return 1;
    }
    
    Logger::Info("LightSandbox starting, SandboxId: %d, DaemonMode: %d, WatchdogMode: %d",
        g_SandboxId, g_IsDaemonMode, g_IsWatchdogMode);
    
    // 守护进程模式
    if (g_IsDaemonMode) {
        Logger::Info("Starting in daemon mode");
        
        // 初始化守护进程
        DaemonGuardConfig daemonConfig;
        daemonConfig.sandboxId = g_SandboxId;
        daemonConfig.serviceName = L"LightSandboxDaemon" + std::to_wstring(g_SandboxId);
        daemonConfig.serviceDisplayName = L"LightSandbox Daemon " + std::to_wstring(g_SandboxId);
        daemonConfig.serviceDescription = L"LightSandbox守护进程，负责保护沙箱不被恶意程序关闭";
        
        if (!DaemonGuard::Initialize(daemonConfig)) {
            Logger::Error("Failed to initialize daemon guard");
            return 1;
        }
        
        // 运行服务主循环
        // 注意：实际实现中应该使用Windows服务API
        while (true) {
            Sleep(1000);
        }
        
        DaemonGuard::Cleanup();
        return 0;
    }
    
    // 看门狗模式
    if (g_IsWatchdogMode) {
        Logger::Info("Starting in watchdog mode");
        
        // 实现看门狗逻辑
        // 注意：实际实现中应该监控主进程并在必要时重启它
        while (true) {
            Sleep(1000);
        }
        
        return 0;
    }
    
    // 正常模式 - 初始化各个模块
    if (!InitializeModules()) {
        Logger::Error("Failed to initialize modules");
        MessageBoxW(NULL, L"初始化模块失败", L"错误", MB_ICONERROR);
        return 1;
    }
    
    // 创建用户界面
    g_pUI = std::make_unique<UserInterface>();
    
    // 初始化用户界面
    UserInterfaceConfig uiConfig;
    if (!g_pUI->Initialize(uiConfig, hInstance)) {
        Logger::Error("Failed to initialize user interface");
        MessageBoxW(NULL, L"初始化用户界面失败", L"错误", MB_ICONERROR);
        CleanupModules();
        return 1;
    }
    
    // 设置回调函数
    g_pUI->SetSandboxStartCallback(StartSandbox);
    g_pUI->SetSandboxStopCallback(StopSandbox);
    g_pUI->SetSandboxCreateCallback(CreateSandbox);
    g_pUI->SetSandboxDeleteCallback(DeleteSandbox);
    g_pUI->SetApplicationLaunchCallback(LaunchApplication);
    g_pUI->SetSettingsSaveCallback(SaveSettings);
    
    // 更新沙箱列表
    UpdateSandboxList();
    
    // 更新应用程序列表
    UpdateApplicationList();
    
    // 启动资源使用率监控线程
    std::thread resourceMonitorThread([]() {
        while (true) {
            UpdateResourceUsage();
            Sleep(1000);
        }
    });
    resourceMonitorThread.detach();
    
    // 显示主窗口
    g_pUI->Show();
    
    // 运行消息循环
    int result = g_pUI->Run();
    
    // 清理资源
    g_pUI.reset();
    CleanupModules();
    Logger::Cleanup();
    
    return result;
}

// 解析命令行参数
bool ParseCommandLine(LPWSTR lpCmdLine) {
    std::wstring cmdLine(lpCmdLine);
    
    // 检查是否为守护进程模式
    if (cmdLine.find(L"--daemon") != std::wstring::npos) {
        g_IsDaemonMode = true;
    }
    
    // 检查是否为看门狗模式
    if (cmdLine.find(L"--watchdog") != std::wstring::npos) {
        g_IsWatchdogMode = true;
    }
    
    // 解析沙箱ID
    size_t idPos = cmdLine.find(L"--sandbox-id=");
    if (idPos != std::wstring::npos) {
        size_t valueStart = idPos + 13; // "--sandbox-id="的长度
        size_t valueEnd = cmdLine.find(L" ", valueStart);
        if (valueEnd == std::wstring::npos) {
            valueEnd = cmdLine.length();
        }
        
        std::wstring idStr = cmdLine.substr(valueStart, valueEnd - valueStart);
        try {
            g_SandboxId = std::stoul(idStr);
        } catch (...) {
            return false;
        }
    }
    
    return true;
}

// 初始化各个模块
bool InitializeModules() {
    // 初始化资源控制模块
    ResourceControlConfig rcConfig;
    rcConfig.sandboxId = g_SandboxId;
    rcConfig.maxCpuUsage = 3; // 3%
    rcConfig.maxMemoryUsage = 5; // 5%
    rcConfig.maxDiskIORate = 10 * 1024 * 1024; // 10 MB/s
    rcConfig.maxNetworkIORate = 5 * 1024 * 1024; // 5 MB/s
    
    if (!ResourceControl::Initialize(rcConfig)) {
        Logger::Error("Failed to initialize resource control module");
        return false;
    }
    
    // 初始化文件系统隔离模块
    FileSystemIsolationConfig fsConfig;
    fsConfig.sandboxId = g_SandboxId;
    fsConfig.baseImagePath = L"C:\\ProgramData\\LightSandbox\\BaseImage";
    fsConfig.differentialStoragePath = L"C:\\ProgramData\\LightSandbox\\Sandbox" + 
                                      std::to_wstring(g_SandboxId);
    fsConfig.enableFileSharing = true;
    
    if (!FileSystemIsolation::Initialize(fsConfig)) {
        Logger::Error("Failed to initialize filesystem isolation module");
        ResourceControl::Cleanup();
        return false;
    }
    
    // 初始化注册表隔离模块
    RegistryIsolationConfig regConfig;
    regConfig.sandboxId = g_SandboxId;
    regConfig.virtualRegistryPath = L"C:\\ProgramData\\LightSandbox\\Registry" + 
                                   std::to_wstring(g_SandboxId);
    regConfig.enableRegistrySharing = true;
    
    if (!RegistryIsolation::Initialize(regConfig)) {
        Logger::Error("Failed to initialize registry isolation module");
        FileSystemIsolation::Cleanup();
        ResourceControl::Cleanup();
        return false;
    }
    
    // 初始化守护进程模块
    DaemonGuardConfig daemonConfig;
    daemonConfig.sandboxId = g_SandboxId;
    daemonConfig.serviceName = L"LightSandboxDaemon" + std::to_wstring(g_SandboxId);
    daemonConfig.serviceDisplayName = L"LightSandbox Daemon " + std::to_wstring(g_SandboxId);
    daemonConfig.serviceDescription = L"LightSandbox守护进程，负责保护沙箱不被恶意程序关闭";
    daemonConfig.autoRestart = true;
    daemonConfig.protectAgainstTermination = true;
    
    if (!DaemonGuard::Initialize(daemonConfig)) {
        Logger::Error("Failed to initialize daemon guard module");
        RegistryIsolation::Cleanup();
        FileSystemIsolation::Cleanup();
        ResourceControl::Cleanup();
        return false;
    }
    
    return true;
}

// 清理各个模块
void CleanupModules() {
    DaemonGuard::Cleanup();
    RegistryIsolation::Cleanup();
    FileSystemIsolation::Cleanup();
    ResourceControl::Cleanup();
}

// 启动沙箱
bool StartSandbox(DWORD sandboxId) {
    Logger::Info("Starting sandbox: %d", sandboxId);
    
    // 实现沙箱启动逻辑
    // 这里简化处理，实际实现中应该创建沙箱环境并启动相关进程
    
    // 更新沙箱列表
    UpdateSandboxList();
    
    return true;
}

// 停止沙箱
bool StopSandbox(DWORD sandboxId) {
    Logger::Info("Stopping sandbox: %d", sandboxId);
    
    // 实现沙箱停止逻辑
    // 这里简化处理，实际实现中应该停止沙箱中的所有进程并清理环境
    
    // 更新沙箱列表
    UpdateSandboxList();
    
    return true;
}

// 创建沙箱
bool CreateSandbox(const SandboxInfo& sandboxInfo) {
    Logger::Info("Creating sandbox: %ls", sandboxInfo.name.c_str());
    
    // 实现沙箱创建逻辑
    // 这里简化处理，实际实现中应该创建沙箱配置和环境
    
    // 更新沙箱列表
    UpdateSandboxList();
    
    return true;
}

// 删除沙箱
bool DeleteSandbox(DWORD sandboxId) {
    Logger::Info("Deleting sandbox: %d", sandboxId);
    
    // 实现沙箱删除逻辑
    // 这里简化处理，实际实现中应该删除沙箱配置和环境
    
    // 更新沙箱列表
    UpdateSandboxList();
    
    return true;
}

// 在沙箱中启动应用程序
bool LaunchApplication(DWORD sandboxId, const std::wstring& appPath) {
    Logger::Info("Launching application in sandbox %d: %ls", sandboxId, appPath.c_str());
    
    // 实现应用程序启动逻辑
    // 这里简化处理，实际实现中应该在沙箱环境中启动应用程序
    
    return true;
}

// 保存设置
bool SaveSettings(const UserInterfaceConfig& config) {
    Logger::Info("Saving settings");
    
    // 实现设置保存逻辑
    // 这里简化处理，实际实现中应该将设置保存到配置文件
    
    return true;
}

// 更新沙箱列表
void UpdateSandboxList() {
    if (!g_pUI) return;
    
    // 获取沙箱列表
    // 这里简化处理，实际实现中应该从配置或注册表中获取沙箱列表
    std::vector<SandboxInfo> sandboxes;
    
    // 添加当前沙箱
    SandboxInfo sandbox;
    sandbox.sandboxId = g_SandboxId;
    sandbox.name = L"沙箱 " + std::to_wstring(g_SandboxId);
    sandbox.description = L"测试沙箱环境";
    sandbox.status = SandboxStatus::NotRunning;
    sandbox.imagePath = L"C:\\ProgramData\\LightSandbox\\BaseImage";
    sandbox.memoryUsage = 0;
    sandbox.cpuUsage = 0;
    sandbox.processCount = 0;
    GetSystemTimeAsFileTime(&sandbox.creationTime);
    sandbox.autoStart = false;
    
    sandboxes.push_back(sandbox);
    
    // 更新UI
    g_pUI->UpdateSandboxList(sandboxes);
}

// 更新应用程序列表
void UpdateApplicationList() {
    if (!g_pUI) return;
    
    // 获取应用程序列表
    // 这里简化处理，实际实现中应该从系统中获取已安装的应用程序
    std::vector<ApplicationInfo> applications;
    
    // 添加一些示例应用程序
    ApplicationInfo app1;
    app1.name = L"记事本";
    app1.executablePath = L"C:\\Windows\\System32\\notepad.exe";
    app1.iconPath = L"";
    app1.description = L"Windows记事本";
    app1.isInstalled = true;
    applications.push_back(app1);
    
    ApplicationInfo app2;
    app2.name = L"计算器";
    app2.executablePath = L"C:\\Windows\\System32\\calc.exe";
    app2.iconPath = L"";
    app2.description = L"Windows计算器";
    app2.isInstalled = true;
    applications.push_back(app2);
    
    ApplicationInfo app3;
    app3.name = L"命令提示符";
    app3.executablePath = L"C:\\Windows\\System32\\cmd.exe";
    app3.iconPath = L"";
    app3.description = L"Windows命令提示符";
    app3.isInstalled = true;
    applications.push_back(app3);
    
    // 更新UI
    g_pUI->UpdateApplicationList(applications);
}

// 更新资源使用情况
void UpdateResourceUsage() {
    if (!g_pUI) return;
    
    // 获取资源使用情况
    // 这里简化处理，实际实现中应该从系统中获取真实的资源使用情况
    static int memoryUsage = 0;
    static int cpuUsage = 0;
    
    // 模拟资源使用波动
    memoryUsage = (memoryUsage + 1) % 5; // 0-4%
    cpuUsage = (cpuUsage + 1) % 3; // 0-2%
    
    // 更新UI
    g_pUI->UpdateResourceUsage(memoryUsage, cpuUsage);
}
