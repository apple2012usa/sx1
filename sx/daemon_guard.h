/**
 * @file daemon_guard.h
 * @brief 守护进程模块头文件
 * 
 * 该文件定义了Windows轻量级沙箱的守护进程模块接口，
 * 负责防止沙箱被恶意程序关闭，并提供自我保护和恢复机制。
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>

namespace LightSandbox {

/**
 * @brief 守护进程配置
 */
struct DaemonGuardConfig {
    DWORD sandboxId;                      ///< 沙箱ID
    std::wstring serviceName;             ///< 守护进程服务名称
    std::wstring serviceDisplayName;      ///< 守护进程服务显示名称
    std::wstring serviceDescription;      ///< 守护进程服务描述
    bool autoRestart;                     ///< 是否自动重启沙箱
    DWORD restartDelay;                   ///< 重启延迟（毫秒）
    bool protectAgainstTermination;       ///< 是否防止进程被终止
    bool installDriverProtection;         ///< 是否安装驱动级保护
    
    DaemonGuardConfig() 
        : sandboxId(0), autoRestart(true), restartDelay(1000), 
          protectAgainstTermination(true), installDriverProtection(false) {}
};

/**
 * @brief 守护进程状态
 */
enum class DaemonGuardStatus {
    NotInstalled,    ///< 未安装
    Stopped,         ///< 已停止
    Running,         ///< 正在运行
    Failed           ///< 失败
};

/**
 * @brief 沙箱进程信息
 */
struct SandboxProcessInfo {
    DWORD processId;         ///< 进程ID
    std::wstring executablePath; ///< 可执行文件路径
    std::wstring commandLine;    ///< 命令行参数
    FILETIME startTime;       ///< 启动时间
    bool isProtected;         ///< 是否受保护
};

/**
 * @brief 守护进程模块接口
 */
class DaemonGuard {
public:
    /**
     * @brief 初始化守护进程模块
     * @param config 守护进程配置
     * @return 是否成功初始化
     */
    static bool Initialize(const DaemonGuardConfig& config);
    
    /**
     * @brief 清理守护进程模块
     */
    static void Cleanup();
    
    /**
     * @brief 安装守护进程服务
     * @return 是否成功安装
     */
    static bool InstallService();
    
    /**
     * @brief 卸载守护进程服务
     * @return 是否成功卸载
     */
    static bool UninstallService();
    
    /**
     * @brief 启动守护进程服务
     * @return 是否成功启动
     */
    static bool StartService();
    
    /**
     * @brief 停止守护进程服务
     * @return 是否成功停止
     */
    static bool StopService();
    
    /**
     * @brief 获取守护进程状态
     * @return 守护进程状态
     */
    static DaemonGuardStatus GetStatus();
    
    /**
     * @brief 注册沙箱进程
     * @param processId 进程ID
     * @param executablePath 可执行文件路径
     * @param commandLine 命令行参数
     * @return 是否成功注册
     */
    static bool RegisterSandboxProcess(DWORD processId, const std::wstring& executablePath, 
                                      const std::wstring& commandLine);
    
    /**
     * @brief 注销沙箱进程
     * @param processId 进程ID
     * @return 是否成功注销
     */
    static bool UnregisterSandboxProcess(DWORD processId);
    
    /**
     * @brief 保护沙箱进程
     * @param processId 进程ID
     * @return 是否成功保护
     */
    static bool ProtectSandboxProcess(DWORD processId);
    
    /**
     * @brief 获取所有受保护的沙箱进程
     * @return 沙箱进程信息列表
     */
    static std::vector<SandboxProcessInfo> GetProtectedProcesses();
    
    /**
     * @brief 安装驱动级保护
     * @return 是否成功安装
     */
    static bool InstallDriverProtection();
    
    /**
     * @brief 卸载驱动级保护
     * @return 是否成功卸载
     */
    static bool UninstallDriverProtection();
    
    /**
     * @brief 设置进程终止回调
     * @param callback 回调函数
     */
    static void SetProcessTerminationCallback(std::function<void(DWORD)> callback);
    
    /**
     * @brief 设置守护进程状态变化回调
     * @param callback 回调函数
     */
    static void SetStatusChangeCallback(std::function<void(DaemonGuardStatus)> callback);
    
    /**
     * @brief 检查守护进程是否正常运行
     * @return 是否正常运行
     */
    static bool IsHealthy();
    
    /**
     * @brief 获取守护进程日志
     * @param maxLines 最大行数
     * @return 日志内容
     */
    static std::vector<std::wstring> GetLogs(int maxLines = 100);
};

} // namespace LightSandbox
