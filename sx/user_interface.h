/**
 * @file user_interface.h
 * @brief 用户界面模块头文件
 * 
 * 该文件定义了Windows轻量级沙箱的用户界面模块接口，
 * 负责提供直观的图形界面，方便用户管理沙箱。
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace LightSandbox {

// 前向声明
class UIImplementation;

/**
 * @brief 沙箱状态
 */
enum class SandboxStatus {
    NotRunning,     ///< 未运行
    Starting,       ///< 正在启动
    Running,        ///< 正在运行
    Stopping,       ///< 正在停止
    Error           ///< 错误
};

/**
 * @brief 沙箱信息
 */
struct SandboxInfo {
    DWORD sandboxId;                ///< 沙箱ID
    std::wstring name;              ///< 沙箱名称
    std::wstring description;       ///< 沙箱描述
    SandboxStatus status;           ///< 沙箱状态
    std::wstring imagePath;         ///< 沙箱映像路径
    DWORD memoryUsage;              ///< 内存使用量（KB）
    DWORD cpuUsage;                 ///< CPU使用率（百分比）
    DWORD processCount;             ///< 进程数量
    FILETIME creationTime;          ///< 创建时间
    bool autoStart;                 ///< 是否自动启动
};

/**
 * @brief 应用程序信息
 */
struct ApplicationInfo {
    std::wstring name;              ///< 应用程序名称
    std::wstring executablePath;    ///< 可执行文件路径
    std::wstring iconPath;          ///< 图标路径
    std::wstring description;       ///< 描述
    bool isInstalled;               ///< 是否已安装
};

/**
 * @brief 用户界面配置
 */
struct UserInterfaceConfig {
    bool showTrayIcon;              ///< 是否显示托盘图标
    bool minimizeToTray;            ///< 是否最小化到托盘
    bool showNotifications;         ///< 是否显示通知
    bool darkMode;                  ///< 是否使用暗色模式
    std::wstring language;          ///< 界面语言
    
    UserInterfaceConfig() 
        : showTrayIcon(true), minimizeToTray(true), 
          showNotifications(true), darkMode(false), language(L"zh-CN") {}
};

/**
 * @brief 用户界面模块接口
 */
class UserInterface {
public:
    /**
     * @brief 构造函数
     */
    UserInterface();
    
    /**
     * @brief 析构函数
     */
    ~UserInterface();
    
    /**
     * @brief 初始化用户界面
     * @param config 用户界面配置
     * @param hInstance 应用程序实例句柄
     * @return 是否成功初始化
     */
    bool Initialize(const UserInterfaceConfig& config, HINSTANCE hInstance);
    
    /**
     * @brief 显示主窗口
     * @return 是否成功显示
     */
    bool Show();
    
    /**
     * @brief 隐藏主窗口
     * @return 是否成功隐藏
     */
    bool Hide();
    
    /**
     * @brief 运行消息循环
     * @return 退出代码
     */
    int Run();
    
    /**
     * @brief 退出应用程序
     */
    void Exit();
    
    /**
     * @brief 显示通知
     * @param title 通知标题
     * @param message 通知内容
     * @param type 通知类型（0: 信息, 1: 警告, 2: 错误）
     */
    void ShowNotification(const std::wstring& title, const std::wstring& message, int type = 0);
    
    /**
     * @brief 更新沙箱列表
     * @param sandboxes 沙箱信息列表
     */
    void UpdateSandboxList(const std::vector<SandboxInfo>& sandboxes);
    
    /**
     * @brief 更新应用程序列表
     * @param applications 应用程序信息列表
     */
    void UpdateApplicationList(const std::vector<ApplicationInfo>& applications);
    
    /**
     * @brief 更新资源使用情况
     * @param memoryUsage 内存使用率（百分比）
     * @param cpuUsage CPU使用率（百分比）
     */
    void UpdateResourceUsage(int memoryUsage, int cpuUsage);
    
    /**
     * @brief 更新日志
     * @param logs 日志内容
     */
    void UpdateLogs(const std::vector<std::wstring>& logs);
    
    /**
     * @brief 设置沙箱启动回调
     * @param callback 回调函数
     */
    void SetSandboxStartCallback(std::function<bool(DWORD)> callback);
    
    /**
     * @brief 设置沙箱停止回调
     * @param callback 回调函数
     */
    void SetSandboxStopCallback(std::function<bool(DWORD)> callback);
    
    /**
     * @brief 设置沙箱创建回调
     * @param callback 回调函数
     */
    void SetSandboxCreateCallback(std::function<bool(const SandboxInfo&)> callback);
    
    /**
     * @brief 设置沙箱删除回调
     * @param callback 回调函数
     */
    void SetSandboxDeleteCallback(std::function<bool(DWORD)> callback);
    
    /**
     * @brief 设置应用程序启动回调
     * @param callback 回调函数
     */
    void SetApplicationLaunchCallback(std::function<bool(DWORD, const std::wstring&)> callback);
    
    /**
     * @brief 设置快照创建回调
     * @param callback 回调函数
     */
    void SetSnapshotCreateCallback(std::function<bool(DWORD, const std::wstring&)> callback);
    
    /**
     * @brief 设置快照恢复回调
     * @param callback 回调函数
     */
    void SetSnapshotRestoreCallback(std::function<bool(DWORD, const std::wstring&)> callback);
    
    /**
     * @brief 设置快照删除回调
     * @param callback 回调函数
     */
    void SetSnapshotDeleteCallback(std::function<bool(DWORD, const std::wstring&)> callback);
    
    /**
     * @brief 设置设置保存回调
     * @param callback 回调函数
     */
    void SetSettingsSaveCallback(std::function<bool(const UserInterfaceConfig&)> callback);
    
private:
    std::unique_ptr<UIImplementation> m_pImpl; ///< 实现指针
};

} // namespace LightSandbox
