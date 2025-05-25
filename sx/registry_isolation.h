/**
 * @file registry_isolation.h
 * @brief 注册表隔离模块头文件
 * 
 * 该文件定义了Windows轻量级沙箱的注册表隔离模块接口，
 * 负责实现注册表虚拟化、键值重定向和注册表访问控制。
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace LightSandbox {

/**
 * @brief 注册表隔离配置
 */
struct RegistryIsolationConfig {
    DWORD sandboxId;                      ///< 沙箱ID
    std::wstring virtualRegistryPath;     ///< 虚拟注册表路径
    bool enableRegistrySharing;           ///< 是否启用注册表共享
    std::vector<std::wstring> readOnlyKeys; ///< 只读键列表
    std::vector<std::wstring> writableKeys; ///< 可写键列表
    std::vector<std::wstring> deniedKeys;   ///< 禁止访问键列表
    
    RegistryIsolationConfig() 
        : sandboxId(0), enableRegistrySharing(false) {}
};

/**
 * @brief 注册表访问规则类型
 */
enum class RegistryAccessRuleType {
    Allow,      ///< 允许访问
    ReadOnly,   ///< 只读访问
    Redirect,   ///< 重定向访问
    Deny        ///< 拒绝访问
};

/**
 * @brief 注册表访问规则
 */
struct RegistryAccessRule {
    std::wstring keyPattern;             ///< 键路径模式
    RegistryAccessRuleType ruleType;     ///< 规则类型
    std::wstring redirectKey;            ///< 重定向键（仅当ruleType为Redirect时有效）
    
    RegistryAccessRule() : ruleType(RegistryAccessRuleType::Deny) {}
    
    RegistryAccessRule(const std::wstring& pattern, RegistryAccessRuleType type)
        : keyPattern(pattern), ruleType(type) {}
        
    RegistryAccessRule(const std::wstring& pattern, const std::wstring& redirect)
        : keyPattern(pattern), ruleType(RegistryAccessRuleType::Redirect), redirectKey(redirect) {}
};

/**
 * @brief 注册表隔离模块接口
 */
class RegistryIsolation {
public:
    /**
     * @brief 初始化注册表隔离模块
     * @param config 注册表隔离配置
     * @return 是否成功初始化
     */
    static bool Initialize(const RegistryIsolationConfig& config);
    
    /**
     * @brief 清理注册表隔离模块
     */
    static void Cleanup();
    
    /**
     * @brief 添加注册表访问规则
     * @param rule 注册表访问规则
     * @return 是否成功添加规则
     */
    static bool AddRegistryAccessRule(const RegistryAccessRule& rule);
    
    /**
     * @brief 移除注册表访问规则
     * @param keyPattern 键路径模式
     * @return 是否成功移除规则
     */
    static bool RemoveRegistryAccessRule(const std::wstring& keyPattern);
    
    /**
     * @brief 检查键是否应该重定向
     * @param originalKey 原始键路径
     * @param redirectedKey 输出参数，重定向后的键路径
     * @return 是否需要重定向
     */
    static bool ShouldRedirectKey(const std::wstring& originalKey, std::wstring& redirectedKey);
    
    /**
     * @brief 检查注册表访问权限
     * @param keyPath 键路径
     * @param desiredAccess 期望的访问权限
     * @param grantedAccess 输出参数，授予的访问权限
     * @return 是否允许访问
     */
    static bool CheckRegistryAccess(const std::wstring& keyPath, DWORD desiredAccess, DWORD& grantedAccess);
    
    /**
     * @brief 创建注册表快照
     * @param snapshotName 快照名称
     * @return 是否成功创建快照
     */
    static bool CreateSnapshot(const std::wstring& snapshotName);
    
    /**
     * @brief 恢复注册表快照
     * @param snapshotName 快照名称
     * @return 是否成功恢复快照
     */
    static bool RestoreSnapshot(const std::wstring& snapshotName);
    
    /**
     * @brief 删除注册表快照
     * @param snapshotName 快照名称
     * @return 是否成功删除快照
     */
    static bool DeleteSnapshot(const std::wstring& snapshotName);
    
    /**
     * @brief 列出所有注册表快照
     * @return 快照名称列表
     */
    static std::vector<std::wstring> ListSnapshots();
    
    /**
     * @brief 从主机系统复制注册表键值到沙箱
     * @param hostKey 主机键路径
     * @param sandboxKey 沙箱键路径
     * @return 是否成功复制
     */
    static bool CopyRegistryKeyToSandbox(const std::wstring& hostKey, const std::wstring& sandboxKey);
    
    /**
     * @brief 从沙箱复制注册表键值到主机系统
     * @param sandboxKey 沙箱键路径
     * @param hostKey 主机键路径
     * @return 是否成功复制
     */
    static bool CopyRegistryKeyFromSandbox(const std::wstring& sandboxKey, const std::wstring& hostKey);
    
    /**
     * @brief 获取注册表操作日志
     * @param startTime 开始时间
     * @param endTime 结束时间
     * @return 注册表操作日志列表
     */
    static std::vector<std::wstring> GetRegistryOperationLogs(FILETIME startTime, FILETIME endTime);
    
    /**
     * @brief 保护关键系统注册表键
     * @return 是否成功设置保护
     */
    static bool ProtectSystemKeys();
};

} // namespace LightSandbox
