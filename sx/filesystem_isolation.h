/**
 * @file filesystem_isolation.h
 * @brief 文件系统隔离模块头文件
 * 
 * 该文件定义了Windows轻量级沙箱的文件系统隔离模块接口，
 * 负责实现文件系统虚拟化、路径重定向和文件访问控制。
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace LightSandbox {

/**
 * @brief 文件系统隔离配置
 */
struct FileSystemIsolationConfig {
    DWORD sandboxId;                      ///< 沙箱ID
    std::wstring baseImagePath;           ///< 基础映像路径
    std::wstring differentialStoragePath; ///< 差异存储路径
    bool enableFileSharing;               ///< 是否启用文件共享
    std::vector<std::wstring> readOnlyPaths; ///< 只读路径列表
    std::vector<std::wstring> writablePaths; ///< 可写路径列表
    std::vector<std::wstring> deniedPaths;   ///< 禁止访问路径列表
    
    FileSystemIsolationConfig() 
        : sandboxId(0), enableFileSharing(false) {}
};

/**
 * @brief 文件访问规则类型
 */
enum class FileAccessRuleType {
    Allow,      ///< 允许访问
    ReadOnly,   ///< 只读访问
    Redirect,   ///< 重定向访问
    Deny        ///< 拒绝访问
};

/**
 * @brief 文件访问规则
 */
struct FileAccessRule {
    std::wstring pathPattern;           ///< 路径模式
    FileAccessRuleType ruleType;        ///< 规则类型
    std::wstring redirectPath;          ///< 重定向路径（仅当ruleType为Redirect时有效）
    
    FileAccessRule() : ruleType(FileAccessRuleType::Deny) {}
    
    FileAccessRule(const std::wstring& pattern, FileAccessRuleType type)
        : pathPattern(pattern), ruleType(type) {}
        
    FileAccessRule(const std::wstring& pattern, const std::wstring& redirect)
        : pathPattern(pattern), ruleType(FileAccessRuleType::Redirect), redirectPath(redirect) {}
};

/**
 * @brief 文件系统隔离模块接口
 */
class FileSystemIsolation {
public:
    /**
     * @brief 初始化文件系统隔离模块
     * @param config 文件系统隔离配置
     * @return 是否成功初始化
     */
    static bool Initialize(const FileSystemIsolationConfig& config);
    
    /**
     * @brief 清理文件系统隔离模块
     */
    static void Cleanup();
    
    /**
     * @brief 添加文件访问规则
     * @param rule 文件访问规则
     * @return 是否成功添加规则
     */
    static bool AddFileAccessRule(const FileAccessRule& rule);
    
    /**
     * @brief 移除文件访问规则
     * @param pathPattern 路径模式
     * @return 是否成功移除规则
     */
    static bool RemoveFileAccessRule(const std::wstring& pathPattern);
    
    /**
     * @brief 检查路径是否应该重定向
     * @param originalPath 原始路径
     * @param redirectedPath 输出参数，重定向后的路径
     * @return 是否需要重定向
     */
    static bool ShouldRedirectPath(const std::wstring& originalPath, std::wstring& redirectedPath);
    
    /**
     * @brief 检查文件访问权限
     * @param filePath 文件路径
     * @param desiredAccess 期望的访问权限
     * @param grantedAccess 输出参数，授予的访问权限
     * @return 是否允许访问
     */
    static bool CheckFileAccess(const std::wstring& filePath, DWORD desiredAccess, DWORD& grantedAccess);
    
    /**
     * @brief 创建文件系统快照
     * @param snapshotName 快照名称
     * @return 是否成功创建快照
     */
    static bool CreateSnapshot(const std::wstring& snapshotName);
    
    /**
     * @brief 恢复文件系统快照
     * @param snapshotName 快照名称
     * @return 是否成功恢复快照
     */
    static bool RestoreSnapshot(const std::wstring& snapshotName);
    
    /**
     * @brief 删除文件系统快照
     * @param snapshotName 快照名称
     * @return 是否成功删除快照
     */
    static bool DeleteSnapshot(const std::wstring& snapshotName);
    
    /**
     * @brief 列出所有文件系统快照
     * @return 快照名称列表
     */
    static std::vector<std::wstring> ListSnapshots();
    
    /**
     * @brief 从主机系统复制文件到沙箱
     * @param hostPath 主机路径
     * @param sandboxPath 沙箱路径
     * @return 是否成功复制
     */
    static bool CopyFileToSandbox(const std::wstring& hostPath, const std::wstring& sandboxPath);
    
    /**
     * @brief 从沙箱复制文件到主机系统
     * @param sandboxPath 沙箱路径
     * @param hostPath 主机路径
     * @return 是否成功复制
     */
    static bool CopyFileFromSandbox(const std::wstring& sandboxPath, const std::wstring& hostPath);
    
    /**
     * @brief 获取文件操作日志
     * @param startTime 开始时间
     * @param endTime 结束时间
     * @return 文件操作日志列表
     */
    static std::vector<std::wstring> GetFileOperationLogs(FILETIME startTime, FILETIME endTime);
};

} // namespace LightSandbox
