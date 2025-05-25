/**
 * @file filesystem_isolation.cpp
 * @brief 文件系统隔离模块实现
 * 
 * 该文件实现了Windows轻量级沙箱的文件系统隔离模块，
 * 负责实现文件系统虚拟化、路径重定向和文件访问控制。
 */

#include "filesystem_isolation.h"
#include "logging.h"
#include <shlwapi.h>
#include <mutex>
#include <algorithm>
#include <regex>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")

namespace LightSandbox {

// 文件系统隔离配置
static FileSystemIsolationConfig g_Config;

// 文件访问规则列表
static std::vector<FileAccessRule> g_FileAccessRules;
static std::mutex g_RulesMutex;

// 文件操作日志
struct FileOperationLogEntry {
    FILETIME timestamp;
    std::wstring operation;
    std::wstring path;
    std::wstring redirectedPath;
    DWORD processId;
    DWORD result;
};

static std::vector<FileOperationLogEntry> g_FileOperationLogs;
static std::mutex g_LogsMutex;

// 快照管理
struct SnapshotInfo {
    std::wstring name;
    std::wstring path;
    FILETIME creationTime;
};

static std::vector<SnapshotInfo> g_Snapshots;
static std::mutex g_SnapshotsMutex;

// 前向声明
static bool InitializeFileSystem();
static bool CreateDirectoryRecursive(const std::wstring& path);
static bool PathMatchesPattern(const std::wstring& path, const std::wstring& pattern);
static void LogFileOperation(const std::wstring& operation, const std::wstring& path, 
                            const std::wstring& redirectedPath, DWORD result);
static std::wstring GetRedirectedPath(const std::wstring& originalPath);
static bool CopyDirectory(const std::wstring& sourceDir, const std::wstring& destDir);

bool FileSystemIsolation::Initialize(const FileSystemIsolationConfig& config) {
    Logger::Info("Initializing FileSystemIsolation module, SandboxId: %d", config.sandboxId);
    
    // 保存配置
    g_Config = config;
    
    // 初始化文件系统
    if (!InitializeFileSystem()) {
        Logger::Error("Failed to initialize file system");
        return false;
    }
    
    // 添加默认规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    g_FileAccessRules.clear();
    
    // 系统目录只读访问
    g_FileAccessRules.push_back(FileAccessRule(L"C:\\Windows\\*", FileAccessRuleType::ReadOnly));
    
    // 程序文件目录只读访问
    g_FileAccessRules.push_back(FileAccessRule(L"C:\\Program Files\\*", FileAccessRuleType::ReadOnly));
    g_FileAccessRules.push_back(FileAccessRule(L"C:\\Program Files (x86)\\*", FileAccessRuleType::ReadOnly));
    
    // 用户文件重定向
    std::wstring userProfilePath = L"C:\\Users\\*";
    std::wstring redirectUserPath = g_Config.differentialStoragePath + L"\\Users";
    g_FileAccessRules.push_back(FileAccessRule(userProfilePath, redirectUserPath));
    
    // 添加用户指定的规则
    for (const auto& path : g_Config.readOnlyPaths) {
        g_FileAccessRules.push_back(FileAccessRule(path, FileAccessRuleType::ReadOnly));
    }
    
    for (const auto& path : g_Config.writablePaths) {
        g_FileAccessRules.push_back(FileAccessRule(path, FileAccessRuleType::Allow));
    }
    
    for (const auto& path : g_Config.deniedPaths) {
        g_FileAccessRules.push_back(FileAccessRule(path, FileAccessRuleType::Deny));
    }
    
    Logger::Info("FileSystemIsolation initialized successfully with %d rules", g_FileAccessRules.size());
    return true;
}

void FileSystemIsolation::Cleanup() {
    Logger::Info("Cleaning up FileSystemIsolation module");
    
    // 清理规则
    std::lock_guard<std::mutex> ruleLock(g_RulesMutex);
    g_FileAccessRules.clear();
    
    // 清理日志
    std::lock_guard<std::mutex> logLock(g_LogsMutex);
    g_FileOperationLogs.clear();
    
    // 清理快照信息
    std::lock_guard<std::mutex> snapshotLock(g_SnapshotsMutex);
    g_Snapshots.clear();
}

bool FileSystemIsolation::AddFileAccessRule(const FileAccessRule& rule) {
    Logger::Info("Adding file access rule for path: %ls, type: %d", 
        rule.pathPattern.c_str(), static_cast<int>(rule.ruleType));
    
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    // 检查是否已存在相同路径的规则
    auto it = std::find_if(g_FileAccessRules.begin(), g_FileAccessRules.end(),
        [&rule](const FileAccessRule& existingRule) {
            return existingRule.pathPattern == rule.pathPattern;
        });
    
    if (it != g_FileAccessRules.end()) {
        // 更新现有规则
        *it = rule;
    } else {
        // 添加新规则
        g_FileAccessRules.push_back(rule);
    }
    
    return true;
}

bool FileSystemIsolation::RemoveFileAccessRule(const std::wstring& pathPattern) {
    Logger::Info("Removing file access rule for path: %ls", pathPattern.c_str());
    
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    auto it = std::find_if(g_FileAccessRules.begin(), g_FileAccessRules.end(),
        [&pathPattern](const FileAccessRule& rule) {
            return rule.pathPattern == pathPattern;
        });
    
    if (it != g_FileAccessRules.end()) {
        g_FileAccessRules.erase(it);
        return true;
    }
    
    Logger::Warning("File access rule not found for path: %ls", pathPattern.c_str());
    return false;
}

bool FileSystemIsolation::ShouldRedirectPath(const std::wstring& originalPath, std::wstring& redirectedPath) {
    // 标准化路径
    wchar_t normalizedPath[MAX_PATH];
    if (!GetFullPathNameW(originalPath.c_str(), MAX_PATH, normalizedPath, NULL)) {
        Logger::Error("Failed to normalize path: %ls, error: %d", originalPath.c_str(), GetLastError());
        return false;
    }
    
    std::wstring path(normalizedPath);
    
    // 检查路径是否匹配任何规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    for (const auto& rule : g_FileAccessRules) {
        if (PathMatchesPattern(path, rule.pathPattern)) {
            switch (rule.ruleType) {
                case FileAccessRuleType::Allow:
                    // 允许直接访问，不需要重定向
                    return false;
                
                case FileAccessRuleType::ReadOnly:
                    // 只读访问，不需要重定向，但在CheckFileAccess中会限制写入权限
                    return false;
                
                case FileAccessRuleType::Redirect:
                    // 需要重定向
                    redirectedPath = GetRedirectedPath(path);
                    LogFileOperation(L"Redirect", path, redirectedPath, 0);
                    return true;
                
                case FileAccessRuleType::Deny:
                    // 拒绝访问，不需要重定向
                    return false;
            }
        }
    }
    
    // 默认重定向到差异存储
    redirectedPath = GetRedirectedPath(path);
    LogFileOperation(L"DefaultRedirect", path, redirectedPath, 0);
    return true;
}

bool FileSystemIsolation::CheckFileAccess(const std::wstring& filePath, DWORD desiredAccess, DWORD& grantedAccess) {
    // 标准化路径
    wchar_t normalizedPath[MAX_PATH];
    if (!GetFullPathNameW(filePath.c_str(), MAX_PATH, normalizedPath, NULL)) {
        Logger::Error("Failed to normalize path: %ls, error: %d", filePath.c_str(), GetLastError());
        return false;
    }
    
    std::wstring path(normalizedPath);
    
    // 检查路径是否匹配任何规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    for (const auto& rule : g_FileAccessRules) {
        if (PathMatchesPattern(path, rule.pathPattern)) {
            switch (rule.ruleType) {
                case FileAccessRuleType::Allow:
                    // 允许所有访问
                    grantedAccess = desiredAccess;
                    LogFileOperation(L"AllowAccess", path, L"", 0);
                    return true;
                
                case FileAccessRuleType::ReadOnly:
                    // 只允许读取访问
                    if (desiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) {
                        // 请求包含写入权限，拒绝
                        grantedAccess = desiredAccess & ~(GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA);
                        LogFileOperation(L"ReadOnlyAccess", path, L"", 0);
                        return grantedAccess != 0; // 如果还有其他权限，则允许
                    } else {
                        // 只请求读取权限，允许
                        grantedAccess = desiredAccess;
                        LogFileOperation(L"ReadOnlyAccess", path, L"", 0);
                        return true;
                    }
                
                case FileAccessRuleType::Redirect:
                    // 重定向后允许所有访问
                    grantedAccess = desiredAccess;
                    return true;
                
                case FileAccessRuleType::Deny:
                    // 拒绝所有访问
                    grantedAccess = 0;
                    LogFileOperation(L"DenyAccess", path, L"", ERROR_ACCESS_DENIED);
                    return false;
            }
        }
    }
    
    // 默认允许所有访问
    grantedAccess = desiredAccess;
    return true;
}

bool FileSystemIsolation::CreateSnapshot(const std::wstring& snapshotName) {
    Logger::Info("Creating file system snapshot: %ls", snapshotName.c_str());
    
    // 检查快照名称是否有效
    if (snapshotName.empty() || snapshotName.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos) {
        Logger::Error("Invalid snapshot name: %ls", snapshotName.c_str());
        return false;
    }
    
    // 创建快照目录
    std::wstring snapshotPath = g_Config.differentialStoragePath + L"\\Snapshots\\" + snapshotName;
    if (!CreateDirectoryRecursive(snapshotPath)) {
        Logger::Error("Failed to create snapshot directory: %ls", snapshotPath.c_str());
        return false;
    }
    
    // 复制差异存储内容到快照目录
    if (!CopyDirectory(g_Config.differentialStoragePath, snapshotPath)) {
        Logger::Error("Failed to copy differential storage to snapshot");
        return false;
    }
    
    // 记录快照信息
    SnapshotInfo snapshot;
    snapshot.name = snapshotName;
    snapshot.path = snapshotPath;
    GetSystemTimeAsFileTime(&snapshot.creationTime);
    
    std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
    g_Snapshots.push_back(snapshot);
    
    Logger::Info("File system snapshot created successfully: %ls", snapshotName.c_str());
    return true;
}

bool FileSystemIsolation::RestoreSnapshot(const std::wstring& snapshotName) {
    Logger::Info("Restoring file system snapshot: %ls", snapshotName.c_str());
    
    // 查找快照
    std::wstring snapshotPath;
    {
        std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
        auto it = std::find_if(g_Snapshots.begin(), g_Snapshots.end(),
            [&snapshotName](const SnapshotInfo& snapshot) {
                return snapshot.name == snapshotName;
            });
        
        if (it == g_Snapshots.end()) {
            Logger::Error("Snapshot not found: %ls", snapshotName.c_str());
            return false;
        }
        
        snapshotPath = it->path;
    }
    
    // 清空差异存储
    std::error_code ec;
    std::filesystem::path diffPath(g_Config.differentialStoragePath);
    for (const auto& entry : std::filesystem::directory_iterator(diffPath, ec)) {
        if (entry.path().filename() != L"Snapshots") {
            std::filesystem::remove_all(entry.path(), ec);
            if (ec) {
                Logger::Warning("Failed to remove %ls, error: %s", 
                    entry.path().c_str(), ec.message().c_str());
            }
        }
    }
    
    // 复制快照内容到差异存储
    if (!CopyDirectory(snapshotPath, g_Config.differentialStoragePath)) {
        Logger::Error("Failed to copy snapshot to differential storage");
        return false;
    }
    
    Logger::Info("File system snapshot restored successfully: %ls", snapshotName.c_str());
    return true;
}

bool FileSystemIsolation::DeleteSnapshot(const std::wstring& snapshotName) {
    Logger::Info("Deleting file system snapshot: %ls", snapshotName.c_str());
    
    // 查找快照
    std::wstring snapshotPath;
    {
        std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
        auto it = std::find_if(g_Snapshots.begin(), g_Snapshots.end(),
            [&snapshotName](const SnapshotInfo& snapshot) {
                return snapshot.name == snapshotName;
            });
        
        if (it == g_Snapshots.end()) {
            Logger::Error("Snapshot not found: %ls", snapshotName.c_str());
            return false;
        }
        
        snapshotPath = it->path;
        g_Snapshots.erase(it);
    }
    
    // 删除快照目录
    std::error_code ec;
    if (!std::filesystem::remove_all(snapshotPath, ec)) {
        Logger::Error("Failed to delete snapshot directory: %ls, error: %s", 
            snapshotPath.c_str(), ec.message().c_str());
        return false;
    }
    
    Logger::Info("File system snapshot deleted successfully: %ls", snapshotName.c_str());
    return true;
}

std::vector<std::wstring> FileSystemIsolation::ListSnapshots() {
    std::vector<std::wstring> result;
    
    std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
    for (const auto& snapshot : g_Snapshots) {
        result.push_back(snapshot.name);
    }
    
    return result;
}

bool FileSystemIsolation::CopyFileToSandbox(const std::wstring& hostPath, const std::wstring& sandboxPath) {
    Logger::Info("Copying file from host to sandbox: %ls -> %ls", hostPath.c_str(), sandboxPath.c_str());
    
    // 获取沙箱中的实际路径
    std::wstring redirectedPath;
    if (ShouldRedirectPath(sandboxPath, redirectedPath)) {
        // 确保目标目录存在
        std::wstring directory = redirectedPath.substr(0, redirectedPath.find_last_of(L'\\'));
        if (!CreateDirectoryRecursive(directory)) {
            Logger::Error("Failed to create directory: %ls", directory.c_str());
            return false;
        }
        
        // 复制文件
        if (!CopyFileW(hostPath.c_str(), redirectedPath.c_str(), FALSE)) {
            Logger::Error("Failed to copy file: %ls -> %ls, error: %d", 
                hostPath.c_str(), redirectedPath.c_str(), GetLastError());
            return false;
        }
    } else {
        // 直接复制到目标路径
        // 确保目标目录存在
        std::wstring directory = sandboxPath.substr(0, sandboxPath.find_last_of(L'\\'));
        if (!CreateDirectoryRecursive(directory)) {
            Logger::Error("Failed to create directory: %ls", directory.c_str());
            return false;
        }
        
        // 复制文件
        if (!CopyFileW(hostPath.c_str(), sandboxPath.c_str(), FALSE)) {
            Logger::Error("Failed to copy file: %ls -> %ls, error: %d", 
                hostPath.c_str(), sandboxPath.c_str(), GetLastError());
            return false;
        }
    }
    
    Logger::Info("File copied successfully from host to sandbox");
    return true;
}

bool FileSystemIsolation::CopyFileFromSandbox(const std::wstring& sandboxPath, const std::wstring& hostPath) {
    Logger::Info("Copying file from sandbox to host: %ls -> %ls", sandboxPath.c_str(), hostPath.c_str());
    
    // 获取沙箱中的实际路径
    std::wstring redirectedPath;
    std::wstring sourcePath = sandboxPath;
    
    if (ShouldRedirectPath(sandboxPath, redirectedPath)) {
        // 检查重定向路径是否存在
        if (GetFileAttributesW(redirectedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            // 重定向路径不存在，尝试从基础映像中复制
            sourcePath = g_Config.baseImagePath + L"\\" + sandboxPath.substr(3); // 去掉驱动器前缀 (C:\)
            
            if (GetFileAttributesW(sourcePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                Logger::Error("Source file not found in sandbox: %ls", sandboxPath.c_str());
                return false;
            }
        } else {
            sourcePath = redirectedPath;
        }
    }
    
    // 确保目标目录存在
    std::wstring directory = hostPath.substr(0, hostPath.find_last_of(L'\\'));
    if (!CreateDirectoryRecursive(directory)) {
        Logger::Error("Failed to create directory: %ls", directory.c_str());
        return false;
    }
    
    // 复制文件
    if (!CopyFileW(sourcePath.c_str(), hostPath.c_str(), FALSE)) {
        Logger::Error("Failed to copy file: %ls -> %ls, error: %d", 
            sourcePath.c_str(), hostPath.c_str(), GetLastError());
        return false;
    }
    
    Logger::Info("File copied successfully from sandbox to host");
    return true;
}

std::vector<std::wstring> FileSystemIsolation::GetFileOperationLogs(FILETIME startTime, FILETIME endTime) {
    std::vector<std::wstring> result;
    
    std::lock_guard<std::mutex> lock(g_LogsMutex);
    
    for (const auto& entry : g_FileOperationLogs) {
        // 检查时间范围
        if (CompareFileTime(&entry.timestamp, &startTime) >= 0 && 
            CompareFileTime(&entry.timestamp, &endTime) <= 0) {
            
            // 格式化日志条目
            SYSTEMTIME st;
            FileTimeToSystemTime(&entry.timestamp, &st);
            
            wchar_t timeStr[64];
            swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            
            std::wstring logEntry = std::wstring(timeStr) + L" [" + std::to_wstring(entry.processId) + L"] " +
                entry.operation + L": " + entry.path;
            
            if (!entry.redirectedPath.empty()) {
                logEntry += L" -> " + entry.redirectedPath;
            }
            
            if (entry.result != 0) {
                logEntry += L" (Error: " + std::to_wstring(entry.result) + L")";
            }
            
            result.push_back(logEntry);
        }
    }
    
    return result;
}

// 初始化文件系统
static bool InitializeFileSystem() {
    // 确保差异存储目录存在
    if (!CreateDirectoryRecursive(g_Config.differentialStoragePath)) {
        Logger::Error("Failed to create differential storage directory: %ls", 
            g_Config.differentialStoragePath.c_str());
        return false;
    }
    
    // 创建快照目录
    std::wstring snapshotsDir = g_Config.differentialStoragePath + L"\\Snapshots";
    if (!CreateDirectoryRecursive(snapshotsDir)) {
        Logger::Error("Failed to create snapshots directory: %ls", snapshotsDir.c_str());
        return false;
    }
    
    // 加载现有快照信息
    std::error_code ec;
    std::filesystem::path snapshotsPath(snapshotsDir);
    
    std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
    g_Snapshots.clear();
    
    for (const auto& entry : std::filesystem::directory_iterator(snapshotsPath, ec)) {
        if (entry.is_directory()) {
            SnapshotInfo snapshot;
            snapshot.name = entry.path().filename().wstring();
            snapshot.path = entry.path().wstring();
            
            // 获取创建时间
            WIN32_FILE_ATTRIBUTE_DATA fileInfo;
            if (GetFileAttributesExW(entry.path().c_str(), GetFileExInfoStandard, &fileInfo)) {
                snapshot.creationTime = fileInfo.ftCreationTime;
            } else {
                GetSystemTimeAsFileTime(&snapshot.creationTime);
            }
            
            g_Snapshots.push_back(snapshot);
            Logger::Info("Loaded existing snapshot: %ls", snapshot.name.c_str());
        }
    }
    
    return true;
}

// 递归创建目录
static bool CreateDirectoryRecursive(const std::wstring& path) {
    // 检查路径是否已存在
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return true; // 路径已存在
    }
    
    // 获取父目录
    size_t pos = path.find_last_of(L'\\');
    if (pos == std::wstring::npos) {
        return false; // 无效路径
    }
    
    std::wstring parentPath = path.substr(0, pos);
    
    // 递归创建父目录
    if (!parentPath.empty() && !CreateDirectoryRecursive(parentPath)) {
        return false;
    }
    
    // 创建当前目录
    if (!CreateDirectoryW(path.c_str(), NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            Logger::Error("Failed to create directory: %ls, error: %d", path.c_str(), error);
            return false;
        }
    }
    
    return true;
}

// 检查路径是否匹配模式
static bool PathMatchesPattern(const std::wstring& path, const std::wstring& pattern) {
    // 使用Windows API进行通配符匹配
    return PathMatchSpecW(path.c_str(), pattern.c_str()) == TRUE;
}

// 记录文件操作
static void LogFileOperation(const std::wstring& operation, const std::wstring& path, 
                            const std::wstring& redirectedPath, DWORD result) {
    FileOperationLogEntry entry;
    GetSystemTimeAsFileTime(&entry.timestamp);
    entry.operation = operation;
    entry.path = path;
    entry.redirectedPath = redirectedPath;
    entry.processId = GetCurrentProcessId();
    entry.result = result;
    
    std::lock_guard<std::mutex> lock(g_LogsMutex);
    g_FileOperationLogs.push_back(entry);
    
    // 限制日志大小
    const size_t MAX_LOG_ENTRIES = 10000;
    if (g_FileOperationLogs.size() > MAX_LOG_ENTRIES) {
        g_FileOperationLogs.erase(g_FileOperationLogs.begin(), 
            g_FileOperationLogs.begin() + (g_FileOperationLogs.size() - MAX_LOG_ENTRIES));
    }
}

// 获取重定向路径
static std::wstring GetRedirectedPath(const std::wstring& originalPath) {
    // 移除驱动器前缀 (C:\)
    std::wstring relativePath = originalPath.substr(2);
    
    // 构建重定向路径
    std::wstring redirectedPath = g_Config.differentialStoragePath + relativePath;
    
    return redirectedPath;
}

// 递归复制目录
static bool CopyDirectory(const std::wstring& sourceDir, const std::wstring& destDir) {
    // 确保目标目录存在
    if (!CreateDirectoryRecursive(destDir)) {
        Logger::Error("Failed to create directory: %ls", destDir.c_str());
        return false;
    }
    
    std::error_code ec;
    std::filesystem::path sourcePath(sourceDir);
    
    try {
        // 遍历源目录中的所有文件和子目录
        for (const auto& entry : std::filesystem::directory_iterator(sourcePath, ec)) {
            std::filesystem::path destPath = std::filesystem::path(destDir) / entry.path().filename();
            
            if (entry.is_directory()) {
                // 跳过Snapshots目录，避免递归复制
                if (entry.path().filename() == L"Snapshots") {
                    continue;
                }
                
                // 递归复制子目录
                if (!CopyDirectory(entry.path().wstring(), destPath.wstring())) {
                    return false;
                }
            } else if (entry.is_regular_file()) {
                // 复制文件
                if (!CopyFileW(entry.path().c_str(), destPath.c_str(), FALSE)) {
                    Logger::Error("Failed to copy file: %ls -> %ls, error: %d", 
                        entry.path().c_str(), destPath.c_str(), GetLastError());
                    return false;
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::Error("Exception during directory copy: %s", e.what());
        return false;
    }
    
    return true;
}

} // namespace LightSandbox
