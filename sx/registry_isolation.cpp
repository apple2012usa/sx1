/**
 * @file registry_isolation.cpp
 * @brief 注册表隔离模块实现
 * 
 * 该文件实现了Windows轻量级沙箱的注册表隔离模块，
 * 负责实现注册表虚拟化、键值重定向和注册表访问控制。
 */

#include "registry_isolation.h"
#include "logging.h"
#include <mutex>
#include <algorithm>
#include <regex>
#include <fstream>
#include <filesystem>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace LightSandbox {

// 注册表隔离配置
static RegistryIsolationConfig g_Config;

// 注册表访问规则列表
static std::vector<RegistryAccessRule> g_RegistryAccessRules;
static std::mutex g_RulesMutex;

// 注册表操作日志
struct RegistryOperationLogEntry {
    FILETIME timestamp;
    std::wstring operation;
    std::wstring keyPath;
    std::wstring redirectedKeyPath;
    DWORD processId;
    DWORD result;
};

static std::vector<RegistryOperationLogEntry> g_RegistryOperationLogs;
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
static bool InitializeRegistry();
static bool CreateRegistryKeyRecursive(HKEY hRootKey, const std::wstring& keyPath);
static bool KeyMatchesPattern(const std::wstring& keyPath, const std::wstring& pattern);
static void LogRegistryOperation(const std::wstring& operation, const std::wstring& keyPath, 
                               const std::wstring& redirectedKeyPath, DWORD result);
static std::wstring GetRedirectedKeyPath(const std::wstring& originalKeyPath);
static bool CopyRegistryKeyRecursive(HKEY hSourceKey, HKEY hDestKey);
static HKEY GetRootKeyFromPath(const std::wstring& keyPath, std::wstring& subKeyPath);
static std::wstring GetFullKeyPath(HKEY hKey, const std::wstring& subKeyPath);

bool RegistryIsolation::Initialize(const RegistryIsolationConfig& config) {
    Logger::Info("Initializing RegistryIsolation module, SandboxId: %d", config.sandboxId);
    
    // 保存配置
    g_Config = config;
    
    // 初始化注册表
    if (!InitializeRegistry()) {
        Logger::Error("Failed to initialize registry");
        return false;
    }
    
    // 添加默认规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    g_RegistryAccessRules.clear();
    
    // HKEY_LOCAL_MACHINE 只读访问
    g_RegistryAccessRules.push_back(RegistryAccessRule(L"HKEY_LOCAL_MACHINE\\*", RegistryAccessRuleType::ReadOnly));
    
    // HKEY_CLASSES_ROOT 只读访问
    g_RegistryAccessRules.push_back(RegistryAccessRule(L"HKEY_CLASSES_ROOT\\*", RegistryAccessRuleType::ReadOnly));
    
    // HKEY_CURRENT_USER 重定向
    std::wstring redirectUserKey = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\LightSandbox\\Sandbox" + 
                                  std::to_wstring(g_Config.sandboxId) + L"\\HKEY_CURRENT_USER";
    g_RegistryAccessRules.push_back(RegistryAccessRule(L"HKEY_CURRENT_USER\\*", redirectUserKey + L"\\*"));
    
    // 添加用户指定的规则
    for (const auto& key : g_Config.readOnlyKeys) {
        g_RegistryAccessRules.push_back(RegistryAccessRule(key, RegistryAccessRuleType::ReadOnly));
    }
    
    for (const auto& key : g_Config.writableKeys) {
        g_RegistryAccessRules.push_back(RegistryAccessRule(key, RegistryAccessRuleType::Allow));
    }
    
    for (const auto& key : g_Config.deniedKeys) {
        g_RegistryAccessRules.push_back(RegistryAccessRule(key, RegistryAccessRuleType::Deny));
    }
    
    // 保护关键系统注册表键
    ProtectSystemKeys();
    
    Logger::Info("RegistryIsolation initialized successfully with %d rules", g_RegistryAccessRules.size());
    return true;
}

void RegistryIsolation::Cleanup() {
    Logger::Info("Cleaning up RegistryIsolation module");
    
    // 清理规则
    std::lock_guard<std::mutex> ruleLock(g_RulesMutex);
    g_RegistryAccessRules.clear();
    
    // 清理日志
    std::lock_guard<std::mutex> logLock(g_LogsMutex);
    g_RegistryOperationLogs.clear();
    
    // 清理快照信息
    std::lock_guard<std::mutex> snapshotLock(g_SnapshotsMutex);
    g_Snapshots.clear();
}

bool RegistryIsolation::AddRegistryAccessRule(const RegistryAccessRule& rule) {
    Logger::Info("Adding registry access rule for key: %ls, type: %d", 
        rule.keyPattern.c_str(), static_cast<int>(rule.ruleType));
    
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    // 检查是否已存在相同路径的规则
    auto it = std::find_if(g_RegistryAccessRules.begin(), g_RegistryAccessRules.end(),
        [&rule](const RegistryAccessRule& existingRule) {
            return existingRule.keyPattern == rule.keyPattern;
        });
    
    if (it != g_RegistryAccessRules.end()) {
        // 更新现有规则
        *it = rule;
    } else {
        // 添加新规则
        g_RegistryAccessRules.push_back(rule);
    }
    
    return true;
}

bool RegistryIsolation::RemoveRegistryAccessRule(const std::wstring& keyPattern) {
    Logger::Info("Removing registry access rule for key: %ls", keyPattern.c_str());
    
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    auto it = std::find_if(g_RegistryAccessRules.begin(), g_RegistryAccessRules.end(),
        [&keyPattern](const RegistryAccessRule& rule) {
            return rule.keyPattern == keyPattern;
        });
    
    if (it != g_RegistryAccessRules.end()) {
        g_RegistryAccessRules.erase(it);
        return true;
    }
    
    Logger::Warning("Registry access rule not found for key: %ls", keyPattern.c_str());
    return false;
}

bool RegistryIsolation::ShouldRedirectKey(const std::wstring& originalKey, std::wstring& redirectedKey) {
    // 检查键是否匹配任何规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    for (const auto& rule : g_RegistryAccessRules) {
        if (KeyMatchesPattern(originalKey, rule.keyPattern)) {
            switch (rule.ruleType) {
                case RegistryAccessRuleType::Allow:
                    // 允许直接访问，不需要重定向
                    return false;
                
                case RegistryAccessRuleType::ReadOnly:
                    // 只读访问，不需要重定向，但在CheckRegistryAccess中会限制写入权限
                    return false;
                
                case RegistryAccessRuleType::Redirect:
                    // 需要重定向
                    // 将原始键路径中的通配符部分替换为重定向键中的通配符部分
                    size_t wildcardPos = rule.keyPattern.find(L'*');
                    if (wildcardPos != std::wstring::npos) {
                        size_t redirectWildcardPos = rule.redirectKey.find(L'*');
                        if (redirectWildcardPos != std::wstring::npos) {
                            // 提取通配符匹配的部分
                            std::wstring matchedPart = originalKey.substr(wildcardPos);
                            // 构建重定向键路径
                            redirectedKey = rule.redirectKey.substr(0, redirectWildcardPos) + matchedPart;
                        } else {
                            redirectedKey = rule.redirectKey;
                        }
                    } else {
                        redirectedKey = rule.redirectKey;
                    }
                    
                    LogRegistryOperation(L"Redirect", originalKey, redirectedKey, 0);
                    return true;
                
                case RegistryAccessRuleType::Deny:
                    // 拒绝访问，不需要重定向
                    return false;
            }
        }
    }
    
    // 默认重定向到虚拟注册表
    redirectedKey = GetRedirectedKeyPath(originalKey);
    LogRegistryOperation(L"DefaultRedirect", originalKey, redirectedKey, 0);
    return true;
}

bool RegistryIsolation::CheckRegistryAccess(const std::wstring& keyPath, DWORD desiredAccess, DWORD& grantedAccess) {
    // 检查键是否匹配任何规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    for (const auto& rule : g_RegistryAccessRules) {
        if (KeyMatchesPattern(keyPath, rule.keyPattern)) {
            switch (rule.ruleType) {
                case RegistryAccessRuleType::Allow:
                    // 允许所有访问
                    grantedAccess = desiredAccess;
                    LogRegistryOperation(L"AllowAccess", keyPath, L"", 0);
                    return true;
                
                case RegistryAccessRuleType::ReadOnly:
                    // 只允许读取访问
                    if (desiredAccess & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | KEY_WRITE)) {
                        // 请求包含写入权限，拒绝
                        grantedAccess = desiredAccess & ~(KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | KEY_WRITE);
                        LogRegistryOperation(L"ReadOnlyAccess", keyPath, L"", 0);
                        return grantedAccess != 0; // 如果还有其他权限，则允许
                    } else {
                        // 只请求读取权限，允许
                        grantedAccess = desiredAccess;
                        LogRegistryOperation(L"ReadOnlyAccess", keyPath, L"", 0);
                        return true;
                    }
                
                case RegistryAccessRuleType::Redirect:
                    // 重定向后允许所有访问
                    grantedAccess = desiredAccess;
                    return true;
                
                case RegistryAccessRuleType::Deny:
                    // 拒绝所有访问
                    grantedAccess = 0;
                    LogRegistryOperation(L"DenyAccess", keyPath, L"", ERROR_ACCESS_DENIED);
                    return false;
            }
        }
    }
    
    // 默认允许所有访问
    grantedAccess = desiredAccess;
    return true;
}

bool RegistryIsolation::CreateSnapshot(const std::wstring& snapshotName) {
    Logger::Info("Creating registry snapshot: %ls", snapshotName.c_str());
    
    // 检查快照名称是否有效
    if (snapshotName.empty() || snapshotName.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos) {
        Logger::Error("Invalid snapshot name: %ls", snapshotName.c_str());
        return false;
    }
    
    // 创建快照目录
    std::wstring snapshotPath = g_Config.virtualRegistryPath + L"\\Snapshots\\" + snapshotName;
    std::error_code ec;
    std::filesystem::create_directories(snapshotPath, ec);
    if (ec) {
        Logger::Error("Failed to create snapshot directory: %ls, error: %s", 
            snapshotPath.c_str(), ec.message().c_str());
        return false;
    }
    
    // 导出虚拟注册表到快照
    std::wstring regFilePath = snapshotPath + L"\\registry.reg";
    
    // 打开虚拟注册表根键
    HKEY hVirtualRoot;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        (L"SOFTWARE\\LightSandbox\\Sandbox" + std::to_wstring(g_Config.sandboxId)).c_str(), 
        0, KEY_READ, &hVirtualRoot);
    
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to open virtual registry root key, error: %d", result);
        return false;
    }
    
    // 导出注册表到文件
    // 注意：实际实现中应该使用RegSaveKey或自定义导出函数
    // 这里简化处理，使用系统reg.exe工具导出
    std::wstring command = L"reg export \"HKLM\\SOFTWARE\\LightSandbox\\Sandbox" + 
                          std::to_wstring(g_Config.sandboxId) + L"\" \"" + 
                          regFilePath + L"\" /y";
    
    int exitCode = _wsystem(command.c_str());
    RegCloseKey(hVirtualRoot);
    
    if (exitCode != 0) {
        Logger::Error("Failed to export registry to file, exit code: %d", exitCode);
        return false;
    }
    
    // 记录快照信息
    SnapshotInfo snapshot;
    snapshot.name = snapshotName;
    snapshot.path = snapshotPath;
    GetSystemTimeAsFileTime(&snapshot.creationTime);
    
    std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
    g_Snapshots.push_back(snapshot);
    
    Logger::Info("Registry snapshot created successfully: %ls", snapshotName.c_str());
    return true;
}

bool RegistryIsolation::RestoreSnapshot(const std::wstring& snapshotName) {
    Logger::Info("Restoring registry snapshot: %ls", snapshotName.c_str());
    
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
    
    // 检查快照文件是否存在
    std::wstring regFilePath = snapshotPath + L"\\registry.reg";
    if (GetFileAttributesW(regFilePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Logger::Error("Snapshot registry file not found: %ls", regFilePath.c_str());
        return false;
    }
    
    // 删除当前虚拟注册表
    HKEY hSoftware;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_WRITE, &hSoftware);
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to open SOFTWARE key, error: %d", result);
        return false;
    }
    
    std::wstring sandboxKeyName = L"LightSandbox\\Sandbox" + std::to_wstring(g_Config.sandboxId);
    result = RegDeleteTreeW(hSoftware, sandboxKeyName.c_str());
    RegCloseKey(hSoftware);
    
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        Logger::Error("Failed to delete virtual registry, error: %d", result);
        return false;
    }
    
    // 导入快照文件
    // 注意：实际实现中应该使用RegLoadKey或自定义导入函数
    // 这里简化处理，使用系统reg.exe工具导入
    std::wstring command = L"reg import \"" + regFilePath + L"\"";
    
    int exitCode = _wsystem(command.c_str());
    if (exitCode != 0) {
        Logger::Error("Failed to import registry from file, exit code: %d", exitCode);
        return false;
    }
    
    Logger::Info("Registry snapshot restored successfully: %ls", snapshotName.c_str());
    return true;
}

bool RegistryIsolation::DeleteSnapshot(const std::wstring& snapshotName) {
    Logger::Info("Deleting registry snapshot: %ls", snapshotName.c_str());
    
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
    
    Logger::Info("Registry snapshot deleted successfully: %ls", snapshotName.c_str());
    return true;
}

std::vector<std::wstring> RegistryIsolation::ListSnapshots() {
    std::vector<std::wstring> result;
    
    std::lock_guard<std::mutex> lock(g_SnapshotsMutex);
    for (const auto& snapshot : g_Snapshots) {
        result.push_back(snapshot.name);
    }
    
    return result;
}

bool RegistryIsolation::CopyRegistryKeyToSandbox(const std::wstring& hostKey, const std::wstring& sandboxKey) {
    Logger::Info("Copying registry key from host to sandbox: %ls -> %ls", 
        hostKey.c_str(), sandboxKey.c_str());
    
    // 解析源键路径
    std::wstring hostSubKey;
    HKEY hHostRoot = GetRootKeyFromPath(hostKey, hostSubKey);
    if (hHostRoot == NULL) {
        Logger::Error("Invalid host key path: %ls", hostKey.c_str());
        return false;
    }
    
    // 打开源键
    HKEY hHostKey;
    LONG result = RegOpenKeyExW(hHostRoot, hostSubKey.c_str(), 0, KEY_READ, &hHostKey);
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to open host key: %ls, error: %d", hostKey.c_str(), result);
        return false;
    }
    
    // 获取沙箱中的实际键路径
    std::wstring redirectedKey;
    std::wstring targetKey = sandboxKey;
    
    if (ShouldRedirectKey(sandboxKey, redirectedKey)) {
        targetKey = redirectedKey;
    }
    
    // 解析目标键路径
    std::wstring sandboxSubKey;
    HKEY hSandboxRoot = GetRootKeyFromPath(targetKey, sandboxSubKey);
    if (hSandboxRoot == NULL) {
        RegCloseKey(hHostKey);
        Logger::Error("Invalid sandbox key path: %ls", targetKey.c_str());
        return false;
    }
    
    // 创建目标键
    HKEY hSandboxKey;
    result = RegCreateKeyExW(hSandboxRoot, sandboxSubKey.c_str(), 0, NULL, 
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSandboxKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        RegCloseKey(hHostKey);
        Logger::Error("Failed to create sandbox key: %ls, error: %d", targetKey.c_str(), result);
        return false;
    }
    
    // 复制键值
    bool success = CopyRegistryKeyRecursive(hHostKey, hSandboxKey);
    
    RegCloseKey(hHostKey);
    RegCloseKey(hSandboxKey);
    
    if (success) {
        Logger::Info("Registry key copied successfully from host to sandbox");
    } else {
        Logger::Error("Failed to copy registry key from host to sandbox");
    }
    
    return success;
}

bool RegistryIsolation::CopyRegistryKeyFromSandbox(const std::wstring& sandboxKey, const std::wstring& hostKey) {
    Logger::Info("Copying registry key from sandbox to host: %ls -> %ls", 
        sandboxKey.c_str(), hostKey.c_str());
    
    // 获取沙箱中的实际键路径
    std::wstring redirectedKey;
    std::wstring sourceKey = sandboxKey;
    
    if (ShouldRedirectKey(sandboxKey, redirectedKey)) {
        sourceKey = redirectedKey;
    }
    
    // 解析源键路径
    std::wstring sandboxSubKey;
    HKEY hSandboxRoot = GetRootKeyFromPath(sourceKey, sandboxSubKey);
    if (hSandboxRoot == NULL) {
        Logger::Error("Invalid sandbox key path: %ls", sourceKey.c_str());
        return false;
    }
    
    // 打开源键
    HKEY hSandboxKey;
    LONG result = RegOpenKeyExW(hSandboxRoot, sandboxSubKey.c_str(), 0, KEY_READ, &hSandboxKey);
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to open sandbox key: %ls, error: %d", sourceKey.c_str(), result);
        return false;
    }
    
    // 解析目标键路径
    std::wstring hostSubKey;
    HKEY hHostRoot = GetRootKeyFromPath(hostKey, hostSubKey);
    if (hHostRoot == NULL) {
        RegCloseKey(hSandboxKey);
        Logger::Error("Invalid host key path: %ls", hostKey.c_str());
        return false;
    }
    
    // 创建目标键
    HKEY hHostKey;
    result = RegCreateKeyExW(hHostRoot, hostSubKey.c_str(), 0, NULL, 
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hHostKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        RegCloseKey(hSandboxKey);
        Logger::Error("Failed to create host key: %ls, error: %d", hostKey.c_str(), result);
        return false;
    }
    
    // 复制键值
    bool success = CopyRegistryKeyRecursive(hSandboxKey, hHostKey);
    
    RegCloseKey(hSandboxKey);
    RegCloseKey(hHostKey);
    
    if (success) {
        Logger::Info("Registry key copied successfully from sandbox to host");
    } else {
        Logger::Error("Failed to copy registry key from sandbox to host");
    }
    
    return success;
}

std::vector<std::wstring> RegistryIsolation::GetRegistryOperationLogs(FILETIME startTime, FILETIME endTime) {
    std::vector<std::wstring> result;
    
    std::lock_guard<std::mutex> lock(g_LogsMutex);
    
    for (const auto& entry : g_RegistryOperationLogs) {
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
                entry.operation + L": " + entry.keyPath;
            
            if (!entry.redirectedKeyPath.empty()) {
                logEntry += L" -> " + entry.redirectedKeyPath;
            }
            
            if (entry.result != 0) {
                logEntry += L" (Error: " + std::to_wstring(entry.result) + L")";
            }
            
            result.push_back(logEntry);
        }
    }
    
    return result;
}

bool RegistryIsolation::ProtectSystemKeys() {
    Logger::Info("Setting up protection for system registry keys");
    
    // 添加关键系统注册表键的保护规则
    std::lock_guard<std::mutex> lock(g_RulesMutex);
    
    // 保护启动项
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*", 
        RegistryAccessRuleType::ReadOnly));
    
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce*", 
        RegistryAccessRuleType::ReadOnly));
    
    // 保护服务配置
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\*", 
        RegistryAccessRuleType::ReadOnly));
    
    // 保护安全策略
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\*", 
        RegistryAccessRuleType::ReadOnly));
    
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\*", 
        RegistryAccessRuleType::ReadOnly));
    
    // 保护驱动程序加载
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\*", 
        RegistryAccessRuleType::ReadOnly));
    
    // 保护文件关联
    g_RegistryAccessRules.push_back(RegistryAccessRule(
        L"HKEY_CLASSES_ROOT\\*", 
        RegistryAccessRuleType::ReadOnly));
    
    Logger::Info("System registry keys protection set up successfully");
    return true;
}

// 初始化注册表
static bool InitializeRegistry() {
    // 创建虚拟注册表根键
    std::wstring rootKeyPath = L"SOFTWARE\\LightSandbox\\Sandbox" + std::to_wstring(g_Config.sandboxId);
    
    HKEY hRootKey;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, rootKeyPath.c_str(), 0, NULL, 
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hRootKey, NULL);
    
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to create virtual registry root key, error: %d", result);
        return false;
    }
    
    RegCloseKey(hRootKey);
    
    // 创建快照目录
    std::wstring snapshotsDir = g_Config.virtualRegistryPath + L"\\Snapshots";
    std::error_code ec;
    std::filesystem::create_directories(snapshotsDir, ec);
    if (ec) {
        Logger::Error("Failed to create snapshots directory: %ls, error: %s", 
            snapshotsDir.c_str(), ec.message().c_str());
        return false;
    }
    
    // 加载现有快照信息
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
            Logger::Info("Loaded existing registry snapshot: %ls", snapshot.name.c_str());
        }
    }
    
    return true;
}

// 递归创建注册表键
static bool CreateRegistryKeyRecursive(HKEY hRootKey, const std::wstring& keyPath) {
    // 空路径，直接返回成功
    if (keyPath.empty()) {
        return true;
    }
    
    // 查找第一个反斜杠
    size_t pos = keyPath.find_first_of(L'\\');
    
    if (pos == std::wstring::npos) {
        // 没有反斜杠，直接创建键
        HKEY hKey;
        LONG result = RegCreateKeyExW(hRootKey, keyPath.c_str(), 0, NULL, 
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        
        if (result != ERROR_SUCCESS) {
            Logger::Error("Failed to create registry key: %ls, error: %d", keyPath.c_str(), result);
            return false;
        }
        
        RegCloseKey(hKey);
        return true;
    } else {
        // 有反斜杠，递归创建
        std::wstring subKey = keyPath.substr(0, pos);
        std::wstring remainingPath = keyPath.substr(pos + 1);
        
        HKEY hSubKey;
        LONG result = RegCreateKeyExW(hRootKey, subKey.c_str(), 0, NULL, 
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKey, NULL);
        
        if (result != ERROR_SUCCESS) {
            Logger::Error("Failed to create registry key: %ls, error: %d", subKey.c_str(), result);
            return false;
        }
        
        bool success = CreateRegistryKeyRecursive(hSubKey, remainingPath);
        RegCloseKey(hSubKey);
        return success;
    }
}

// 检查键路径是否匹配模式
static bool KeyMatchesPattern(const std::wstring& keyPath, const std::wstring& pattern) {
    // 使用Windows API进行通配符匹配
    return PathMatchSpecW(keyPath.c_str(), pattern.c_str()) == TRUE;
}

// 记录注册表操作
static void LogRegistryOperation(const std::wstring& operation, const std::wstring& keyPath, 
                               const std::wstring& redirectedKeyPath, DWORD result) {
    RegistryOperationLogEntry entry;
    GetSystemTimeAsFileTime(&entry.timestamp);
    entry.operation = operation;
    entry.keyPath = keyPath;
    entry.redirectedKeyPath = redirectedKeyPath;
    entry.processId = GetCurrentProcessId();
    entry.result = result;
    
    std::lock_guard<std::mutex> lock(g_LogsMutex);
    g_RegistryOperationLogs.push_back(entry);
    
    // 限制日志大小
    const size_t MAX_LOG_ENTRIES = 10000;
    if (g_RegistryOperationLogs.size() > MAX_LOG_ENTRIES) {
        g_RegistryOperationLogs.erase(g_RegistryOperationLogs.begin(), 
            g_RegistryOperationLogs.begin() + (g_RegistryOperationLogs.size() - MAX_LOG_ENTRIES));
    }
}

// 获取重定向键路径
static std::wstring GetRedirectedKeyPath(const std::wstring& originalKeyPath) {
    // 解析原始键路径
    std::wstring subKeyPath;
    HKEY hRootKey = GetRootKeyFromPath(originalKeyPath, subKeyPath);
    
    if (hRootKey == NULL) {
        Logger::Error("Invalid registry key path: %ls", originalKeyPath.c_str());
        return originalKeyPath;
    }
    
    // 构建重定向键路径
    std::wstring rootName;
    
    if (hRootKey == HKEY_LOCAL_MACHINE) {
        rootName = L"HKLM";
    } else if (hRootKey == HKEY_CURRENT_USER) {
        rootName = L"HKCU";
    } else if (hRootKey == HKEY_CLASSES_ROOT) {
        rootName = L"HKCR";
    } else if (hRootKey == HKEY_USERS) {
        rootName = L"HKU";
    } else if (hRootKey == HKEY_CURRENT_CONFIG) {
        rootName = L"HKCC";
    } else {
        rootName = L"UNKNOWN";
    }
    
    std::wstring redirectedPath = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\LightSandbox\\Sandbox" + 
                                 std::to_wstring(g_Config.sandboxId) + L"\\" + 
                                 rootName + L"\\" + subKeyPath;
    
    return redirectedPath;
}

// 递归复制注册表键
static bool CopyRegistryKeyRecursive(HKEY hSourceKey, HKEY hDestKey) {
    // 复制所有值
    DWORD maxValueNameLength, maxValueDataLength;
    DWORD valueCount;
    
    LONG result = RegQueryInfoKeyW(hSourceKey, NULL, NULL, NULL, NULL, NULL, NULL,
        &valueCount, &maxValueNameLength, &maxValueDataLength, NULL, NULL);
    
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to query source key info, error: %d", result);
        return false;
    }
    
    // 分配缓冲区
    std::vector<wchar_t> valueName(maxValueNameLength + 1);
    std::vector<BYTE> valueData(maxValueDataLength);
    
    // 复制所有值
    for (DWORD i = 0; i < valueCount; i++) {
        DWORD valueNameLength = maxValueNameLength + 1;
        DWORD valueDataLength = maxValueDataLength;
        DWORD valueType;
        
        result = RegEnumValueW(hSourceKey, i, valueName.data(), &valueNameLength, NULL,
            &valueType, valueData.data(), &valueDataLength);
        
        if (result != ERROR_SUCCESS) {
            Logger::Warning("Failed to enumerate value %d, error: %d", i, result);
            continue;
        }
        
        result = RegSetValueExW(hDestKey, valueName.data(), 0, valueType,
            valueData.data(), valueDataLength);
        
        if (result != ERROR_SUCCESS) {
            Logger::Warning("Failed to set value %ls, error: %d", valueName.data(), result);
        }
    }
    
    // 递归复制所有子键
    DWORD maxSubKeyNameLength;
    DWORD subKeyCount;
    
    result = RegQueryInfoKeyW(hSourceKey, NULL, NULL, NULL, &subKeyCount,
        &maxSubKeyNameLength, NULL, NULL, NULL, NULL, NULL, NULL);
    
    if (result != ERROR_SUCCESS) {
        Logger::Error("Failed to query source key info for subkeys, error: %d", result);
        return false;
    }
    
    // 分配缓冲区
    std::vector<wchar_t> subKeyName(maxSubKeyNameLength + 1);
    
    // 复制所有子键
    for (DWORD i = 0; i < subKeyCount; i++) {
        DWORD subKeyNameLength = maxSubKeyNameLength + 1;
        
        result = RegEnumKeyExW(hSourceKey, i, subKeyName.data(), &subKeyNameLength,
            NULL, NULL, NULL, NULL);
        
        if (result != ERROR_SUCCESS) {
            Logger::Warning("Failed to enumerate subkey %d, error: %d", i, result);
            continue;
        }
        
        // 打开源子键
        HKEY hSourceSubKey;
        result = RegOpenKeyExW(hSourceKey, subKeyName.data(), 0, KEY_READ, &hSourceSubKey);
        
        if (result != ERROR_SUCCESS) {
            Logger::Warning("Failed to open source subkey %ls, error: %d", subKeyName.data(), result);
            continue;
        }
        
        // 创建目标子键
        HKEY hDestSubKey;
        result = RegCreateKeyExW(hDestKey, subKeyName.data(), 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hDestSubKey, NULL);
        
        if (result != ERROR_SUCCESS) {
            RegCloseKey(hSourceSubKey);
            Logger::Warning("Failed to create destination subkey %ls, error: %d", subKeyName.data(), result);
            continue;
        }
        
        // 递归复制子键
        CopyRegistryKeyRecursive(hSourceSubKey, hDestSubKey);
        
        RegCloseKey(hSourceSubKey);
        RegCloseKey(hDestSubKey);
    }
    
    return true;
}

// 从路径获取根键句柄
static HKEY GetRootKeyFromPath(const std::wstring& keyPath, std::wstring& subKeyPath) {
    // 检查路径是否以根键名称开头
    if (keyPath.compare(0, 5, L"HKEY_") == 0) {
        size_t pos = keyPath.find_first_of(L'\\');
        
        if (pos != std::wstring::npos) {
            std::wstring rootName = keyPath.substr(0, pos);
            subKeyPath = keyPath.substr(pos + 1);
            
            if (rootName == L"HKEY_LOCAL_MACHINE" || rootName == L"HKLM") {
                return HKEY_LOCAL_MACHINE;
            } else if (rootName == L"HKEY_CURRENT_USER" || rootName == L"HKCU") {
                return HKEY_CURRENT_USER;
            } else if (rootName == L"HKEY_CLASSES_ROOT" || rootName == L"HKCR") {
                return HKEY_CLASSES_ROOT;
            } else if (rootName == L"HKEY_USERS" || rootName == L"HKU") {
                return HKEY_USERS;
            } else if (rootName == L"HKEY_CURRENT_CONFIG" || rootName == L"HKCC") {
                return HKEY_CURRENT_CONFIG;
            }
        } else {
            // 只有根键名称，没有子键
            subKeyPath = L"";
            
            if (keyPath == L"HKEY_LOCAL_MACHINE" || keyPath == L"HKLM") {
                return HKEY_LOCAL_MACHINE;
            } else if (keyPath == L"HKEY_CURRENT_USER" || keyPath == L"HKCU") {
                return HKEY_CURRENT_USER;
            } else if (keyPath == L"HKEY_CLASSES_ROOT" || keyPath == L"HKCR") {
                return HKEY_CLASSES_ROOT;
            } else if (keyPath == L"HKEY_USERS" || keyPath == L"HKU") {
                return HKEY_USERS;
            } else if (keyPath == L"HKEY_CURRENT_CONFIG" || keyPath == L"HKCC") {
                return HKEY_CURRENT_CONFIG;
            }
        }
    }
    
    return NULL;
}

// 获取完整键路径
static std::wstring GetFullKeyPath(HKEY hKey, const std::wstring& subKeyPath) {
    std::wstring rootName;
    
    if (hKey == HKEY_LOCAL_MACHINE) {
        rootName = L"HKEY_LOCAL_MACHINE";
    } else if (hKey == HKEY_CURRENT_USER) {
        rootName = L"HKEY_CURRENT_USER";
    } else if (hKey == HKEY_CLASSES_ROOT) {
        rootName = L"HKEY_CLASSES_ROOT";
    } else if (hKey == HKEY_USERS) {
        rootName = L"HKEY_USERS";
    } else if (hKey == HKEY_CURRENT_CONFIG) {
        rootName = L"HKEY_CURRENT_CONFIG";
    } else {
        rootName = L"UNKNOWN";
    }
    
    if (subKeyPath.empty()) {
        return rootName;
    } else {
        return rootName + L"\\" + subKeyPath;
    }
}

} // namespace LightSandbox
