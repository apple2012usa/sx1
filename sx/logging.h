/**
 * @file logging.h
 * @brief 日志记录模块头文件
 * 
 * 该文件定义了Windows轻量级沙箱的日志记录模块接口，
 * 负责记录系统运行时的各种日志信息。
 */

#pragma once

#include <Windows.h>
#include <string>

namespace LightSandbox {

/**
 * @brief 日志级别
 */
enum class LogLevel {
    Debug,    ///< 调试信息
    Info,     ///< 一般信息
    Warning,  ///< 警告信息
    Error,    ///< 错误信息
    Fatal     ///< 致命错误
};

/**
 * @brief 日志配置
 */
struct LoggingConfig {
    bool enableConsoleOutput;     ///< 是否输出到控制台
    bool enableFileOutput;        ///< 是否输出到文件
    bool enableDebugOutput;       ///< 是否输出到调试器
    LogLevel minLevel;            ///< 最低日志级别
    std::wstring logFilePath;     ///< 日志文件路径
    size_t maxFileSize;           ///< 最大日志文件大小（字节）
    int maxBackupFiles;           ///< 最大备份文件数量
    
    LoggingConfig() 
        : enableConsoleOutput(true), enableFileOutput(true), enableDebugOutput(true),
          minLevel(LogLevel::Info), maxFileSize(10 * 1024 * 1024), maxBackupFiles(5) {}
};

/**
 * @brief 日志记录模块
 */
class Logger {
public:
    /**
     * @brief 初始化日志记录模块
     * @param config 日志配置
     * @return 是否成功初始化
     */
    static bool Initialize(const LoggingConfig& config);
    
    /**
     * @brief 清理日志记录模块
     */
    static void Cleanup();
    
    /**
     * @brief 记录调试信息
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    static void Debug(const char* format, ...);
    
    /**
     * @brief 记录一般信息
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    static void Info(const char* format, ...);
    
    /**
     * @brief 记录警告信息
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    static void Warning(const char* format, ...);
    
    /**
     * @brief 记录错误信息
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    static void Error(const char* format, ...);
    
    /**
     * @brief 记录致命错误
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    static void Fatal(const char* format, ...);
    
    /**
     * @brief 记录日志
     * @param level 日志级别
     * @param format 格式化字符串
     * @param ... 可变参数
     */
    static void Log(LogLevel level, const char* format, ...);
    
    /**
     * @brief 设置日志级别
     * @param level 日志级别
     */
    static void SetLogLevel(LogLevel level);
    
    /**
     * @brief 获取日志级别
     * @return 日志级别
     */
    static LogLevel GetLogLevel();
    
    /**
     * @brief 启用/禁用控制台输出
     * @param enable 是否启用
     */
    static void EnableConsoleOutput(bool enable);
    
    /**
     * @brief 启用/禁用文件输出
     * @param enable 是否启用
     */
    static void EnableFileOutput(bool enable);
    
    /**
     * @brief 启用/禁用调试器输出
     * @param enable 是否启用
     */
    static void EnableDebugOutput(bool enable);
    
    /**
     * @brief 设置日志文件路径
     * @param filePath 文件路径
     */
    static void SetLogFilePath(const std::wstring& filePath);
};

} // namespace LightSandbox
