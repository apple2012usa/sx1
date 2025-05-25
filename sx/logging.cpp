/**
 * @file logging.cpp
 * @brief 日志记录模块实现
 * 
 * 该文件实现了Windows轻量级沙箱的日志记录模块，
 * 负责记录系统运行时的各种日志信息。
 */

#include "logging.h"
#include <mutex>
#include <fstream>
#include <cstdarg>
#include <ctime>
#include <filesystem>
#include <iostream>

namespace LightSandbox {

// 日志配置
static LoggingConfig g_LogConfig;

// 日志文件
static std::wofstream g_LogFile;

// 日志互斥锁
static std::mutex g_LogMutex;

// 日志级别名称
static const char* g_LogLevelNames[] = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "FATAL"
};

// 格式化日志消息
static std::string FormatLogMessage(LogLevel level, const char* format, va_list args) {
    // 获取当前时间
    time_t now = time(nullptr);
    tm localTime;
    localtime_s(&localTime, &now);
    
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTime);
    
    // 格式化日志级别和时间
    char prefix[64];
    sprintf_s(prefix, "[%s] [%s] ", g_LogLevelNames[static_cast<int>(level)], timeStr);
    
    // 格式化消息
    char msgBuf[1024];
    vsnprintf_s(msgBuf, sizeof(msgBuf), format, args);
    
    // 组合完整日志消息
    return std::string(prefix) + msgBuf;
}

// 写入日志到文件
static void WriteToFile(const std::string& message) {
    if (!g_LogConfig.enableFileOutput || g_LogConfig.logFilePath.empty()) {
        return;
    }
    
    // 检查日志文件是否打开
    if (!g_LogFile.is_open()) {
        g_LogFile.open(g_LogConfig.logFilePath, std::ios::app);
        if (!g_LogFile.is_open()) {
            return;
        }
    }
    
    // 检查文件大小
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(g_LogConfig.logFilePath, ec);
    if (!ec && fileSize > g_LogConfig.maxFileSize) {
        // 关闭当前日志文件
        g_LogFile.close();
        
        // 备份日志文件
        for (int i = g_LogConfig.maxBackupFiles; i > 0; i--) {
            std::wstring oldName = g_LogConfig.logFilePath + L"." + std::to_wstring(i);
            std::wstring newName = g_LogConfig.logFilePath + L"." + std::to_wstring(i + 1);
            
            if (i == g_LogConfig.maxBackupFiles) {
                std::filesystem::remove(newName, ec);
            }
            
            std::filesystem::rename(oldName, newName, ec);
        }
        
        std::filesystem::rename(g_LogConfig.logFilePath, g_LogConfig.logFilePath + L".1", ec);
        
        // 重新打开日志文件
        g_LogFile.open(g_LogConfig.logFilePath, std::ios::app);
        if (!g_LogFile.is_open()) {
            return;
        }
    }
    
    // 写入日志
    g_LogFile << message.c_str() << std::endl;
    g_LogFile.flush();
}

// 写入日志到控制台
static void WriteToConsole(const std::string& message) {
    if (!g_LogConfig.enableConsoleOutput) {
        return;
    }
    
    std::cout << message << std::endl;
}

// 写入日志到调试器
static void WriteToDebugger(const std::string& message) {
    if (!g_LogConfig.enableDebugOutput) {
        return;
    }
    
    OutputDebugStringA(message.c_str());
    OutputDebugStringA("\n");
}

bool Logger::Initialize(const LoggingConfig& config) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    g_LogConfig = config;
    
    // 确保日志目录存在
    if (g_LogConfig.enableFileOutput && !g_LogConfig.logFilePath.empty()) {
        std::wstring directory = g_LogConfig.logFilePath.substr(0, g_LogConfig.logFilePath.find_last_of(L'\\'));
        std::error_code ec;
        std::filesystem::create_directories(directory, ec);
        
        // 打开日志文件
        g_LogFile.open(g_LogConfig.logFilePath, std::ios::app);
        if (!g_LogFile.is_open()) {
            return false;
        }
    }
    
    Info("Logging system initialized");
    return true;
}

void Logger::Cleanup() {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    if (g_LogFile.is_open()) {
        g_LogFile.close();
    }
}

void Logger::Debug(const char* format, ...) {
    if (g_LogConfig.minLevel > LogLevel::Debug) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    Log(LogLevel::Debug, format, args);
    va_end(args);
}

void Logger::Info(const char* format, ...) {
    if (g_LogConfig.minLevel > LogLevel::Info) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    Log(LogLevel::Info, format, args);
    va_end(args);
}

void Logger::Warning(const char* format, ...) {
    if (g_LogConfig.minLevel > LogLevel::Warning) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    Log(LogLevel::Warning, format, args);
    va_end(args);
}

void Logger::Error(const char* format, ...) {
    if (g_LogConfig.minLevel > LogLevel::Error) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    Log(LogLevel::Error, format, args);
    va_end(args);
}

void Logger::Fatal(const char* format, ...) {
    if (g_LogConfig.minLevel > LogLevel::Fatal) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    Log(LogLevel::Fatal, format, args);
    va_end(args);
}

void Logger::Log(LogLevel level, const char* format, ...) {
    if (level < g_LogConfig.minLevel) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    std::string message = FormatLogMessage(level, format, args);
    va_end(args);
    
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    WriteToFile(message);
    WriteToConsole(message);
    WriteToDebugger(message);
}

void Logger::SetLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogConfig.minLevel = level;
}

LogLevel Logger::GetLogLevel() {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    return g_LogConfig.minLevel;
}

void Logger::EnableConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogConfig.enableConsoleOutput = enable;
}

void Logger::EnableFileOutput(bool enable) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogConfig.enableFileOutput = enable;
}

void Logger::EnableDebugOutput(bool enable) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogConfig.enableDebugOutput = enable;
}

void Logger::SetLogFilePath(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    
    if (g_LogFile.is_open()) {
        g_LogFile.close();
    }
    
    g_LogConfig.logFilePath = filePath;
    
    if (g_LogConfig.enableFileOutput && !g_LogConfig.logFilePath.empty()) {
        std::wstring directory = g_LogConfig.logFilePath.substr(0, g_LogConfig.logFilePath.find_last_of(L'\\'));
        std::error_code ec;
        std::filesystem::create_directories(directory, ec);
        
        g_LogFile.open(g_LogConfig.logFilePath, std::ios::app);
    }
}

} // namespace LightSandbox
