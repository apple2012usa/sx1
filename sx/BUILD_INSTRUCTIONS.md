# Windows 轻量级沙箱 - 编译与构建说明

## 系统要求

- Windows 10 或 Windows 11 操作系统
- Visual Studio 2019 或 Visual Studio 2022（推荐）
- Windows SDK 10.0.19041.0 或更高版本
- 管理员权限（运行时需要）

## 项目文件说明

本项目包含以下关键文件：

1. **LightSandbox.vcxproj** - Visual Studio 项目文件
2. **core_isolation_layer.cpp** - 核心隔离层实现
3. **resource_control.h/.cpp** - 资源控制模块
4. **filesystem_isolation.h/.cpp** - 文件系统隔离模块
5. **registry_isolation.h/.cpp** - 注册表保护模块
6. **daemon_guard.h/.cpp** - 守护进程模块
7. **user_interface.h/.cpp** - 用户界面模块
8. **logging.h/.cpp** - 日志记录模块
9. **main.cpp** - 程序入口点

## 编译步骤

### 1. 准备工作

1. 确保已安装 Visual Studio 2019 或 Visual Studio 2022
2. 确保已安装 Windows SDK（通过 Visual Studio 安装程序）
3. 确保已安装 C++ 桌面开发工作负载（通过 Visual Studio 安装程序）

### 2. 创建项目

#### 方法一：使用提供的项目文件

1. 打开 Visual Studio
2. 选择"文件" > "打开" > "项目/解决方案"
3. 导航到包含 `LightSandbox.vcxproj` 的文件夹并打开项目文件

#### 方法二：手动创建项目

1. 打开 Visual Studio
2. 创建新的 C++ Windows 桌面应用程序项目
3. 项目名称设置为 "LightSandbox"
4. 将所有源代码文件添加到项目中
5. 配置项目属性（见下文）

### 3. 配置项目属性

1. 右键点击解决方案资源管理器中的项目，选择"属性"
2. 确保以下设置正确：
   - 常规 > 配置类型：应用程序(.exe)
   - 常规 > 字符集：使用 Unicode 字符集
   - C/C++ > 预处理器 > 预处理器定义：添加 `_UNICODE;UNICODE;_CRT_SECURE_NO_WARNINGS`
   - 链接器 > 输入 > 附加依赖项：确保包含以下库：
     ```
     User32.lib
     Advapi32.lib
     Shell32.lib
     Comctl32.lib
     Shlwapi.lib
     ```
   - 链接器 > 系统 > 子系统：Windows (/SUBSYSTEM:WINDOWS)

### 4. 编译项目

1. 选择配置（Debug 或 Release）和平台（x86 或 x64）
2. 点击"生成" > "生成解决方案"（或按 F7）
3. 等待编译完成，检查输出窗口中是否有错误

### 5. 运行程序

1. 点击"调试" > "开始调试"（或按 F5）
2. 如果出现 UAC 提示，请允许程序以管理员权限运行

## 常见问题与解决方案

### 编译错误

1. **找不到头文件**
   - 确保所有源文件都在同一目录下
   - 检查项目属性 > C/C++ > 常规 > 附加包含目录

2. **链接错误**
   - 确保已添加所有必要的库（见上文）
   - 检查是否有函数声明与实现不匹配的情况

3. **字符集问题**
   - 确保项目使用 Unicode 字符集
   - 检查是否混用了 ANSI 和 Unicode 函数

### 运行错误

1. **权限不足**
   - 以管理员身份运行 Visual Studio
   - 右键点击生成的 EXE，选择"以管理员身份运行"

2. **缺少 DLL**
   - 确保目标系统安装了 Visual C++ 可再发行程序包
   - 考虑使用静态链接 (/MT 或 /MTd 编译选项)

3. **沙箱初始化失败**
   - 检查日志文件（默认位置：C:\ProgramData\LightSandbox\Logs\）
   - 确保程序有足够权限创建和访问必要的目录

## 自定义构建

### 修改资源限制

在 `main.cpp` 中找到 `InitializeModules()` 函数，修改以下参数：

```cpp
rcConfig.maxCpuUsage = 3; // CPU 使用率限制（百分比）
rcConfig.maxMemoryUsage = 5; // 内存使用率限制（百分比）
```

### 修改隔离路径

在 `main.cpp` 中找到 `InitializeModules()` 函数，修改以下参数：

```cpp
fsConfig.baseImagePath = L"C:\\ProgramData\\LightSandbox\\BaseImage";
fsConfig.differentialStoragePath = L"C:\\ProgramData\\LightSandbox\\Sandbox" + 
                                  std::to_wstring(g_SandboxId);
```

### 添加新功能

1. 在相应模块中添加新功能
2. 在 `main.cpp` 中更新初始化代码
3. 在用户界面中添加相应控件和回调函数

## 发布程序

### 创建发布版本

1. 将配置切换到"Release"
2. 选择目标平台（x86 或 x64）
3. 生成解决方案
4. 生成的 EXE 文件位于项目的 Release 或 x64\Release 目录中

### 创建安装程序（可选）

1. 添加新的"安装程序"项目到解决方案
2. 配置安装程序，包含以下文件：
   - LightSandbox.exe
   - 必要的配置文件
   - Visual C++ 可再发行程序包（如果需要）
3. 设置安装程序以请求管理员权限
4. 生成安装程序

## 注意事项

1. 该程序需要管理员权限才能正常运行
2. 首次运行时会在 C:\ProgramData\LightSandbox 目录下创建必要的文件和目录
3. 日志文件默认保存在 C:\ProgramData\LightSandbox\Logs 目录下
4. 如需调试，建议启用详细日志记录（在 `main.cpp` 中设置 `logConfig.minLevel = LogLevel::Debug;`）
