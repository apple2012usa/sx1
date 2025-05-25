/**
 * @file user_interface.cpp
 * @brief 用户界面模块实现
 * 
 * 该文件实现了Windows轻量级沙箱的用户界面模块，
 * 使用Win32 API创建和管理图形界面。
 */

#include "user_interface.h"
#include "logging.h"
#include <CommCtrl.h>
#include <windowsx.h>
#include <vector>
#include <map>
#include <thread>

#pragma comment(lib, "Comctl32.lib")

namespace LightSandbox {

// 控件ID
#define IDC_MAIN_LISTVIEW_SANDBOXES 1001
#define IDC_MAIN_LISTVIEW_APPS      1002
#define IDC_MAIN_BUTTON_START       1003
#define IDC_MAIN_BUTTON_STOP        1004
#define IDC_MAIN_BUTTON_CREATE      1005
#define IDC_MAIN_BUTTON_DELETE      1006
#define IDC_MAIN_BUTTON_LAUNCH      1007
#define IDC_MAIN_BUTTON_SETTINGS    1008
#define IDC_MAIN_TEXT_LOGS          1009
#define IDC_MAIN_STATUSBAR          1010
#define IDC_TRAY_ICON               1011

// 托盘图标消息
#define WM_TRAYICON (WM_USER + 1)

// 全局变量
static HWND g_hMainWnd = NULL;
static HWND g_hListViewSandboxes = NULL;
static HWND g_hListViewApps = NULL;
static HWND g_hLogEdit = NULL;
static HWND g_hStatusBar = NULL;
static HINSTANCE g_hInstance = NULL;
static UserInterfaceConfig g_UIConfig;
static NOTIFYICONDATAW g_nid;
static bool g_isMinimizedToTray = false;

// 回调函数
static std::function<bool(DWORD)> g_SandboxStartCallback;
static std::function<bool(DWORD)> g_SandboxStopCallback;
static std::function<bool(const SandboxInfo&)> g_SandboxCreateCallback;
static std::function<bool(DWORD)> g_SandboxDeleteCallback;
static std::function<bool(DWORD, const std::wstring&)> g_ApplicationLaunchCallback;
static std::function<bool(DWORD, const std::wstring&)> g_SnapshotCreateCallback;
static std::function<bool(DWORD, const std::wstring&)> g_SnapshotRestoreCallback;
static std::function<bool(DWORD, const std::wstring&)> g_SnapshotDeleteCallback;
static std::function<bool(const UserInterfaceConfig&)> g_SettingsSaveCallback;

// 窗口过程
static LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

// UI实现类（Pimpl模式）
class UIImplementation {
public:
    UIImplementation() = default;
    ~UIImplementation() = default;
    
    bool Initialize(const UserInterfaceConfig& config, HINSTANCE hInstance);
    bool Show();
    bool Hide();
    int Run();
    void Exit();
    void ShowNotification(const std::wstring& title, const std::wstring& message, int type);
    void UpdateSandboxList(const std::vector<SandboxInfo>& sandboxes);
    void UpdateApplicationList(const std::vector<ApplicationInfo>& applications);
    void UpdateResourceUsage(int memoryUsage, int cpuUsage);
    void UpdateLogs(const std::vector<std::wstring>& logs);
    
    // 设置回调
    void SetSandboxStartCallback(std::function<bool(DWORD)> callback) { g_SandboxStartCallback = callback; }
    void SetSandboxStopCallback(std::function<bool(DWORD)> callback) { g_SandboxStopCallback = callback; }
    void SetSandboxCreateCallback(std::function<bool(const SandboxInfo&)> callback) { g_SandboxCreateCallback = callback; }
    void SetSandboxDeleteCallback(std::function<bool(DWORD)> callback) { g_SandboxDeleteCallback = callback; }
    void SetApplicationLaunchCallback(std::function<bool(DWORD, const std::wstring&)> callback) { g_ApplicationLaunchCallback = callback; }
    void SetSnapshotCreateCallback(std::function<bool(DWORD, const std::wstring&)> callback) { g_SnapshotCreateCallback = callback; }
    void SetSnapshotRestoreCallback(std::function<bool(DWORD, const std::wstring&)> callback) { g_SnapshotRestoreCallback = callback; }
    void SetSnapshotDeleteCallback(std::function<bool(DWORD, const std::wstring&)> callback) { g_SnapshotDeleteCallback = callback; }
    void SetSettingsSaveCallback(std::function<bool(const UserInterfaceConfig&)> callback) { g_SettingsSaveCallback = callback; }
    
private:
    bool CreateMainWindow();
    bool CreateControls(HWND hWndParent);
    bool CreateTrayIcon(HWND hWndParent);
    void RemoveTrayIcon();
    void UpdateStatusBar(const std::wstring& text1, const std::wstring& text2);
    void AppendLog(const std::wstring& log);
    DWORD GetSelectedSandboxId();
    std::wstring GetSelectedApplicationPath();
};

// UserInterface 类实现
UserInterface::UserInterface() : m_pImpl(std::make_unique<UIImplementation>()) {}

UserInterface::~UserInterface() {
    // 清理托盘图标
    if (g_UIConfig.showTrayIcon) {
        m_pImpl->RemoveTrayIcon();
    }
}

bool UserInterface::Initialize(const UserInterfaceConfig& config, HINSTANCE hInstance) {
    return m_pImpl->Initialize(config, hInstance);
}

bool UserInterface::Show() {
    return m_pImpl->Show();
}

bool UserInterface::Hide() {
    return m_pImpl->Hide();
}

int UserInterface::Run() {
    return m_pImpl->Run();
}

void UserInterface::Exit() {
    m_pImpl->Exit();
}

void UserInterface::ShowNotification(const std::wstring& title, const std::wstring& message, int type) {
    m_pImpl->ShowNotification(title, message, type);
}

void UserInterface::UpdateSandboxList(const std::vector<SandboxInfo>& sandboxes) {
    m_pImpl->UpdateSandboxList(sandboxes);
}

void UserInterface::UpdateApplicationList(const std::vector<ApplicationInfo>& applications) {
    m_pImpl->UpdateApplicationList(applications);
}

void UserInterface::UpdateResourceUsage(int memoryUsage, int cpuUsage) {
    m_pImpl->UpdateResourceUsage(memoryUsage, cpuUsage);
}

void UserInterface::UpdateLogs(const std::vector<std::wstring>& logs) {
    m_pImpl->UpdateLogs(logs);
}

void UserInterface::SetSandboxStartCallback(std::function<bool(DWORD)> callback) {
    m_pImpl->SetSandboxStartCallback(callback);
}

void UserInterface::SetSandboxStopCallback(std::function<bool(DWORD)> callback) {
    m_pImpl->SetSandboxStopCallback(callback);
}

void UserInterface::SetSandboxCreateCallback(std::function<bool(const SandboxInfo&)> callback) {
    m_pImpl->SetSandboxCreateCallback(callback);
}

void UserInterface::SetSandboxDeleteCallback(std::function<bool(DWORD)> callback) {
    m_pImpl->SetSandboxDeleteCallback(callback);
}

void UserInterface::SetApplicationLaunchCallback(std::function<bool(DWORD, const std::wstring&)> callback) {
    m_pImpl->SetApplicationLaunchCallback(callback);
}

void UserInterface::SetSnapshotCreateCallback(std::function<bool(DWORD, const std::wstring&)> callback) {
    m_pImpl->SetSnapshotCreateCallback(callback);
}

void UserInterface::SetSnapshotRestoreCallback(std::function<bool(DWORD, const std::wstring&)> callback) {
    m_pImpl->SetSnapshotRestoreCallback(callback);
}

void UserInterface::SetSnapshotDeleteCallback(std::function<bool(DWORD, const std::wstring&)> callback) {
    m_pImpl->SetSnapshotDeleteCallback(callback);
}

void UserInterface::SetSettingsSaveCallback(std::function<bool(const UserInterfaceConfig&)> callback) {
    m_pImpl->SetSettingsSaveCallback(callback);
}

// UIImplementation 类实现
bool UIImplementation::Initialize(const UserInterfaceConfig& config, HINSTANCE hInstance) {
    Logger::Info("Initializing UserInterface module");
    g_UIConfig = config;
    g_hInstance = hInstance;
    
    // 初始化通用控件
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    if (!InitCommonControlsEx(&icex)) {
        Logger::Error("Failed to initialize common controls");
        return false;
    }
    
    // 创建主窗口
    if (!CreateMainWindow()) {
        return false;
    }
    
    // 创建托盘图标
    if (g_UIConfig.showTrayIcon) {
        if (!CreateTrayIcon(g_hMainWnd)) {
            Logger::Warning("Failed to create tray icon");
        }
    }
    
    Logger::Info("UserInterface initialized successfully");
    return true;
}

bool UIImplementation::Show() {
    if (g_hMainWnd) {
        ShowWindow(g_hMainWnd, SW_SHOW);
        UpdateWindow(g_hMainWnd);
        g_isMinimizedToTray = false;
        return true;
    }
    return false;
}

bool UIImplementation::Hide() {
    if (g_hMainWnd) {
        ShowWindow(g_hMainWnd, SW_HIDE);
        return true;
    }
    return false;
}

int UIImplementation::Run() {
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

void UIImplementation::Exit() {
    PostQuitMessage(0);
}

void UIImplementation::ShowNotification(const std::wstring& title, const std::wstring& message, int type) {
    if (!g_UIConfig.showNotifications || !g_UIConfig.showTrayIcon || !g_nid.hWnd) {
        return;
    }
    
    g_nid.uFlags = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_INFO; // 默认信息图标
    if (type == 1) g_nid.dwInfoFlags = NIIF_WARNING;
    if (type == 2) g_nid.dwInfoFlags = NIIF_ERROR;
    
    wcsncpy_s(g_nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(g_nid.szInfo, message.c_str(), _TRUNCATE);
    g_nid.uTimeout = 5000; // 显示5秒
    
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

void UIImplementation::UpdateSandboxList(const std::vector<SandboxInfo>& sandboxes) {
    if (!g_hListViewSandboxes) return;
    
    // 清空列表
    ListView_DeleteAllItems(g_hListViewSandboxes);
    
    // 添加项目
    for (const auto& sandbox : sandboxes) {
        LVITEMW item = { 0 };
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = ListView_GetItemCount(g_hListViewSandboxes);
        item.lParam = (LPARAM)sandbox.sandboxId; // 将ID存储在lParam中
        
        // 添加名称
        item.pszText = const_cast<LPWSTR>(sandbox.name.c_str());
        item.iSubItem = 0;
        ListView_InsertItem(g_hListViewSandboxes, &item);
        
        // 添加状态
        std::wstring statusStr;
        switch (sandbox.status) {
            case SandboxStatus::NotRunning: statusStr = L"未运行"; break;
            case SandboxStatus::Starting:   statusStr = L"正在启动"; break;
            case SandboxStatus::Running:    statusStr = L"正在运行"; break;
            case SandboxStatus::Stopping:   statusStr = L"正在停止"; break;
            case SandboxStatus::Error:      statusStr = L"错误"; break;
        }
        ListView_SetItemText(g_hListViewSandboxes, item.iItem, 1, const_cast<LPWSTR>(statusStr.c_str()));
        
        // 添加描述
        ListView_SetItemText(g_hListViewSandboxes, item.iItem, 2, const_cast<LPWSTR>(sandbox.description.c_str()));
    }
}

void UIImplementation::UpdateApplicationList(const std::vector<ApplicationInfo>& applications) {
    if (!g_hListViewApps) return;
    
    // 清空列表
    ListView_DeleteAllItems(g_hListViewApps);
    
    // 添加项目
    for (const auto& app : applications) {
        LVITEMW item = { 0 };
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = ListView_GetItemCount(g_hListViewApps);
        item.lParam = (LPARAM)app.executablePath.c_str(); // 将路径存储在lParam中
        
        // 添加名称
        item.pszText = const_cast<LPWSTR>(app.name.c_str());
        item.iSubItem = 0;
        ListView_InsertItem(g_hListViewApps, &item);
        
        // 添加状态
        std::wstring statusStr = app.isInstalled ? L"已安装" : L"未安装";
        ListView_SetItemText(g_hListViewApps, item.iItem, 1, const_cast<LPWSTR>(statusStr.c_str()));
        
        // 添加描述
        ListView_SetItemText(g_hListViewApps, item.iItem, 2, const_cast<LPWSTR>(app.description.c_str()));
    }
}

void UIImplementation::UpdateResourceUsage(int memoryUsage, int cpuUsage) {
    if (!g_hStatusBar) return;
    
    std::wstring memText = L"内存: " + std::to_wstring(memoryUsage) + L"%";
    std::wstring cpuText = L"CPU: " + std::to_wstring(cpuUsage) + L"%";
    
    UpdateStatusBar(memText, cpuText);
}

void UIImplementation::UpdateLogs(const std::vector<std::wstring>& logs) {
    if (!g_hLogEdit) return;
    
    // 清空现有日志
    SetWindowTextW(g_hLogEdit, L"");
    
    // 添加新日志
    for (const auto& log : logs) {
        AppendLog(log);
    }
}

// 创建主窗口
bool UIImplementation::CreateMainWindow() {
    WNDCLASSEXW wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = MainWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = g_hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"LightSandboxMainWnd";
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wcex)) {
        Logger::Error("Failed to register window class, error: %d", GetLastError());
        return false;
    }
    
    g_hMainWnd = CreateWindowExW(
        0,
        L"LightSandboxMainWnd",
        L"LightSandbox 控制台",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL,
        NULL,
        g_hInstance,
        this // 将this指针传递给WM_CREATE
    );
    
    if (!g_hMainWnd) {
        Logger::Error("Failed to create main window, error: %d", GetLastError());
        return false;
    }
    
    return true;
}

// 创建控件
bool UIImplementation::CreateControls(HWND hWndParent) {
    // 创建沙箱列表视图
    g_hListViewSandboxes = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        10, 10, 380, 200, hWndParent,
        (HMENU)IDC_MAIN_LISTVIEW_SANDBOXES, g_hInstance, NULL);
    
    if (!g_hListViewSandboxes) return false;
    ListView_SetExtendedListViewStyle(g_hListViewSandboxes, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // 添加沙箱列表列
    LVCOLUMNW lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.cx = 120;
    lvc.pszText = L"名称";
    lvc.iSubItem = 0;
    ListView_InsertColumn(g_hListViewSandboxes, 0, &lvc);
    lvc.cx = 80;
    lvc.pszText = L"状态";
    lvc.iSubItem = 1;
    ListView_InsertColumn(g_hListViewSandboxes, 1, &lvc);
    lvc.cx = 160;
    lvc.pszText = L"描述";
    lvc.iSubItem = 2;
    ListView_InsertColumn(g_hListViewSandboxes, 2, &lvc);
    
    // 创建应用程序列表视图
    g_hListViewApps = CreateWindowExW(
        0, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        410, 10, 360, 200, hWndParent,
        (HMENU)IDC_MAIN_LISTVIEW_APPS, g_hInstance, NULL);
        
    if (!g_hListViewApps) return false;
    ListView_SetExtendedListViewStyle(g_hListViewApps, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // 添加应用程序列表列
    lvc.cx = 120;
    lvc.pszText = L"名称";
    lvc.iSubItem = 0;
    ListView_InsertColumn(g_hListViewApps, 0, &lvc);
    lvc.cx = 80;
    lvc.pszText = L"状态";
    lvc.iSubItem = 1;
    ListView_InsertColumn(g_hListViewApps, 1, &lvc);
    lvc.cx = 140;
    lvc.pszText = L"描述";
    lvc.iSubItem = 2;
    ListView_InsertColumn(g_hListViewApps, 2, &lvc);
    
    // 创建按钮
    CreateWindowW(L"BUTTON", L"启动", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 220, 80, 25, hWndParent, (HMENU)IDC_MAIN_BUTTON_START, g_hInstance, NULL);
    CreateWindowW(L"BUTTON", L"停止", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        100, 220, 80, 25, hWndParent, (HMENU)IDC_MAIN_BUTTON_STOP, g_hInstance, NULL);
    CreateWindowW(L"BUTTON", L"创建", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        190, 220, 80, 25, hWndParent, (HMENU)IDC_MAIN_BUTTON_CREATE, g_hInstance, NULL);
    CreateWindowW(L"BUTTON", L"删除", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        280, 220, 80, 25, hWndParent, (HMENU)IDC_MAIN_BUTTON_DELETE, g_hInstance, NULL);
    CreateWindowW(L"BUTTON", L"启动应用", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        410, 220, 100, 25, hWndParent, (HMENU)IDC_MAIN_BUTTON_LAUNCH, g_hInstance, NULL);
    CreateWindowW(L"BUTTON", L"设置", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        690, 220, 80, 25, hWndParent, (HMENU)IDC_MAIN_BUTTON_SETTINGS, g_hInstance, NULL);
        
    // 创建日志编辑框
    g_hLogEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        10, 260, 760, 250, hWndParent,
        (HMENU)IDC_MAIN_TEXT_LOGS, g_hInstance, NULL);
        
    // 创建状态栏
    g_hStatusBar = CreateWindowExW(
        0, STATUSCLASSNAMEW, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hWndParent,
        (HMENU)IDC_MAIN_STATUSBAR, g_hInstance, NULL);
        
    if (!g_hStatusBar) return false;
    int parts[] = { 150, 300, -1 }; // 状态栏分段
    SendMessage(g_hStatusBar, SB_SETPARTS, sizeof(parts) / sizeof(int), (LPARAM)parts);
    UpdateStatusBar(L"就绪", L"");
    
    return true;
}

// 创建托盘图标
bool UIImplementation::CreateTrayIcon(HWND hWndParent) {
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hWndParent;
    g_nid.uID = IDC_TRAY_ICON;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); // 使用默认图标，可以替换为自定义图标
    wcsncpy_s(g_nid.szTip, L"LightSandbox", _TRUNCATE);
    
    if (!Shell_NotifyIconW(NIM_ADD, &g_nid)) {
        Logger::Error("Failed to add tray icon, error: %d", GetLastError());
        return false;
    }
    
    return true;
}

// 移除托盘图标
void UIImplementation::RemoveTrayIcon() {
    if (g_nid.hWnd) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_nid.hWnd = NULL;
    }
}

// 更新状态栏
void UIImplementation::UpdateStatusBar(const std::wstring& text1, const std::wstring& text2) {
    if (g_hStatusBar) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)text1.c_str());
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 1, (LPARAM)text2.c_str());
    }
}

// 追加日志
void UIImplementation::AppendLog(const std::wstring& log) {
    if (!g_hLogEdit) return;
    
    int len = GetWindowTextLengthW(g_hLogEdit);
    SendMessageW(g_hLogEdit, EM_SETSEL, len, len);
    SendMessageW(g_hLogEdit, EM_REPLACESEL, FALSE, (LPARAM)(log + L"\r\n").c_str());
}

// 获取选中的沙箱ID
DWORD UIImplementation::GetSelectedSandboxId() {
    int selectedIndex = ListView_GetNextItem(g_hListViewSandboxes, -1, LVNI_SELECTED);
    if (selectedIndex != -1) {
        LVITEMW item = { 0 };
        item.mask = LVIF_PARAM;
        item.iItem = selectedIndex;
        if (ListView_GetItem(g_hListViewSandboxes, &item)) {
            return (DWORD)item.lParam;
        }
    }
    return 0; // 无效ID
}

// 获取选中的应用程序路径
std::wstring UIImplementation::GetSelectedApplicationPath() {
    int selectedIndex = ListView_GetNextItem(g_hListViewApps, -1, LVNI_SELECTED);
    if (selectedIndex != -1) {
        LVITEMW item = { 0 };
        item.mask = LVIF_PARAM;
        item.iItem = selectedIndex;
        if (ListView_GetItem(g_hListViewApps, &item)) {
            return (wchar_t*)item.lParam;
        }
    }
    return L""; // 空路径
}

// 主窗口过程
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            g_hMainWnd = hWnd;
            UIImplementation* pThis = (UIImplementation*)((CREATESTRUCT*)lParam)->lpCreateParams;
            SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
            if (!pThis->CreateControls(hWnd)) {
                MessageBoxW(hWnd, L"创建控件失败!", L"错误", MB_ICONERROR);
                return -1;
            }
            break;
        }
        
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            UIImplementation* pThis = (UIImplementation*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            if (!pThis) break;
            
            DWORD selectedSandboxId = pThis->GetSelectedSandboxId();
            std::wstring selectedAppPath = pThis->GetSelectedApplicationPath();
            
            switch (wmId) {
                case IDC_MAIN_BUTTON_START:
                    if (g_SandboxStartCallback && selectedSandboxId != 0) {
                        if (!g_SandboxStartCallback(selectedSandboxId)) {
                            MessageBoxW(hWnd, L"启动沙箱失败!", L"错误", MB_ICONERROR);
                        }
                    }
                    break;
                case IDC_MAIN_BUTTON_STOP:
                    if (g_SandboxStopCallback && selectedSandboxId != 0) {
                        if (!g_SandboxStopCallback(selectedSandboxId)) {
                            MessageBoxW(hWnd, L"停止沙箱失败!", L"错误", MB_ICONERROR);
                        }
                    }
                    break;
                case IDC_MAIN_BUTTON_CREATE:
                    // TODO: 显示创建沙箱对话框
                    if (g_SandboxCreateCallback) {
                        SandboxInfo newSandbox; // 从对话框获取信息
                        newSandbox.name = L"新沙箱";
                        newSandbox.description = L"这是一个新创建的沙箱";
                        if (!g_SandboxCreateCallback(newSandbox)) {
                            MessageBoxW(hWnd, L"创建沙箱失败!", L"错误", MB_ICONERROR);
                        }
                    }
                    break;
                case IDC_MAIN_BUTTON_DELETE:
                    if (g_SandboxDeleteCallback && selectedSandboxId != 0) {
                        if (MessageBoxW(hWnd, L"确定要删除选中的沙箱吗?", L"确认删除", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                            if (!g_SandboxDeleteCallback(selectedSandboxId)) {
                                MessageBoxW(hWnd, L"删除沙箱失败!", L"错误", MB_ICONERROR);
                            }
                        }
                    }
                    break;
                case IDC_MAIN_BUTTON_LAUNCH:
                    if (g_ApplicationLaunchCallback && selectedSandboxId != 0 && !selectedAppPath.empty()) {
                        if (!g_ApplicationLaunchCallback(selectedSandboxId, selectedAppPath)) {
                            MessageBoxW(hWnd, L"启动应用程序失败!", L"错误", MB_ICONERROR);
                        }
                    }
                    break;
                case IDC_MAIN_BUTTON_SETTINGS:
                    // TODO: 显示设置对话框
                    if (g_SettingsSaveCallback) {
                        UserInterfaceConfig currentConfig = g_UIConfig; // 从对话框获取新设置
                        if (!g_SettingsSaveCallback(currentConfig)) {
                            MessageBoxW(hWnd, L"保存设置失败!", L"错误", MB_ICONERROR);
                        }
                    }
                    break;
                default:
                    return DefWindowProc(hWnd, message, wParam, lParam);
            }
            break;
        }
        
        case WM_SIZE: {
            // 调整状态栏大小
            if (g_hStatusBar) {
                SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
            }
            // TODO: 调整其他控件大小
            break;
        }
        
        case WM_CLOSE: {
            if (g_UIConfig.minimizeToTray) {
                ShowWindow(hWnd, SW_HIDE);
                g_isMinimizedToTray = true;
            } else {
                DestroyWindow(hWnd);
            }
            break;
        }
        
        case WM_DESTROY: {
            UIImplementation* pThis = (UIImplementation*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            if (pThis) {
                pThis->Exit();
            }
            break;
        }
        
        case WM_TRAYICON: {
            UIImplementation* pThis = (UIImplementation*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
            if (!pThis) break;
            
            switch (LOWORD(lParam)) {
                case WM_LBUTTONDBLCLK: // 双击显示窗口
                    pThis->Show();
                    SetForegroundWindow(hWnd);
                    break;
                case WM_RBUTTONUP: { // 右键菜单
                    POINT pt;
                    GetCursorPos(&pt);
                    HMENU hMenu = CreatePopupMenu();
                    AppendMenuW(hMenu, MF_STRING, 1, L"显示控制台");
                    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
                    AppendMenuW(hMenu, MF_STRING, 2, L"退出");
                    
                    SetForegroundWindow(hWnd); // 确保菜单能正确消失
                    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hWnd, NULL);
                    DestroyMenu(hMenu);
                    
                    if (cmd == 1) { // 显示控制台
                        pThis->Show();
                        SetForegroundWindow(hWnd);
                    } else if (cmd == 2) { // 退出
                        DestroyWindow(hWnd);
                    }
                    break;
                }
            }
            break;
        }
        
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

} // namespace LightSandbox
