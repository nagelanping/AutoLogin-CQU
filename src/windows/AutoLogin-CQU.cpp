#define _WIN32_WINNT 0x0600
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <fstream>
#include <map>
#include <atomic>
#include <algorithm>
#include <limits>
#include <cstring>
#include <cctype>
#include <cstdlib>

#ifndef WINHTTP_OPTION_DISABLE_FEATURE
#define WINHTTP_OPTION_DISABLE_FEATURE 63
#endif

#ifndef WINHTTP_DISABLE_KEEP_ALIVE
#define WINHTTP_DISABLE_KEEP_ALIVE 0x00000008
#endif

// 编译指令: g++ <AutoLogin-CQU.cpp> -o <AutoLogin-CQU.exe> -lwinhttp -liphlpapi -lws2_32 -lshell32 -luser32 -static

using namespace std;

// ================= 配置常量 =================
const wstring LOGIN_HOST = L"login.cqu.edu.cn";
const string LOGIN_HOST_UTF8 = "login.cqu.edu.cn";
const int LOGIN_PORT = 802;
const wstring LOGIN_PATH_BASE = L"/eportal/portal/login";
const DWORD DEFAULT_CHECK_INTERVAL_SECONDS = 20;
const DWORD DEFAULT_TIMEOUT_SECONDS = 5;
const DWORD MAX_CHECK_INTERVAL_SECONDS = 86400;
const DWORD MAX_TIMEOUT_SECONDS = 300;
const size_t MAX_RESPONSE_BYTES = 4096;
const int CONFIG_ERROR_EXIT_CODE = 78;

// ================= 全局配置变量 =================
string USER_ACCOUNT;
string USER_PASSWORD;
string SERVER_IP; // 可选：直接指定服务器 IP，绕过 DNS 解析
string LOGIN_IP;  // 可选：指定用于认证的客户端 IPv4，适用于路由器接入场景
DWORD CHECK_INTERVAL_MS = DEFAULT_CHECK_INTERVAL_SECONDS * 1000;
DWORD TIMEOUT_MS = DEFAULT_TIMEOUT_SECONDS * 1000;

string Trim(const string &str)
{
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == string::npos)
        return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

string StripInlineComment(const string &value)
{
    bool inSingleQuote = false;
    bool inDoubleQuote = false;

    for (size_t i = 0; i < value.size(); ++i)
    {
        char c = value[i];
        if (c == '\'' && !inDoubleQuote)
            inSingleQuote = !inSingleQuote;
        else if (c == '"' && !inSingleQuote)
            inDoubleQuote = !inDoubleQuote;
        else if (c == '#' && !inSingleQuote && !inDoubleQuote)
            return value.substr(0, i);
    }

    return value;
}

string UnquoteYamlValue(const string &value)
{
    string result = Trim(StripInlineComment(value));
    if (result.size() >= 2)
    {
        char first = result.front();
        char last = result.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
            return result.substr(1, result.size() - 2);
    }
    return result;
}

bool IsSupportedConfigKey(const string &key)
{
    return key == "STUDENT_ID" || key == "USER_PASSWORD" ||
           key == "SERVER_IP" || key == "LOGIN_IP" ||
           key == "CHECK_INTERVAL" || key == "TIMEOUT";
}

bool LoadYamlConfig(const string &filename, map<string, string> &config)
{
    ifstream file(filename);
    if (!file.is_open())
        return false;

    string line;
    size_t lineNumber = 0;
    while (getline(file, line))
    {
        ++lineNumber;
        string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        size_t delimiter = trimmed.find(':');
        if (delimiter == string::npos)
        {
            cerr << "[错误] config.yaml 第 " << lineNumber << " 行缺少 ':'。" << endl;
            return false;
        }

        string key = Trim(trimmed.substr(0, delimiter));
        if (key.empty() || !IsSupportedConfigKey(key))
        {
            cerr << "[错误] config.yaml 第 " << lineNumber << " 行包含未知或空配置项。" << endl;
            return false;
        }
        if (config.find(key) != config.end())
        {
            cerr << "[错误] config.yaml 第 " << lineNumber << " 行重复配置项: " << key << endl;
            return false;
        }

        config[key] = UnquoteYamlValue(trimmed.substr(delimiter + 1));
    }

    return true;
}

bool TryGetConfigSeconds(const map<string, string> &config, const string &key, DWORD defaultValue, DWORD maxValue, DWORD &seconds)
{
    map<string, string>::const_iterator it = config.find(key);
    if (it == config.end() || it->second.empty())
    {
        seconds = defaultValue;
        return true;
    }

    try
    {
        size_t parsedLength = 0;
        unsigned long value = stoul(it->second, &parsedLength, 10);
        if (parsedLength != it->second.size() || value == 0 || value > maxValue)
            return false;
        seconds = static_cast<DWORD>(value);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool IsPlaceholderCredential(const string &value)
{
    return value == "xxxxxxxx" || value == "xxxxxx";
}

DWORD SecondsToMilliseconds(DWORD seconds)
{
    DWORD maxSeconds = numeric_limits<DWORD>::max() / 1000;
    return min(seconds, maxSeconds) * 1000;
}

bool IsValidIpAddress(const string &value, bool ipv4Only)
{
    IN_ADDR ipv4 = {0};
    if (InetPtonA(AF_INET, value.c_str(), &ipv4) == 1)
        return true;
    if (ipv4Only)
        return false;

    IN6_ADDR ipv6 = {0};
    return InetPtonA(AF_INET6, value.c_str(), &ipv6) == 1;
}

bool LoadConfig()
{
    char exePath[MAX_PATH];
    DWORD pathLength = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (pathLength == 0 || pathLength == MAX_PATH)
    {
        cerr << "[错误] 无法获取可执行文件路径" << endl;
        return false;
    }
    string path(exePath);
    string configPath = path.substr(0, path.find_last_of("\\/") + 1) + "config.yaml";

    map<string, string> config;
    if (!LoadYamlConfig(configPath, config))
    {
        cerr << "[错误] 无法读取 config.yaml，请检查配置文件。" << endl;
        cerr << "配置文件路径: " << configPath << endl;
        return false;
    }

    string studentId = config["STUDENT_ID"];
    USER_PASSWORD = config["USER_PASSWORD"];
    SERVER_IP = config["SERVER_IP"];
    LOGIN_IP = config["LOGIN_IP"];

    if (studentId.empty() || USER_PASSWORD.empty() ||
        IsPlaceholderCredential(studentId) || IsPlaceholderCredential(USER_PASSWORD))
    {
        cerr << "[错误] 未配置有效账号或密码，请更新 config.yaml。" << endl;
        cerr << "配置文件路径: " << configPath << endl;
        return false;
    }

    if (!SERVER_IP.empty() && !IsValidIpAddress(SERVER_IP, false))
    {
        cerr << "[错误] SERVER_IP 必须是有效的 IPv4 或 IPv6 地址。" << endl;
        return false;
    }
    if (!LOGIN_IP.empty() && !IsValidIpAddress(LOGIN_IP, true))
    {
        cerr << "[错误] LOGIN_IP 必须是有效的 IPv4 地址。" << endl;
        return false;
    }

    DWORD checkIntervalSeconds = 0;
    DWORD timeoutSeconds = 0;
    if (!TryGetConfigSeconds(config, "CHECK_INTERVAL", DEFAULT_CHECK_INTERVAL_SECONDS,
                             MAX_CHECK_INTERVAL_SECONDS, checkIntervalSeconds))
    {
        cerr << "[错误] CHECK_INTERVAL 必须是 1 到 " << MAX_CHECK_INTERVAL_SECONDS << " 秒的正整数。" << endl;
        return false;
    }
    if (!TryGetConfigSeconds(config, "TIMEOUT", DEFAULT_TIMEOUT_SECONDS,
                             MAX_TIMEOUT_SECONDS, timeoutSeconds))
    {
        cerr << "[错误] TIMEOUT 必须是 1 到 " << MAX_TIMEOUT_SECONDS << " 秒的正整数。" << endl;
        return false;
    }

    USER_ACCOUNT = string(",0,") + studentId;
    CHECK_INTERVAL_MS = SecondsToMilliseconds(checkIntervalSeconds);
    TIMEOUT_MS = SecondsToMilliseconds(timeoutSeconds);

    cout << "[信息] 已加载配置文件: " << configPath << endl;
    return true;
}

// ================= 全局控制 =================
HANDLE g_hExitEvent = NULL;
HANDLE g_hPauseEvent = NULL; // 暂停事件
HANDLE g_hMessageReadyEvent = NULL;
atomic<DWORD> g_dwMessageThreadId(0);
atomic_bool g_bPaused(false);       // 暂停状态
atomic_bool g_bHiddenToTray(false); // 已隐藏到托盘
atomic_bool g_bTraySupported(false);

// 系统托盘相关
#define WM_TRAYICON (WM_USER + 1)
#define WM_APP_EXIT (WM_APP + 1)
#define ID_TRAY_SHOW 1001
#define ID_TRAY_PAUSE 1002
#define ID_TRAY_EXIT 1003
NOTIFYICONDATAW g_nid = {0};
HWND g_hWnd = NULL;     // 消息窗口句柄
HWND g_hConsole = NULL; // 控制台窗口句柄

// 控制台信号处理 (Ctrl+C, 关闭窗口等)
BOOL WINAPI ConsoleHandler(DWORD signal)
{
    switch (signal)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_hExitEvent)
        {
            SetEvent(g_hExitEvent); // 触发退出事件，中断 Sleep
        }
        return TRUE;
    default:
        return FALSE;
    }
}

// ================= 系统托盘功能 =================

bool IsWindowsTerminalSession()
{
    return GetEnvironmentVariableW(L"WT_SESSION", NULL, 0) > 0;
}

bool HasClassicConsoleTraySupport()
{
    return g_bTraySupported.load() && g_hConsole && IsWindow(g_hConsole);
}

// 显示控制台窗口
void ShowConsoleWindow()
{
    if (!HasClassicConsoleTraySupport())
        return;

    ShowWindow(g_hConsole, SW_RESTORE);
    SetForegroundWindow(g_hConsole);
    g_bHiddenToTray.store(false);
}

// 隐藏控制台窗口到托盘
void HideToTray()
{
    if (!HasClassicConsoleTraySupport())
        return;

    ShowWindow(g_hConsole, SW_HIDE);
    g_bHiddenToTray.store(true);
}

void UpdateTrayTooltip(bool isPaused)
{
    if (!g_hWnd)
        return;

    NOTIFYICONDATAW nid = {0};
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = g_hWnd;
    nid.uID = 1;
    nid.uFlags = NIF_TIP;
    wcscpy_s(nid.szTip, isPaused ? L"CQU 自动登录 - 已暂停" : L"CQU 自动登录 - 运行中");
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// 切换暂停状态
void TogglePause()
{
    bool wasPaused = g_bPaused.load();
    while (!g_bPaused.compare_exchange_weak(wasPaused, !wasPaused))
    {
    }

    bool isPaused = !wasPaused;
    if (isPaused)
    {
        cout << "[信息] 服务已暂停，按 Ctrl+P 继续" << endl;
    }
    else
    {
        cout << "[信息] 服务已继续" << endl;
        if (g_hPauseEvent)
            SetEvent(g_hPauseEvent);
    }

    UpdateTrayTooltip(isPaused);
}

// 创建托盘图标
bool CreateTrayIcon(HWND hWnd)
{
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hWnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"CQU 自动登录 - 运行中");
    return Shell_NotifyIconW(NIM_ADD, &g_nid) == TRUE;
}

// 删除托盘图标
void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

// 显示托盘右键菜单
void ShowTrayMenu(HWND hWnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_SHOW, L"显示");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_PAUSE, g_bPaused.load() ? L"继续" : L"暂停");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出");

    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
}

// 隐藏窗口的消息处理函数
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP)
        {
            ShowConsoleWindow();
        }
        else if (lParam == WM_RBUTTONUP)
        {
            ShowTrayMenu(hWnd);
        }
        break;
    case WM_APP_EXIT:
        RemoveTrayIcon();
        DestroyWindow(hWnd);
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAY_SHOW:
            ShowConsoleWindow();
            break;
        case ID_TRAY_PAUSE:
            TogglePause();
            break;
        case ID_TRAY_EXIT:
            SetEvent(g_hExitEvent);
            break;
        }
        break;
    case WM_DESTROY:
        g_hWnd = NULL;
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// 创建隐藏的消息窗口
HWND CreateMessageWindow()
{
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"AutoLoginCQUClass";
    RegisterClassExW(&wc);

    return CreateWindowExW(0, L"AutoLoginCQUClass", L"AutoLoginCQU",
                           0, 0, 0, 0, 0, HWND_MESSAGE, NULL,
                           GetModuleHandle(NULL), NULL);
}

// 监控控制台窗口最小化的线程
DWORD WINAPI ConsoleMonitorThread(LPVOID lpParam)
{
    while (WaitForSingleObject(g_hExitEvent, 200) == WAIT_TIMEOUT)
    {
        if (HasClassicConsoleTraySupport() && !g_bHiddenToTray.load() && IsIconic(g_hConsole))
            HideToTray();
    }
    return 0;
}

// 键盘输入监控线程 (Ctrl+P) - 使用控制台输入事件，仅当焦点在控制台时生效
DWORD WINAPI KeyboardMonitorThread(LPVOID lpParam)
{
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput == INVALID_HANDLE_VALUE)
        return 1;

    DWORD oldMode = 0;
    if (!GetConsoleMode(hInput, &oldMode))
        return 1;

    DWORD newMode = oldMode | ENABLE_WINDOW_INPUT | ENABLE_PROCESSED_INPUT;
    if (!SetConsoleMode(hInput, newMode))
        return 1;

    INPUT_RECORD inputRecord;
    DWORD eventsRead;

    while (WaitForSingleObject(g_hExitEvent, 0) == WAIT_TIMEOUT)
    {
        DWORD waitResult = WaitForSingleObject(hInput, 100);
        if (waitResult != WAIT_OBJECT_0)
            continue;

        if (!PeekConsoleInput(hInput, &inputRecord, 1, &eventsRead) || eventsRead == 0)
            continue;

        if (!ReadConsoleInput(hInput, &inputRecord, 1, &eventsRead))
            continue;

        if (inputRecord.EventType == KEY_EVENT && inputRecord.Event.KeyEvent.bKeyDown &&
            (inputRecord.Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) &&
            inputRecord.Event.KeyEvent.wVirtualKeyCode == 'P')
        {
            TogglePause();
        }
    }

    SetConsoleMode(hInput, oldMode);
    return 0;
}

// 消息循环线程（同时负责创建窗口和托盘图标）
DWORD WINAPI MessageLoopThread(LPVOID lpParam)
{
    g_dwMessageThreadId.store(GetCurrentThreadId());
    MSG msg;
    PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

    g_hWnd = CreateMessageWindow();
    if (g_hWnd)
    {
        if (!CreateTrayIcon(g_hWnd))
            cerr << "[警告] 无法创建托盘图标，托盘功能不可用。" << endl;
    }
    else
    {
        cerr << "[警告] 无法创建托盘消息窗口，托盘功能不可用。" << endl;
    }

    if (g_hMessageReadyEvent)
        SetEvent(g_hMessageReadyEvent);

    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    g_dwMessageThreadId.store(0);
    return 0;
}

// ================= RAII 资源封装 =================

// WinHTTP 句柄自动管理
struct WinHttpDeleter
{
    void operator()(HINTERNET h) const
    {
        if (h)
            WinHttpCloseHandle(h);
    }
};
using ScopedWinHttp = unique_ptr<void, WinHttpDeleter>;

// 内存指针自动管理 (用于 GetAdaptersAddresses)
struct MallocDeleter
{
    void operator()(void *p) const
    {
        if (p)
            free(p);
    }
};
using ScopedMalloc = unique_ptr<void, MallocDeleter>;

// ================= 工具函数 =================

// URL 编码
string UrlEncode(const string &value)
{
    ostringstream escaped;
    escaped.fill('0');
    escaped << hex;
    for (char c : value)
    {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
        }
        else
        {
            escaped << '%' << setw(2) << int((unsigned char)c);
        }
    }
    return escaped.str();
}

// UTF-8 string 转 wstring
wstring ToWString(const string &str)
{
    if (str.empty())
        return wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// wstring 转 UTF-8 string
string ToString(const wstring &wstr)
{
    if (wstr.empty())
        return string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void CloseHandleIfValid(HANDLE &handle)
{
    if (handle)
    {
        CloseHandle(handle);
        handle = NULL;
    }
}

string TruncateForLog(const string &value, size_t maxLength = 200)
{
    if (value.length() <= maxLength)
        return value;
    return value.substr(0, maxLength) + "...";
}

// 获取本机 IP (IPv4 & IPv6)
bool GetLocalIPs(string &ipv4, string &ipv6)
{
    ipv4.clear();
    ipv6.clear();
    string fallback_ipv4;
    string nat_fallback_ipv4; // 最低优先：192.168.x.x（家用路由器 LAN 地址）

    ULONG outBufLen = 15000;
    ScopedMalloc pAddresses(malloc(outBufLen));

    // 第一次尝试获取大小
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, (PIP_ADAPTER_ADDRESSES)pAddresses.get(), &outBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        pAddresses.reset(malloc(outBufLen));
    }

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, (PIP_ADAPTER_ADDRESSES)pAddresses.get(), &outBufLen) == NO_ERROR)
    {
        for (PIP_ADAPTER_ADDRESSES pCurr = (PIP_ADAPTER_ADDRESSES)pAddresses.get(); pCurr != NULL; pCurr = pCurr->Next)
        {
            if (pCurr->OperStatus != IfOperStatusUp || pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                continue;

            for (PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress; pUni != NULL; pUni = pUni->Next)
            {
                char ip[INET6_ADDRSTRLEN] = {0};
                getnameinfo(pUni->Address.lpSockaddr, pUni->Address.iSockaddrLength, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);

                if (pUni->Address.lpSockaddr->sa_family == AF_INET)
                {
                    string s_ip = ip;
                    // 排除回环、APIPA (169.254.x.x)、VPN 保留地址 (198.18.x.x)
                    if (s_ip.find("127.") == 0 || s_ip.find("169.254.") == 0 || s_ip.find("198.18.") == 0)
                        continue;

                    // 192.168.x.x 是路由器 LAN 地址，降为最低优先兜底
                    if (s_ip.find("192.168.") == 0)
                    {
                        if (nat_fallback_ipv4.empty())
                            nat_fallback_ipv4 = s_ip;
                        continue;
                    }

                    // 优先选择物理网卡 (以太网 或 Wi-Fi)
                    if (pCurr->IfType == IF_TYPE_ETHERNET_CSMACD || pCurr->IfType == IF_TYPE_IEEE80211)
                    {
                        if (ipv4.empty())
                            ipv4 = s_ip;
                    }
                    else
                    {
                        if (fallback_ipv4.empty())
                            fallback_ipv4 = s_ip;
                    }
                }
                else if (pUni->Address.lpSockaddr->sa_family == AF_INET6)
                {
                    // 忽略链路本地地址 (fe80::)
                    if (ipv6.empty() && strncmp(ip, "fe80", 4) != 0)
                        ipv6 = ip;
                }
            }
        }
    }

    // 如果没有找到物理网卡 IP，使用备选 IP
    if (ipv4.empty() && !fallback_ipv4.empty())
    {
        ipv4 = fallback_ipv4;
    }

    // 最后兜底：仅有 192.168.x.x（设备在路由器 NAT 后方）
    if (ipv4.empty() && !nat_fallback_ipv4.empty())
    {
        ipv4 = nat_fallback_ipv4;
        cout << "[警告] 当前 IP (" << ipv4 << ") 为路由器内网地址，设备可能处于 NAT 后方，认证可能失败。" << endl;
    }

    return !ipv4.empty();
}

// ================= 核心逻辑 =================

// 解析主机名到 IP（优先 IPv4，回退 IPv6）
bool ResolveHostToIP(const string &host, string &out_ip)
{
    out_ip.clear();
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int res = getaddrinfo(host.c_str(), NULL, &hints, &result);
    if (res != 0 || result == NULL)
        return false;

    // 优先 IPv4
    for (struct addrinfo *p = result; p != NULL; p = p->ai_next)
    {
        if (p->ai_family == AF_INET)
        {
            char ip[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in *sa = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            out_ip = ip;
            freeaddrinfo(result);
            return true;
        }
    }

    // 再尝试 IPv6
    for (struct addrinfo *p = result; p != NULL; p = p->ai_next)
    {
        if (p->ai_family == AF_INET6)
        {
            char ip[INET6_ADDRSTRLEN] = {0};
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)p->ai_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof(ip));
            out_ip = ip;
            freeaddrinfo(result);
            return true;
        }
    }

    freeaddrinfo(result);
    return false;
}

wstring BuildLoginPath(const string &loginIpv4, const string &ipv6)
{
    stringstream ss;
    ss << "callback=dr1004"
       << "&login_method=1"
       << "&user_account=" << UrlEncode(USER_ACCOUNT)
       << "&user_password=" << UrlEncode(USER_PASSWORD)
       << "&wlan_user_ip=" << UrlEncode(loginIpv4)
       << "&wlan_user_ipv6=" << UrlEncode(ipv6)
       << "&wlan_user_mac=000000000000"
       << "&wlan_ac_ip=&wlan_ac_name="
       << "&term_ua=" << UrlEncode("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
       << "&term_type=1&jsVersion=4.2.2&terminal_type=1&lang=zh-cn,zh&v=6231";

    return LOGIN_PATH_BASE + L"?" + ToWString(ss.str());
}

bool GetPortalAddress(string &resolvedIP)
{
    if (!SERVER_IP.empty())
    {
        resolvedIP = SERVER_IP;
        return true;
    }

    if (!ResolveHostToIP(LOGIN_HOST_UTF8, resolvedIP))
    {
        cerr << "[错误] 无法解析主机名到 IP: " << LOGIN_HOST_UTF8 << endl;
        cerr << "[提示] 请在 config.yaml 中添加 SERVER_IP: xxx.xxx.xxx.xxx 手动指定服务器 IP" << endl;
        cerr << "[提示] 可通过 nslookup login.cqu.edu.cn 查询正确的 IP 地址" << endl;
        return false;
    }

    return true;
}

bool ReadResponseBody(HINTERNET hRequest, string &response)
{
    response.clear();

    while (response.size() < MAX_RESPONSE_BYTES)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &available))
        {
            cerr << "[错误] 查询响应数据失败: " << GetLastError() << endl;
            return false;
        }
        if (available == 0)
            return true;

        DWORD toRead = (DWORD)min<size_t>(available, MAX_RESPONSE_BYTES - response.size());
        vector<char> buffer(toRead);
        DWORD downloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), toRead, &downloaded))
        {
            cerr << "[错误] 读取响应数据失败: " << GetLastError() << endl;
            return false;
        }
        if (downloaded == 0)
            return true;

        response.append(buffer.data(), downloaded);
    }

    return true;
}

bool ContainsJsonIntField(const string &response, const string &key, int expected)
{
    string token = "\"" + key + "\"";
    size_t pos = 0;

    while ((pos = response.find(token, pos)) != string::npos)
    {
        pos += token.size();
        while (pos < response.size() && isspace((unsigned char)response[pos]))
            ++pos;
        if (pos >= response.size() || response[pos] != ':')
            continue;
        ++pos;
        while (pos < response.size() && isspace((unsigned char)response[pos]))
            ++pos;

        bool quoted = pos < response.size() && response[pos] == '"';
        if (quoted)
            ++pos;

        size_t valueStart = pos;
        if (pos < response.size() && response[pos] == '-')
            ++pos;
        while (pos < response.size() && isdigit((unsigned char)response[pos]))
            ++pos;
        if (valueStart == pos)
            continue;

        try
        {
            int value = stoi(response.substr(valueStart, pos - valueStart));
            if (quoted && (pos >= response.size() || response[pos] != '"'))
                continue;
            if (value == expected)
                return true;
        }
        catch (...)
        {
        }
    }

    return false;
}

enum class LoginResult
{
    Success,
    AlreadyOnline,
    Failed
};

LoginResult ClassifyLoginResponse(const string &response)
{
    if (ContainsJsonIntField(response, "result", 1))
        return LoginResult::Success;

    bool alreadyOnline = ContainsJsonIntField(response, "ret_code", 2);
    bool welcomeOnline = ContainsJsonIntField(response, "result", 0) &&
                         ContainsJsonIntField(response, "ret_code", 1) &&
                         response.find("Welcome to Drcom System") != string::npos;

    return (alreadyOnline || welcomeOnline) ? LoginResult::AlreadyOnline : LoginResult::Failed;
}

void LogLoginResult(LoginResult result, const string &loginIpv4, const string &response)
{
    switch (result)
    {
    case LoginResult::Success:
        cout << "[成功] 登录成功 (IPv4: " << loginIpv4 << ")" << endl;
        break;
    case LoginResult::AlreadyOnline:
        cout << "[成功] 设备已在线 (IPv4: " << loginIpv4 << ")" << endl;
        break;
    case LoginResult::Failed:
        cout << "[失败] 登录失败 (IPv4: " << loginIpv4 << ")" << endl;
        break;
    }

    if (!response.empty())
        cout << "[响应] " << TruncateForLog(response) << endl;
}

void PerformLogin(HINTERNET hSession)
{
    string ipv4, ipv6;
    if (!GetLocalIPs(ipv4, ipv6))
    {
        cerr << "[错误] 无法获取本机 IPv4 地址。" << endl;
        return;
    }

    string loginIpv4 = LOGIN_IP.empty() ? ipv4 : LOGIN_IP;
    if (!LOGIN_IP.empty())
        cout << "[信息] 使用配置的登录 IP: " << loginIpv4 << endl;

    string resolvedIP;
    if (!GetPortalAddress(resolvedIP))
        return;
    if (!SERVER_IP.empty())
        cout << "[信息] 使用配置的服务器 IP: " << resolvedIP << endl;

    ScopedWinHttp hConnect(WinHttpConnect(hSession, ToWString(resolvedIP).c_str(), LOGIN_PORT, 0));
    if (!hConnect)
    {
        cerr << "[错误] WinHttpConnect 失败 (IP: " << resolvedIP << "): " << GetLastError() << endl;
        return;
    }

    wstring fullPath = BuildLoginPath(loginIpv4, ipv6);
    ScopedWinHttp hRequest(WinHttpOpenRequest(hConnect.get(), L"GET", fullPath.c_str(),
                                              NULL, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE));
    if (!hRequest)
    {
        cerr << "[错误] 创建请求失败: " << GetLastError() << endl;
        return;
    }

    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    if (!WinHttpSetOption(hRequest.get(), WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags)))
    {
        cerr << "[错误] 设置 TLS 证书选项失败: " << GetLastError() << endl;
        return;
    }

    DWORD disabledFeatures = WINHTTP_DISABLE_KEEP_ALIVE;
    if (!WinHttpSetOption(hRequest.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disabledFeatures, sizeof(disabledFeatures)))
        cerr << "[警告] 禁用 WinHTTP keep-alive 失败: " << GetLastError() << endl;

    wstring hostHeader = L"Host: " + LOGIN_HOST;
    if (!WinHttpAddRequestHeaders(hRequest.get(), hostHeader.c_str(), (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
    {
        cerr << "[错误] 添加 Host 请求头失败: " << GetLastError() << endl;
        return;
    }
    if (!WinHttpAddRequestHeaders(hRequest.get(), L"Connection: close", (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
        cerr << "[警告] 添加 Connection 请求头失败: " << GetLastError() << endl;

    if (!WinHttpSendRequest(hRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        cerr << "[错误] 发送请求失败: " << GetLastError() << endl;
        return;
    }

    if (!WinHttpReceiveResponse(hRequest.get(), NULL))
    {
        cerr << "[错误] 接收响应失败: " << GetLastError() << endl;
        return;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX))
    {
        cerr << "[错误] 查询状态码失败: " << GetLastError() << endl;
        return;
    }

    if (statusCode != 200)
    {
        cout << "[警告] 请求返回状态码: " << statusCode << endl;
        return;
    }

    string response;
    if (!ReadResponseBody(hRequest.get(), response))
        return;

    LogLoginResult(ClassifyLoginResponse(response), loginIpv4, response);
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);

    if (!LoadConfig())
        return CONFIG_ERROR_EXIT_CODE;

    int exitCode = 0;
    bool wsaStarted = false;
    WSADATA wsaData = {0};
    HANDLE hConsoleMonitor = NULL;
    HANDLE hKeyboardMonitor = NULL;
    HANDLE hMessageLoop = NULL;

    g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_hPauseEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_hMessageReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_hExitEvent || !g_hPauseEvent || !g_hMessageReadyEvent)
    {
        cerr << "[错误] 创建事件失败: " << GetLastError() << endl;
        exitCode = 1;
        goto cleanup;
    }

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE))
    {
        cerr << "[错误] 无法设置控制台处理程序: " << GetLastError() << endl;
        exitCode = 1;
        goto cleanup;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << "[错误] WSAStartup 失败。" << endl;
        exitCode = 1;
        goto cleanup;
    }
    wsaStarted = true;

    {
        ScopedWinHttp hSession(WinHttpOpen(L"AutoLogin-CQU/1.0",
                                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                                           WINHTTP_NO_PROXY_NAME,
                                           WINHTTP_NO_PROXY_BYPASS, 0));
        if (!hSession)
        {
            cerr << "[错误] WinHttpOpen 失败: " << GetLastError() << endl;
            exitCode = 1;
            goto cleanup;
        }

        if (!WinHttpSetTimeouts(hSession.get(), TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS))
            cerr << "[警告] 设置 WinHTTP 超时失败: " << GetLastError() << endl;

        if (IsWindowsTerminalSession())
        {
            g_hConsole = NULL;
            g_bTraySupported.store(false);
            cerr << "[警告] 检测到 Windows Terminal，当前版本不支持最小化到系统托盘。" << endl;
            cerr << "[警告] 如需使用托盘功能，请从 cmd.exe 或传统控制台窗口启动。" << endl;
        }
        else
        {
            g_hConsole = GetConsoleWindow();
            g_bTraySupported.store(g_hConsole && IsWindow(g_hConsole));
            if (!g_bTraySupported.load())
                cerr << "[警告] 未检测到可用的传统控制台窗口，托盘功能不可用。" << endl;
        }

        if (g_bTraySupported.load())
        {
            hConsoleMonitor = CreateThread(NULL, 0, ConsoleMonitorThread, NULL, 0, NULL);
            if (!hConsoleMonitor)
                cerr << "[警告] 控制台窗口监控线程启动失败: " << GetLastError() << endl;

            hMessageLoop = CreateThread(NULL, 0, MessageLoopThread, NULL, 0, NULL);
            if (!hMessageLoop)
            {
                cerr << "[警告] 托盘消息线程启动失败: " << GetLastError() << endl;
            }
            else if (WaitForSingleObject(g_hMessageReadyEvent, 1000) != WAIT_OBJECT_0)
            {
                cerr << "[警告] 托盘消息线程启动超时，核心登录服务将继续运行。" << endl;
            }
        }

        hKeyboardMonitor = CreateThread(NULL, 0, KeyboardMonitorThread, NULL, 0, NULL);
        if (!hKeyboardMonitor)
            cerr << "[警告] 键盘监控线程启动失败: " << GetLastError() << endl;

        cout << "=== CQU 自动登录服务已启动 ===" << endl;
        cout << "按 Ctrl+C 或关闭窗口可安全退出。" << endl;
        cout << "按 Ctrl+P 暂停/继续服务。" << endl;
        if (g_bTraySupported.load())
            cout << "最小化窗口将隐藏到系统托盘。" << endl;
        else
            cout << "当前环境不支持最小化到系统托盘；如需使用该功能，请从 cmd.exe 或传统控制台窗口启动。" << endl;

        while (true)
        {
            if (!g_bPaused.load())
                PerformLogin(hSession.get());

            HANDLE handles[] = {g_hExitEvent, g_hPauseEvent};
            DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, CHECK_INTERVAL_MS);
            if (waitResult == WAIT_OBJECT_0)
            {
                cout << "\n正在退出..." << endl;
                break;
            }
            if (waitResult == WAIT_FAILED)
            {
                cerr << "[错误] 等待事件失败: " << GetLastError() << endl;
                exitCode = 1;
                break;
            }
        }
    }

cleanup:
    if (g_hExitEvent)
        SetEvent(g_hExitEvent);

    if (g_hWnd)
        PostMessage(g_hWnd, WM_APP_EXIT, 0, 0);
    else
    {
        DWORD messageThreadId = g_dwMessageThreadId.load();
        if (messageThreadId)
            PostThreadMessage(messageThreadId, WM_QUIT, 0, 0);
    }

    if (hConsoleMonitor)
    {
        WaitForSingleObject(hConsoleMonitor, INFINITE);
        CloseHandle(hConsoleMonitor);
    }
    if (hKeyboardMonitor)
    {
        WaitForSingleObject(hKeyboardMonitor, INFINITE);
        CloseHandle(hKeyboardMonitor);
    }
    if (hMessageLoop)
    {
        WaitForSingleObject(hMessageLoop, INFINITE);
        CloseHandle(hMessageLoop);
    }

    if (wsaStarted)
        WSACleanup();

    CloseHandleIfValid(g_hMessageReadyEvent);
    CloseHandleIfValid(g_hPauseEvent);
    CloseHandleIfValid(g_hExitEvent);

    if (exitCode == 0)
        cout << "程序已安全结束。" << endl;
    return exitCode;
}
