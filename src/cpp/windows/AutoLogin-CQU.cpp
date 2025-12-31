#define _WIN32_WINNT 0x0600
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

// 编译指令: g++ AutoLogin-CQU.cpp -o AutoLogin-CQU.exe -lwinhttp -liphlpapi -lws2_32 -lshell32 -luser32 -static

using namespace std;

// ================= 配置常量 =================
const wstring LOGIN_HOST = L"login.cqu.edu.cn";
const int LOGIN_PORT = 802;
const wstring LOGIN_PATH_BASE = L"/eportal/portal/login";

// ================= 全局配置变量 =================
string USER_ACCOUNT;
string USER_PASSWORD;
string SERVER_IP;  // 可选：直接指定服务器 IP，绕过 DNS 解析
DWORD CHECK_INTERVAL_MS = 20000;
DWORD TIMEOUT_MS = 5000;

void LoadConfig()
{
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0)
    {
        cerr << "[错误] 无法获取可执行文件路径" << endl;
        return;
    }
    string path(exePath);
    string iniPath = path.substr(0, path.find_last_of("\\/") + 1) + "config.ini";

    char buffer[256];

    GetPrivateProfileStringA("Settings", "STUDENT_ID", "", buffer, 256, iniPath.c_str());
    if (strlen(buffer) > 0)
        USER_ACCOUNT = string(",0,") + buffer;
    else
        USER_ACCOUNT = "";

    GetPrivateProfileStringA("Settings", "USER_PASSWORD", "", buffer, 256, iniPath.c_str());
    USER_PASSWORD = buffer;

    GetPrivateProfileStringA("Settings", "SERVER_IP", "", buffer, 256, iniPath.c_str());
    SERVER_IP = buffer;

    int interval = GetPrivateProfileIntA("Settings", "CHECK_INTERVAL", 20, iniPath.c_str());
    if (interval > 0)
        CHECK_INTERVAL_MS = interval * 1000;

    int timeout = GetPrivateProfileIntA("Settings", "TIMEOUT", 5, iniPath.c_str());
    if (timeout > 0)
        TIMEOUT_MS = timeout * 1000;

    if (USER_ACCOUNT.empty() || USER_PASSWORD.empty())
    {
        cerr << "[警告] 未在 config.ini 中找到账号或密码，请检查配置文件。" << endl;
        cerr << "配置文件路径: " << iniPath << endl;
    }
    else
    {
        cout << "[信息] 已加载配置文件: " << iniPath << endl;
    }
}

// ================= 全局控制 =================
HANDLE g_hExitEvent = NULL;
HANDLE g_hPauseEvent = NULL;  // 暂停事件
bool g_bPaused = false;       // 暂停状态
bool g_bMinimized = false;    // 最小化状态

// 系统托盘相关
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_SHOW 1001
#define ID_TRAY_PAUSE 1002
#define ID_TRAY_EXIT 1003
NOTIFYICONDATAW g_nid = {0};
HWND g_hWnd = NULL;           // 消息窗口句柄
HWND g_hConsole = NULL;       // 控制台窗口句柄

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

// 显示控制台窗口
void ShowConsoleWindow()
{
    if (g_hConsole)
    {
        ShowWindow(g_hConsole, SW_RESTORE);
        SetForegroundWindow(g_hConsole);
        g_bMinimized = false;
    }
}

// 隐藏控制台窗口到托盘
void HideToTray()
{
    if (g_hConsole)
    {
        ShowWindow(g_hConsole, SW_HIDE);
        g_bMinimized = true;
    }
}

// 切换暂停状态
void TogglePause()
{
    g_bPaused = !g_bPaused;
    if (g_bPaused)
    {
        cout << "[信息] 服务已暂停，按 Ctrl+P 继续" << endl;
    }
    else
    {
        cout << "[信息] 服务已继续" << endl;
        SetEvent(g_hPauseEvent);  // 唤醒主循环
    }
    
    // 更新托盘提示
    if (g_bPaused)
        wcscpy_s(g_nid.szTip, L"CQU 自动登录 - 已暂停");
    else
        wcscpy_s(g_nid.szTip, L"CQU 自动登录 - 运行中");
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// 创建托盘图标
void CreateTrayIcon(HWND hWnd)
{
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hWnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"CQU 自动登录 - 运行中");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
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
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_PAUSE, g_bPaused ? L"继续" : L"暂停");
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
        if (g_hConsole && !g_bMinimized)
        {
            if (IsIconic(g_hConsole))  // 窗口被最小化
            {
                HideToTray();
            }
        }
    }
    return 0;
}

// 键盘输入监控线程 (Ctrl+P) - 使用控制台输入事件，仅当焦点在控制台时生效
DWORD WINAPI KeyboardMonitorThread(LPVOID lpParam)
{
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput == INVALID_HANDLE_VALUE)
        return 1;
    
    // 保存原始控制台模式
    DWORD oldMode;
    GetConsoleMode(hInput, &oldMode);
    // 启用窗口输入和鼠标输入，禁用行输入模式以便读取单个按键
    SetConsoleMode(hInput, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT);
    
    INPUT_RECORD inputRecord;
    DWORD eventsRead;
    
    while (WaitForSingleObject(g_hExitEvent, 0) == WAIT_TIMEOUT)
    {
        // 等待输入事件，带超时
        DWORD waitResult = WaitForSingleObject(hInput, 100);
        if (waitResult == WAIT_OBJECT_0)
        {
            if (PeekConsoleInput(hInput, &inputRecord, 1, &eventsRead) && eventsRead > 0)
            {
                ReadConsoleInput(hInput, &inputRecord, 1, &eventsRead);
                
                if (inputRecord.EventType == KEY_EVENT && 
                    inputRecord.Event.KeyEvent.bKeyDown)
                {
                    // 检测 Ctrl+P
                    if ((inputRecord.Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) &&
                        inputRecord.Event.KeyEvent.wVirtualKeyCode == 'P')
                    {
                        TogglePause();
                    }
                }
            }
        }
    }
    
    // 恢复控制台模式
    SetConsoleMode(hInput, oldMode);
    return 0;
}

// 消息循环线程（同时负责创建窗口和托盘图标）
DWORD WINAPI MessageLoopThread(LPVOID lpParam)
{
    // 在此线程中创建消息窗口和托盘图标
    g_hWnd = CreateMessageWindow();
    if (g_hWnd)
    {
        CreateTrayIcon(g_hWnd);
    }
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
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

// 获取本机 IP (IPv4 & IPv6)
bool GetLocalIPs(string &ipv4, string &ipv6)
{
    ipv4.clear();
    ipv6.clear();
    string fallback_ipv4;

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
                    // 排除 127.x.x.x 和 198.18.x.x (常见 VPN 保留地址)
                    if (s_ip.find("127.") == 0 || s_ip.find("198.18.") == 0)
                        continue;

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

void PerformLogin(HINTERNET hSession)
{
    string ipv4, ipv6;
    if (!GetLocalIPs(ipv4, ipv6))
    {
        cerr << "[错误] 无法获取本机 IPv4 地址。" << endl;
        return;
    }

    // 构建 URL 参数
    stringstream ss;
    ss << "callback=dr1004"
       << "&login_method=1"
       << "&user_account=" << UrlEncode(USER_ACCOUNT)
       << "&user_password=" << UrlEncode(USER_PASSWORD)
       << "&wlan_user_ip=" << UrlEncode(ipv4)
       << "&wlan_user_ipv6=" << UrlEncode(ipv6)
       << "&wlan_user_mac=000000000000"
       << "&wlan_ac_ip=&wlan_ac_name="
       << "&term_ua=" << UrlEncode("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
       << "&term_type=1&jsVersion=4.2.2&terminal_type=1&lang=zh-cn,zh&v=6231";

    wstring fullPath = LOGIN_PATH_BASE + L"?" + ToWString(ss.str());

    // 确定目标服务器 IP：优先使用配置文件中的 SERVER_IP，否则尝试 DNS 解析
    string resolvedIP;
    if (!SERVER_IP.empty())
    {
        resolvedIP = SERVER_IP;
        cout << "[信息] 使用配置的服务器 IP: " << resolvedIP << endl;
    }
    else if (!ResolveHostToIP(ToString(LOGIN_HOST), resolvedIP))
    {
        cerr << "[错误] 无法解析主机名到 IP: " << ToString(LOGIN_HOST) << endl;
        cerr << "[提示] 请在 config.ini 中添加 SERVER_IP=xxx.xxx.xxx.xxx 手动指定服务器 IP" << endl;
        cerr << "[提示] 可通过 nslookup login.cqu.edu.cn 查询正确的 IP 地址" << endl;
        return;
    }

    // 使用解析到的 IP 建立连接（每次重建，确保解析是最新的）
    wstring wsIp = ToWString(resolvedIP);
    ScopedWinHttp hConnect(WinHttpConnect(hSession, wsIp.c_str(), LOGIN_PORT, 0));
    if (!hConnect)
    {
        cerr << "[错误] WinHttpConnect 失败 (IP: " << resolvedIP << "): " << GetLastError() << endl;
        return;
    }

    // 创建请求（HTTPS）
    ScopedWinHttp hRequest(WinHttpOpenRequest(hConnect.get(), L"GET", fullPath.c_str(),
                                              NULL, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE));

    if (!hRequest)
    {
        cerr << "[错误] 创建请求失败: " << GetLastError() << endl;
        return;
    }

    // 忽略 SSL 证书错误 (常见于校园网自签名证书)
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest.get(), WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    // 添加 Host 头以便服务器识别虚拟主机（使用原始主机名）
    wstring hostHeader = L"Host: " + LOGIN_HOST;
    WinHttpAddRequestHeaders(hRequest.get(), hostHeader.c_str(), (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    // 发送请求
    if (WinHttpSendRequest(hRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        if (WinHttpReceiveResponse(hRequest.get(), NULL))
        {
            DWORD statusCode = 0;
            DWORD dwSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

            if (statusCode == 200)
            {
                // 读取响应内容以确认登录结果
                string response;
                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;
                do
                {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest.get(), &dwSize))
                        break;
                    if (dwSize == 0)
                        break;

                    vector<char> buffer(dwSize + 1);
                    if (WinHttpReadData(hRequest.get(), &buffer[0], dwSize, &dwDownloaded))
                    {
                        response.append(buffer.data(), dwDownloaded);
                    }
                } while (dwSize > 0);

                // 解析简单的 JSON 响应
                // 成功: "result":1
                // 已在线: "ret_code":2
                bool isSuccess = (response.find("\"result\":1") != string::npos);
                bool isOnline = (response.find("\"ret_code\":2") != string::npos);

                if (isSuccess || isOnline)
                {
                    cout << "[成功] " << (isOnline ? "设备已在线" : "登录成功") << " (IPv4: " << ipv4 << ")" << endl;
                }
                else
                {
                    cout << "[失败] 登录失败 (IPv4: " << ipv4 << ")" << endl;
                }

                if (!response.empty())
                {
                    // 简单的截断输出，防止过长
                    if (response.length() > 200)
                        response = response.substr(0, 200) + "...";
                    cout << "[响应] " << response << endl;
                }
            }
            else
            {
                cout << "[警告] 请求返回状态码: " << statusCode << endl;
            }
        }
        else
        {
            cerr << "[错误] 接收响应失败: " << GetLastError() << endl;
        }
    }
    else
    {
        cerr << "[错误] 发送请求失败: " << GetLastError() << endl;
    }
}

int main()
{
    // 1. 初始化控制台和信号处理
    SetConsoleOutputCP(CP_UTF8);

    // 加载配置文件
    LoadConfig();

    g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_hPauseEvent = CreateEvent(NULL, FALSE, FALSE, NULL);  // 自动重置事件
    
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE))
    {
        cerr << "无法设置控制台处理程序。" << endl;
        return 1;
    }

    // 获取控制台窗口句柄
    g_hConsole = GetConsoleWindow();
    
    // 启动监控线程（消息循环线程会创建托盘图标）
    HANDLE hConsoleMonitor = CreateThread(NULL, 0, ConsoleMonitorThread, NULL, 0, NULL);
    HANDLE hKeyboardMonitor = CreateThread(NULL, 0, KeyboardMonitorThread, NULL, 0, NULL);
    HANDLE hMessageLoop = CreateThread(NULL, 0, MessageLoopThread, NULL, 0, NULL);
    
    // 等待托盘图标创建完成
    Sleep(100);

    cout << "=== CQU 自动登录服务已启动 ===" << endl;
    cout << "按 Ctrl+C 或关闭窗口可安全退出。" << endl;
    cout << "按 Ctrl+P 暂停/继续服务。" << endl;
    cout << "最小化窗口将隐藏到系统托盘。" << endl;

    // 2. 初始化 WinHTTP 会话 (RAII)
    // WINHTTP_ACCESS_TYPE_NO_PROXY: 强制绕过系统代理，直连
    ScopedWinHttp hSession(WinHttpOpen(L"AutoLogin-CQU/1.0",
                                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession)
    {
        cerr << "WinHttpOpen 失败。" << endl;
        return 1;
    }

    WinHttpSetTimeouts(hSession.get(), TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS);

    // 初始化 Winsock，用于 getaddrinfo/inet_ntop 等函数（ResolveHostToIP 使用）
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << "WSAStartup 失败。" << endl;
        return 1;
    }

    // 4. 主循环

    while (true)
    {
        // 检查是否暂停
        if (!g_bPaused)
        {
            PerformLogin(hSession.get());
        }

        // 等待间隔，同时监听退出事件和暂停唤醒事件
        HANDLE handles[] = {g_hExitEvent, g_hPauseEvent};
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, CHECK_INTERVAL_MS);
        
        if (waitResult == WAIT_OBJECT_0)  // 退出事件
        {
            cout << "\n正在退出..." << endl;
            break;
        }
        // WAIT_OBJECT_0 + 1 表示暂停事件被触发（继续），继续下一轮循环
    }

    // 5. 资源清理
    RemoveTrayIcon();
    
    // 等待线程结束
    if (hConsoleMonitor) { WaitForSingleObject(hConsoleMonitor, 500); CloseHandle(hConsoleMonitor); }
    if (hKeyboardMonitor) { WaitForSingleObject(hKeyboardMonitor, 500); CloseHandle(hKeyboardMonitor); }
    if (hMessageLoop) { PostMessage(g_hWnd, WM_QUIT, 0, 0); WaitForSingleObject(hMessageLoop, 500); CloseHandle(hMessageLoop); }
    
    if (g_hWnd) DestroyWindow(g_hWnd);
    
    // ScopedWinHttp 析构函数会自动调用 WinHttpCloseHandle
    // 操作系统会自动回收进程内存
    WSACleanup();
    CloseHandle(g_hPauseEvent);
    CloseHandle(g_hExitEvent);
    cout << "程序已安全结束。" << endl;
    return 0;
}
