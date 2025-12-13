#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>

// 编译指令: g++ AutoLogin-CQU.cpp -o AutoLogin-CQU.exe -lwinhttp -liphlpapi -lws2_32 -static

using namespace std;

// ================= 配置常量 =================
const wstring LOGIN_HOST = L"login.cqu.edu.cn";
const int LOGIN_PORT = 802;
const wstring LOGIN_PATH_BASE = L"/eportal/portal/login";

// ================= 全局配置变量 =================
string USER_ACCOUNT;
string USER_PASSWORD;
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

    GetPrivateProfileStringA("Settings", "USER_ACCOUNT", "", buffer, 256, iniPath.c_str());
    USER_ACCOUNT = buffer;

    GetPrivateProfileStringA("Settings", "USER_PASSWORD", "", buffer, 256, iniPath.c_str());
    USER_PASSWORD = buffer;

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

void PerformLogin(HINTERNET hConnect)
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

    // 创建请求
    ScopedWinHttp hRequest(WinHttpOpenRequest(hConnect, L"GET", fullPath.c_str(),
                                              NULL, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE)); // HTTPS

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
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE))
    {
        cerr << "无法设置控制台处理程序。" << endl;
        return 1;
    }

    cout << "=== CQU 自动登录服务已启动 ===" << endl;
    cout << "按 Ctrl+C 或关闭窗口可安全退出。" << endl;

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

    // 3. 建立连接 (保持连接复用)
    ScopedWinHttp hConnect(WinHttpConnect(hSession.get(), LOGIN_HOST.c_str(), LOGIN_PORT, 0));
    if (!hConnect)
    {
        cerr << "WinHttpConnect 失败。" << endl;
        return 1;
    }

    // 4. 主循环
    while (true)
    {
        PerformLogin(hConnect.get());

        // 等待间隔，同时监听退出事件
        // 如果 g_hExitEvent 被触发 (Ctrl+C)，WaitForSingleObject 会立即返回 WAIT_OBJECT_0
        DWORD waitResult = WaitForSingleObject(g_hExitEvent, CHECK_INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0)
        {
            cout << "\n正在退出..." << endl;
            break;
        }
    }

    // 5. 资源清理
    // ScopedWinHttp 析构函数会自动调用 WinHttpCloseHandle
    // 操作系统会自动回收进程内存
    CloseHandle(g_hExitEvent);
    cout << "程序已安全结束。" << endl;
    return 0;
}
