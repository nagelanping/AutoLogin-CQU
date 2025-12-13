#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <csignal>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <fstream>

// 编译指令: g++ AutoLogin-CQU-Linux.cpp -o AutoLogin-CQU -lcurl -O2
// 依赖项:  curl

using namespace std;

// ================= 配置变量 =================
const string LOGIN_BASE_URL = "https://login.cqu.edu.cn:802/eportal/portal/login";
string USER_ACCOUNT = "";
string USER_PASSWORD = "";
int CHECK_INTERVAL_SEC = 20;
long TIMEOUT_SEC = 5;

// ================= 全局控制 =================
volatile sig_atomic_t g_running = 1;

// 信号处理函数
void SignalHandler(int signum)
{
    g_running = 0;
}

// ================= RAII 资源封装 =================

// Curl 全局初始化管理
class CurlGlobal
{
public:
    CurlGlobal() { curl_global_init(CURL_GLOBAL_ALL); }
    ~CurlGlobal() { curl_global_cleanup(); }
};

// Curl Easy 句柄管理
struct CurlDeleter
{
    void operator()(CURL *curl) const
    {
        if (curl)
            curl_easy_cleanup(curl);
    }
};
using ScopedCurl = unique_ptr<CURL, CurlDeleter>;

// ================= 配置管理 =================

// 去除字符串首尾空白
string Trim(const string &str)
{
    size_t first = str.find_first_not_of(" \t\r\n");
    if (string::npos == first)
    {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// 加载配置文件
bool LoadConfig(const string &filename)
{
    ifstream file(filename);
    if (!file.is_open())
    {
        return false;
    }

    string line;
    while (getline(file, line))
    {
        line = Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#')
            continue;
        if (line[0] == '[')
            continue;

        size_t delimiterPos = line.find('=');
        if (delimiterPos != string::npos)
        {
            string key = Trim(line.substr(0, delimiterPos));
            string value = Trim(line.substr(delimiterPos + 1));

            if (key == "USER_ACCOUNT")
                USER_ACCOUNT = value;
            else if (key == "USER_PASSWORD")
                USER_PASSWORD = value;
            else if (key == "CHECK_INTERVAL")
                CHECK_INTERVAL_SEC = stoi(value);
            else if (key == "TIMEOUT")
                TIMEOUT_SEC = stol(value);
        }
    }
    return true;
}

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

// 获取本机 IP (IPv4 & IPv6)
bool GetLocalIPs(string &ipv4, string &ipv6)
{
    ipv4.clear();
    ipv6.clear();
    string fallback_ipv4;

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return false;
    }

    // 使用 unique_ptr 自动释放 ifaddrs 链表
    unique_ptr<struct ifaddrs, void (*)(struct ifaddrs *)> ptr_guard(ifaddr, freeifaddrs);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        // 忽略回环接口 (lo) 和未启动的接口
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP))
            continue;

        int family = ifa->ifa_addr->sa_family;
        char host[NI_MAXHOST];

        if (family == AF_INET || family == AF_INET6)
        {
            int s = getnameinfo(ifa->ifa_addr,
                                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);
            if (s != 0)
                continue;

            if (family == AF_INET)
            {
                string s_ip = host;
                // 排除 127.x.x.x 和 198.18.x.x (常见 VPN 保留地址)
                if (s_ip.find("127.") == 0 || s_ip.find("198.18.") == 0)
                    continue;

                // 简单的启发式优先级: e*(ethernet), w*(wireless) 优先
                string ifname = ifa->ifa_name;
                bool is_physical = (ifname.find("eth") == 0 || ifname.find("en") == 0 || ifname.find("wlan") == 0 || ifname.find("wl") == 0);

                if (is_physical)
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
            else if (family == AF_INET6)
            {
                // 忽略链路本地地址 (fe80::)
                if (ipv6.empty() && strncmp(host, "fe80", 4) != 0)
                {
                    // 移除可能存在的 scope id (例如 %eth0)
                    string ip_str(host);
                    size_t pos = ip_str.find('%');
                    if (pos != string::npos)
                    {
                        ip_str = ip_str.substr(0, pos);
                    }
                    ipv6 = ip_str;
                }
            }
        }
    }

    if (ipv4.empty() && !fallback_ipv4.empty())
    {
        ipv4 = fallback_ipv4;
    }

    return !ipv4.empty();
}

// libcurl 写回调 (保存响应内容)
size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

// ================= 核心逻辑 =================

void PerformLogin(CURL *curl)
{
    string ipv4, ipv6;
    if (!GetLocalIPs(ipv4, ipv6))
    {
        cerr << "[错误] 无法获取本机 IPv4 地址。" << endl;
        return;
    }

    // 构建 URL 参数
    stringstream ss;
    ss << LOGIN_BASE_URL << "?"
       << "callback=dr1004"
       << "&login_method=1"
       << "&user_account=" << UrlEncode(USER_ACCOUNT)
       << "&user_password=" << UrlEncode(USER_PASSWORD)
       << "&wlan_user_ip=" << UrlEncode(ipv4)
       << "&wlan_user_ipv6=" << UrlEncode(ipv6)
       << "&wlan_user_mac=000000000000"
       << "&wlan_ac_ip=&wlan_ac_name="
       << "&term_ua=" << UrlEncode("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
       << "&term_type=1&jsVersion=4.2.2&terminal_type=1&lang=zh-cn,zh&v=6231";

    string fullUrl = ss.str();

    // 设置请求选项
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());

    string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // 执行请求
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        cerr << "[错误] 请求失败: " << curl_easy_strerror(res) << endl;
    }
    else
    {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 200)
        {
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
            cout << "[警告] 请求返回状态码: " << response_code << endl;
        }
    }
}

int main()
{
    // 0. 加载配置
    if (!LoadConfig("config.ini"))
    {
        cerr << "[警告] 未找到配置文件 config.ini，请确保文件存在。" << endl;
    }

    if (USER_ACCOUNT.empty() || USER_PASSWORD.empty())
    {
        cerr << "[错误] 账号或密码未配置，请检查 config.ini。" << endl;
        return 1;
    }

    // 1. 信号处理
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SignalHandler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // 2. 初始化 Libcurl
    CurlGlobal curlGlobal;             // 全局初始化
    ScopedCurl curl(curl_easy_init()); // 句柄初始化

    if (!curl)
    {
        cerr << "Curl 初始化失败。" << endl;
        return 1;
    }

    // 3. 设置持久化选项 (复用连接)
    // 绕过系统代理
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
    // 设置超时
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, TIMEOUT_SEC);
    // 设置回调，避免输出响应体到 stdout
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteCallback);
    // 启用 TCP Keep-Alive
    curl_easy_setopt(curl.get(), CURLOPT_TCP_KEEPALIVE, 1L);
    // 不验证 SSL 证书 (校园网自签名证书可能导致问题)
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 0L);

    cout << "=== CQU 自动登录服务 (Linux) 已启动 ===" << endl;
    cout << "按 Ctrl+C 可安全退出。" << endl;

    // 4. 主循环
    while (g_running)
    {
        PerformLogin(curl.get());

        // 睡眠等待
        // 如果收到信号，sleep 会被中断并返回剩余秒数，循环条件 g_running 变为 0，从而优雅退出
        if (g_running)
        {
            sleep(CHECK_INTERVAL_SEC);
        }
    }

    cout << "\n正在退出..." << endl;
    // ScopedCurl 和 CurlGlobal 会自动清理资源
    return 0;
}
