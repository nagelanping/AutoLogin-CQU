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
#include <curl/curl.h>
#include <fstream>
#include <algorithm>
#include <limits>
#include <sysexits.h>

// 编译指令: g++ <AutoLogin-CQU.cpp> -o <AutoLogin-CQU> -lcurl -O2
// 依赖项:  curl

using namespace std;

// ================= 配置变量 =================
const string LOGIN_HOST = "login.cqu.edu.cn";
const int LOGIN_PORT = 802;
const int CONFIG_ERROR_EXIT_CODE = EX_CONFIG;
const size_t MAX_RESPONSE_BYTES = 4096;
const string LOGIN_PATH = "/eportal/portal/login";
const string USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
string STUDENT_ID = "";
string USER_PASSWORD = "";
string SERVER_IP = "";
string LOGIN_IP = "";
string CA_BUNDLE = "";
int CHECK_INTERVAL_SEC = 20;
long TIMEOUT_SEC = 5;

// ================= 全局控制 =================
volatile sig_atomic_t g_running = 1;

// 信号处理函数
void SignalHandler(int signum)
{
    (void)signum;
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

long ParsePositiveLong(const string &value, long defaultValue)
{
    if (value.empty())
        return defaultValue;

    try
    {
        size_t parsedLength = 0;
        long parsed = stol(value, &parsedLength);
        return parsedLength == value.size() && parsed > 0 ? parsed : defaultValue;
    }
    catch (...)
    {
        return defaultValue;
    }
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
        string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        size_t delimiterPos = trimmed.find(':');
        if (delimiterPos == string::npos)
            continue;

        string key = Trim(trimmed.substr(0, delimiterPos));
        string value = UnquoteYamlValue(trimmed.substr(delimiterPos + 1));

        if (key == "STUDENT_ID")
            STUDENT_ID = value;
        else if (key == "USER_PASSWORD")
            USER_PASSWORD = value;
        else if (key == "SERVER_IP")
            SERVER_IP = value;
        else if (key == "LOGIN_IP")
            LOGIN_IP = value;
        else if (key == "CA_BUNDLE")
            CA_BUNDLE = value;
        else if (key == "CHECK_INTERVAL")
            CHECK_INTERVAL_SEC = static_cast<int>(min(ParsePositiveLong(value, CHECK_INTERVAL_SEC), static_cast<long>(numeric_limits<int>::max())));
        else if (key == "TIMEOUT")
            TIMEOUT_SEC = ParsePositiveLong(value, TIMEOUT_SEC);
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
    string nat_fallback_ipv4; // 最低优先：192.168.x.x（家用路由器 LAN 地址）

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

    // 最后兜底：仅有 192.168.x.x（设备在路由器 NAT 后方）
    if (ipv4.empty() && !nat_fallback_ipv4.empty())
    {
        ipv4 = nat_fallback_ipv4;
        cerr << "autologin-cqu: warning: using NAT address (" << ipv4 << "), device may be behind router" << endl;
    }

    return !ipv4.empty();
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    string *response = static_cast<string *>(userp);
    size_t bytes = size * nmemb;
    size_t available = MAX_RESPONSE_BYTES > response->size() ? MAX_RESPONSE_BYTES - response->size() : 0;
    response->append(static_cast<char *>(contents), min(bytes, available));
    return bytes;
}

enum class LoginResult
{
    Success,
    AlreadyOnline,
    Failed
};

LoginResult ClassifyLoginResponse(const string &response)
{
    if (response.find("\"result\":1") != string::npos)
        return LoginResult::Success;

    if (response.find("\"ret_code\":2") != string::npos)
        return LoginResult::AlreadyOnline;

    if (response.find("\"result\":0") != string::npos &&
        response.find("\"ret_code\":1") != string::npos &&
        response.find("Welcome to Drcom System") != string::npos)
        return LoginResult::AlreadyOnline;

    return LoginResult::Failed;
}


string BuildLoginUrl(const string &loginIpv4, const string &ipv6)
{
    stringstream ss;
    ss << "https://" << LOGIN_HOST << ":" << LOGIN_PORT << LOGIN_PATH << "?"
       << "callback=dr1004"
       << "&login_method=1"
       << "&user_account=" << UrlEncode(",0," + STUDENT_ID)
       << "&user_password=" << UrlEncode(USER_PASSWORD)
       << "&wlan_user_ip=" << UrlEncode(loginIpv4)
       << "&wlan_user_ipv6=" << UrlEncode(ipv6)
       << "&wlan_user_mac=000000000000"
       << "&wlan_ac_ip=&wlan_ac_name="
       << "&term_ua=" << UrlEncode(USER_AGENT)
       << "&term_type=1&jsVersion=4.2.2&terminal_type=1&lang=zh-cn,zh&v=6231";

    return ss.str();
}

bool GetLocalIPv6(string &ipv6)
{
    ipv6.clear();
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return false;
    }

    unique_ptr<struct ifaddrs, void (*)(struct ifaddrs *)> ptr_guard(ifaddr, freeifaddrs);
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET6)
            continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP))
            continue;

        char host[NI_MAXHOST];
        int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0 || strncmp(host, "fe80", 4) == 0)
            continue;

        ipv6 = host;
        size_t pos = ipv6.find('%');
        if (pos != string::npos)
            ipv6 = ipv6.substr(0, pos);
        return true;
    }

    return false;
}

bool GetLoginAddresses(string &loginIpv4, string &ipv6)
{
    if (!LOGIN_IP.empty())
    {
        loginIpv4 = LOGIN_IP;
        GetLocalIPv6(ipv6);
        return true;
    }

    if (!GetLocalIPs(loginIpv4, ipv6))
    {
        cerr << "autologin-cqu: error: failed to get local IPv4 address" << endl;
        return false;
    }

    return true;
}


void PerformLogin(CURL *curl)
{
    string loginIpv4, ipv6;
    if (!GetLoginAddresses(loginIpv4, ipv6))
        return;

    string fullUrl = BuildLoginUrl(loginIpv4, ipv6);
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());

    string response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        cerr << "autologin-cqu: error: request failed: " << curl_easy_strerror(res) << endl;
        return;
    }

    long responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
    if (responseCode != 200)
    {
        cerr << "autologin-cqu: warning: http status " << responseCode << endl;
        return;
    }

    switch (ClassifyLoginResponse(response))
    {
    case LoginResult::Success:
        cout << "autologin-cqu: login success ip=" << loginIpv4 << endl;
        break;
    case LoginResult::AlreadyOnline:
        cout << "autologin-cqu: already online ip=" << loginIpv4 << endl;
        break;
    case LoginResult::Failed:
        cerr << "autologin-cqu: login failed ip=" << loginIpv4 << endl;
        break;
    }
}

int main()
{
    // 0. 加载配置
    if (!LoadConfig("config.yaml"))
    {
        cerr << "autologin-cqu: error: config.yaml not found" << endl;
        return CONFIG_ERROR_EXIT_CODE;
    }

    if (STUDENT_ID.empty() || USER_PASSWORD.empty())
    {
        cerr << "autologin-cqu: error: account or password not configured" << endl;
        return CONFIG_ERROR_EXIT_CODE;
    }

    if (!LOGIN_IP.empty())
    {
        cout << "autologin-cqu: using configured login ip=" << LOGIN_IP << endl;
    }

    if (!CA_BUNDLE.empty())
    {
        ifstream caFile(CA_BUNDLE);
        if (!caFile.is_open())
        {
            cerr << "autologin-cqu: error: CA bundle not readable: " << CA_BUNDLE << endl;
            return CONFIG_ERROR_EXIT_CODE;
        }
        cout << "autologin-cqu: using CA bundle " << CA_BUNDLE << endl;
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
        cerr << "autologin-cqu: error: curl init failed" << endl;
        return 1;
    }

    // 3. 设置 libcurl 选项
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, TIMEOUT_SEC);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl.get(), CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    if (!CA_BUNDLE.empty())
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, CA_BUNDLE.c_str());
    if (!SERVER_IP.empty())
    {
        string resolveEntry = LOGIN_HOST + ":" + to_string(LOGIN_PORT) + ":" + SERVER_IP;
        if (SERVER_IP.find(':') != string::npos)
            resolveEntry = LOGIN_HOST + ":" + to_string(LOGIN_PORT) + ":[" + SERVER_IP + "]";
        curl_easy_setopt(curl.get(), CURLOPT_RESOLVE, resolveEntry.c_str());
    }
    // 显式设置 Host 头（不带端口，与门户协议保持一致）
    unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(curl_slist_append(NULL, ("Host: " + LOGIN_HOST).c_str()), curl_slist_free_all);
    if (!headers)
    {
        cerr << "autologin-cqu: error: curl header init failed" << endl;
        return 1;
    }
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());

    cout << "autologin-cqu: started interval=" << CHECK_INTERVAL_SEC << "s" << endl;

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

    cout << "autologin-cqu: stopped" << endl;
    // ScopedCurl 和 CurlGlobal 会自动清理资源
    return 0;
}
