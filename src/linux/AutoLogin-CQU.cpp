#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <csignal>
#include <cstring>
#include <cctype>
#include <memory>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <fstream>
#include <algorithm>
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
struct Config
{
    string studentId;
    string password;
    string serverIp; // 可选：固定实际连接地址（IPv6 不带方括号）
    string loginIp;  // 可选：提交给门户的客户端 IPv4
    string caBundle; // 可选：自定义 CA 证书文件路径
    int checkIntervalSec = 20;
    long timeoutSec = 5;
};

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
    CurlGlobal() : ok_(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) {}
    ~CurlGlobal()
    {
        if (ok_)
            curl_global_cleanup();
    }

    bool ok() const
    {
        return ok_;
    }

private:
    bool ok_;
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
        else if (c == '#' && !inSingleQuote && !inDoubleQuote && (i == 0 || isspace(static_cast<unsigned char>(value[i - 1]))))
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

void ConfigError(int lineNo, const string &message)
{
    cerr << "autologin-cqu: error: config.yaml line " << lineNo << ": " << message << endl;
}

// value 为空时使用默认值；否则必须是位于 [minValue, maxValue] 内的完整整数
bool ParseBoundedLong(const string &value, long defaultValue, long minValue, long maxValue, const string &key, int lineNo, long &out)
{
    if (value.empty())
    {
        out = defaultValue;
        return true;
    }

    long parsed = 0;
    try
    {
        size_t parsedLength = 0;
        parsed = stol(value, &parsedLength);
        if (parsedLength != value.size())
        {
            ConfigError(lineNo, "invalid number for " + key + ": " + value);
            return false;
        }
    }
    catch (...)
    {
        ConfigError(lineNo, "invalid number for " + key + ": " + value);
        return false;
    }

    if (parsed < minValue || parsed > maxValue)
    {
        ConfigError(lineNo, key + " must be in [" + to_string(minValue) + ", " + to_string(maxValue) + "], got " + to_string(parsed));
        return false;
    }

    out = parsed;
    return true;
}

bool IsIPv4(const string &ip)
{
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

bool IsIPv6(const string &ip)
{
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip.c_str(), &addr) == 1;
}
// 加载并校验配置文件；任何错误已打印并返回 false（调用方以 exit 78 退出）
bool LoadConfig(const string &filename, Config &cfg)
{
    ifstream file(filename);
    if (!file.is_open())
    {
        cerr << "autologin-cqu: error: config.yaml not found or not readable" << endl;
        return false;
    }

    vector<string> seenKeys;
    string line;
    int lineNo = 0;
    while (getline(file, line))
    {
        ++lineNo;
        string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        size_t delimiterPos = trimmed.find(':');
        if (delimiterPos == string::npos)
        {
            ConfigError(lineNo, "invalid line (missing ':')");
            return false;
        }

        string key = Trim(trimmed.substr(0, delimiterPos));
        string value = UnquoteYamlValue(trimmed.substr(delimiterPos + 1));

        if (key.empty())
        {
            ConfigError(lineNo, "empty key");
            return false;
        }

        bool known = key == "STUDENT_ID" || key == "USER_PASSWORD" || key == "SERVER_IP" ||
                     key == "LOGIN_IP" || key == "CA_BUNDLE" || key == "CHECK_INTERVAL" || key == "TIMEOUT";
        if (!known)
        {
            ConfigError(lineNo, "unknown key: " + key);
            return false;
        }

        if (find(seenKeys.begin(), seenKeys.end(), key) != seenKeys.end())
        {
            ConfigError(lineNo, "duplicate key: " + key);
            return false;
        }
        seenKeys.push_back(key);

        if (key == "STUDENT_ID")
            cfg.studentId = value;
        else if (key == "USER_PASSWORD")
            cfg.password = value;
        else if (key == "SERVER_IP")
            cfg.serverIp = value;
        else if (key == "LOGIN_IP")
            cfg.loginIp = value;
        else if (key == "CA_BUNDLE")
            cfg.caBundle = value;
        else if (key == "CHECK_INTERVAL")
        {
            long parsed;
            if (!ParseBoundedLong(value, 20, 5, 3600, key, lineNo, parsed))
                return false;
            cfg.checkIntervalSec = static_cast<int>(parsed);
        }
        else // TIMEOUT
        {
            if (!ParseBoundedLong(value, 5, 1, 300, key, lineNo, cfg.timeoutSec))
                return false;
        }
    }

    if (cfg.studentId.empty() || cfg.password.empty())
    {
        cerr << "autologin-cqu: error: account or password not configured" << endl;
        return false;
    }
    if (cfg.studentId == "xxxxxxxx" || cfg.password == "xxxxxx")
    {
        cerr << "autologin-cqu: error: template placeholder not replaced, fill in real account and password" << endl;
        return false;
    }
    if (!cfg.loginIp.empty() && !IsIPv4(cfg.loginIp))
    {
        cerr << "autologin-cqu: error: LOGIN_IP must be a valid IPv4 address: " << cfg.loginIp << endl;
        return false;
    }
    if (!cfg.serverIp.empty() && !IsIPv4(cfg.serverIp) && !IsIPv6(cfg.serverIp))
    {
        cerr << "autologin-cqu: error: SERVER_IP must be a valid IP address (IPv6 without brackets): " << cfg.serverIp << endl;
        return false;
    }
    if (!cfg.caBundle.empty())
    {
        ifstream caFile(cfg.caBundle);
        if (!caFile.is_open())
        {
            cerr << "autologin-cqu: error: CA bundle not readable: " << cfg.caBundle << endl;
            return false;
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

// 严格读取 JSON 中指定名称的整数字段（容忍空格、可选引号和负号）。
// 与 Windows 版实现一致，保证两端响应分类规则相同。
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


string BuildLoginUrl(const Config &cfg, const string &loginIpv4, const string &ipv6)
{
    stringstream ss;
    ss << "https://" << LOGIN_HOST << ":" << LOGIN_PORT << LOGIN_PATH << "?"
       << "callback=dr1004"
       << "&login_method=1"
       << "&user_account=" << UrlEncode(",0," + cfg.studentId)
       << "&user_password=" << UrlEncode(cfg.password)
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

// ================= 地址选择 =================
// 第二阶段第 3 项：两端语义一致，见 AUDIT.md 第二阶段第 3 项

// 门户目的 IP：SERVER_IP 优先（字面 IP），否则解析门户域名（IPv4 优先，其次 IPv6）
bool ResolvePortalDestination(const Config &cfg, string &destIp)
{
    if (!cfg.serverIp.empty())
    {
        destIp = cfg.serverIp;
        return true;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    if (getaddrinfo(LOGIN_HOST.c_str(), NULL, &hints, &result) != 0 || result == NULL)
    {
        cerr << "autologin-cqu: warning: DNS resolution of " << LOGIN_HOST << " failed; falling back to heuristic address" << endl;
        return false;
    }
    unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> guard(result, freeaddrinfo);

    char ip[INET6_ADDRSTRLEN];
    for (struct addrinfo *p = result; p != NULL; p = p->ai_next)
    {
        if (p->ai_family != AF_INET)
            continue;
        if (inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, ip, sizeof(ip)) != NULL)
        {
            destIp = ip;
            return true;
        }
    }
    for (struct addrinfo *p = result; p != NULL; p = p->ai_next)
    {
        if (p->ai_family != AF_INET6)
            continue;
        if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, ip, sizeof(ip)) != NULL)
        {
            destIp = ip;
            return true;
        }
    }
    return false;
}

// 用 UDP connect 探测到目的地址的路由源地址（不实际发送报文）
bool ProbeRouteSource(const string &destIp, string &srcIp)
{
    struct sockaddr_storage dst;
    memset(&dst, 0, sizeof(dst));
    socklen_t dstLen;
    int family;
    if (IsIPv4(destIp))
    {
        family = AF_INET;
        ((struct sockaddr_in *)&dst)->sin_family = family;
        ((struct sockaddr_in *)&dst)->sin_port = htons(LOGIN_PORT);
        inet_pton(AF_INET, destIp.c_str(), &((struct sockaddr_in *)&dst)->sin_addr);
        dstLen = sizeof(struct sockaddr_in);
    }
    else if (IsIPv6(destIp))
    {
        family = AF_INET6;
        ((struct sockaddr_in6 *)&dst)->sin6_family = family;
        ((struct sockaddr_in6 *)&dst)->sin6_port = htons(LOGIN_PORT);
        inet_pton(AF_INET6, destIp.c_str(), &((struct sockaddr_in6 *)&dst)->sin6_addr);
        dstLen = sizeof(struct sockaddr_in6);
    }
    else
        return false;

    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;
    bool ok = false;
    struct sockaddr_storage src;
    socklen_t srcLen = sizeof(src);
    if (connect(fd, (struct sockaddr *)&dst, dstLen) == 0 &&
        getsockname(fd, (struct sockaddr *)&src, &srcLen) == 0)
    {
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr *)&src, srcLen, host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0)
        {
            srcIp = host;
            ok = true;
        }
    }
    close(fd);
    return ok;
}

// 找到包含 addr 的接口上另一个地址族的第一个地址（v6 要求全局，排除链路本地/未指定）
// 注：匹配遍历时不排除回环接口（self-test 依赖 127.0.0.1<->::1 命中 lo）；LOGIN_IP=127.x 属误配置
bool GetOtherFamilyOnInterface(const string &addr, int wantedFamily, string &out)
{
    out.clear();
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
        return false;
    unique_ptr<struct ifaddrs, void (*)(struct ifaddrs *)> guard(ifaddr, freeifaddrs);

    string ifname;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        int fam = ifa->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6)
            continue;
        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr,
                        (fam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
            continue;
        string h = host;
        size_t pos = h.find('%');
        if (pos != string::npos)
            h = h.substr(0, pos);
        if (h == addr)
        {
            ifname = ifa->ifa_name;
            break;
        }
    }
    if (ifname.empty())
        return false;

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || ifa->ifa_name == NULL || string(ifa->ifa_name) != ifname)
            continue;
        int fam = ifa->ifa_addr->sa_family;
        if (fam != wantedFamily)
            continue;
        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr,
                        (fam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
            continue;
        string h = host;
        size_t pos = h.find('%');
        if (pos != string::npos)
            h = h.substr(0, pos);
        if (wantedFamily == AF_INET6 && (strncmp(h.c_str(), "fe80", 4) == 0 || h == "::"))
            continue;
        out = h;
        return true;
    }
    return false;
}

// 地址选择：manual = LOGIN_IP 显式指定；route = 按到认证服务器的路由选定源地址；
// route-v4-fallback = 探测到 v6 路由但同接口无可用 IPv4，上报 IPv4 退回启发式；
// heuristic = 接口/网段启发式兜底。语义与 Windows 版一致（见 AUDIT.md 第二阶段第 3 项）。
bool GetLoginAddresses(const Config &cfg, string &loginIpv4, string &ipv6, string &addressSource)
{
    ipv6.clear();

    if (!cfg.loginIp.empty())
    {
        loginIpv4 = cfg.loginIp;
        if (!GetOtherFamilyOnInterface(loginIpv4, AF_INET6, ipv6))
            GetLocalIPv6(ipv6);
        addressSource = "manual";
        return true;
    }

    string dest;
    string src;
    if (ResolvePortalDestination(cfg, dest) && ProbeRouteSource(dest, src))
    {
        if (IsIPv4(src))
        {
            loginIpv4 = src;
            GetOtherFamilyOnInterface(src, AF_INET6, ipv6);
            addressSource = "route";
            return true;
        }
        // 探测结果为 IPv6：必须为全局地址（非链路本地）
        if (IsIPv6(src) && strncmp(src.c_str(), "fe80", 4) != 0)
        {
            ipv6 = src;
            if (GetOtherFamilyOnInterface(src, AF_INET, loginIpv4))
            {
                addressSource = "route";
                return true;
            }
            // 仅 v6 路由：IPv4 提交值退回启发式
            string fallbackIpv4;
            string fallbackIpv6;
            if (!GetLocalIPs(fallbackIpv4, fallbackIpv6))
            {
                cerr << "autologin-cqu: error: no local IPv4 available for login (v6 route only)" << endl;
                return false;
            }
            loginIpv4 = fallbackIpv4;
            addressSource = "route-v4-fallback";
            return true;
        }
    }

    // 兜底：接口/网段启发式；上报 v6 优先取所选 v4 同接口的全局 v6
    if (!GetLocalIPs(loginIpv4, ipv6))
    {
        cerr << "autologin-cqu: error: failed to get local IPv4 address" << endl;
        return false;
    }
    string sameIfaceV6;
    if (GetOtherFamilyOnInterface(loginIpv4, AF_INET6, sameIfaceV6))
        ipv6 = sameIfaceV6;
    addressSource = "heuristic";
    return true;
}


void PerformLogin(const Config &cfg, CURL *curl)
{
    string loginIpv4, ipv6, addressSource;
    if (!GetLoginAddresses(cfg, loginIpv4, ipv6, addressSource))
        return;

    string fullUrl = BuildLoginUrl(cfg, loginIpv4, ipv6);
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
        cout << "autologin-cqu: login success ip=" << loginIpv4 << " (" << addressSource << ")" << endl;
        break;
    case LoginResult::AlreadyOnline:
        cout << "autologin-cqu: already online ip=" << loginIpv4 << " (" << addressSource << ")" << endl;
        break;
    case LoginResult::Failed:
        // response_bytes 与截断标记辅助区分认证失败/HTML 错误页/代理错误页；响应正文默认不记录
        cerr << "autologin-cqu: login failed ip=" << loginIpv4 << " (" << addressSource << ")"
             << " response_bytes=" << response.size()
             << (response.size() >= MAX_RESPONSE_BYTES ? " (truncated)" : "") << endl;
        break;
    }
}

// ================= 自检：离线响应分类检查 =================
// 用法: ./AutoLogin-CQU --self-test （无需配置文件和网络；地址探测断言要求 IPv6 回环可用）
bool RunSelfTest()
{
    struct Case
    {
        const char *name;
        string body;
        LoginResult expected;
    };
    Case cases[] = {
        {"success", "{\"result\":1,\"message\":\"Welcome to Drcom System\"}", LoginResult::Success},
        {"success_whitespace", "{\"result\" : 1}", LoginResult::Success},
        {"success_field_order", "{\"message\":\"Welcome to Drcom System\",\"result\":1}", LoginResult::Success},
        {"success_quoted_value", "{\"result\":\"1\"}", LoginResult::Success},
        {"already_online_ret_code", "{\"result\":0,\"ret_code\":2,\"message\":\"already online\"}", LoginResult::AlreadyOnline},
        {"already_online_drcom", "{\"result\":0,\"ret_code\":1,\"message\":\"Welcome to Drcom System\"}", LoginResult::AlreadyOnline},
        {"auth_failure", "{\"result\":0,\"ret_code\":1,\"message\":\"user not exist\"}", LoginResult::Failed},
        {"result_prefix_must_not_match", "{\"result\":12}", LoginResult::Failed},
        {"ret_code_prefix_must_not_match", "{\"ret_code\":21}", LoginResult::Failed},
        {"empty_response", "", LoginResult::Failed},
        {"html_error_page", "<html><head><title>502 Bad Gateway</title></head><body>gateway error</body></html>", LoginResult::Failed},
        {"proxy_error_page", "Bad Gateway\r\nServer: proxy\r\n", LoginResult::Failed},
        {"truncated_early_field", string("{\"result\":1,") + string(6000, 'x'), LoginResult::Success},
        {"truncated_no_field", string(6000, 'x'), LoginResult::Failed},
    };

    int failedCount = 0;
    for (const Case &c : cases)
    {
        LoginResult got = ClassifyLoginResponse(c.body);
        if (got != c.expected)
        {
            ++failedCount;
            cerr << "self-test: FAIL " << c.name << " expected=" << static_cast<int>(c.expected)
                 << " got=" << static_cast<int>(got) << endl;
        }
    }
    // 地址选择：回环 UDP 探测应返回回环地址（不实际发送报文）
    string src;
    if (!(ProbeRouteSource("127.0.0.1", src) && src == "127.0.0.1"))
    {
        ++failedCount;
        cerr << "self-test: FAIL probe_ipv4_loopback got=" << src << endl;
    }
    src.clear();
    if (!(ProbeRouteSource("::1", src) && src == "::1"))
    {
        ++failedCount;
        cerr << "self-test: FAIL probe_ipv6_loopback got=" << src << endl;
    }
    // 门户目的 IP：SERVER_IP 优先于域名解析
    Config probeCfg;
    probeCfg.serverIp = "192.0.2.1";
    string dest;
    if (!(ResolvePortalDestination(probeCfg, dest) && dest == "192.0.2.1"))
    {
        ++failedCount;
        cerr << "self-test: FAIL resolve_server_ip got=" << dest << endl;
    }
    // 同接口地址查找：回环接口上 127.0.0.1 <-> ::1 双向可查
    string other;
    if (!(GetOtherFamilyOnInterface("127.0.0.1", AF_INET6, other) && other == "::1"))
    {
        ++failedCount;
        cerr << "self-test: FAIL same_iface_v6 got=" << other << endl;
    }
    other.clear();
    if (!(GetOtherFamilyOnInterface("::1", AF_INET, other) && other == "127.0.0.1"))
    {
        ++failedCount;
        cerr << "self-test: FAIL same_iface_v4 got=" << other << endl;
    }

    if (failedCount == 0)
        cout << "self-test: response classification and address selection checks passed" << endl;
    return failedCount == 0;
}

int main(int argc, char *argv[])
{
    // 离线自检（第二阶段第 5 项）：不需要配置文件和网络
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0)
        return RunSelfTest() ? 0 : 1;
    // 0. 加载并校验配置（任何错误 exit 78，由 systemd RestartPreventExitStatus 防止重启循环）
    Config cfg;
    if (!LoadConfig("config.yaml", cfg))
        return CONFIG_ERROR_EXIT_CODE;

    if (!cfg.loginIp.empty())
        cout << "autologin-cqu: using configured login ip=" << cfg.loginIp << endl;

    if (!cfg.serverIp.empty())
        cout << "autologin-cqu: using configured server ip=" << cfg.serverIp << endl;

    if (!cfg.caBundle.empty())
        cout << "autologin-cqu: using CA bundle " << cfg.caBundle << endl;
    // 1. 信号处理
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SignalHandler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // 2. 初始化 Libcurl
    CurlGlobal curlGlobal;
    if (!curlGlobal.ok())
    {
        cerr << "autologin-cqu: error: curl global init failed" << endl;
        return 1;
    }

    ScopedCurl curl(curl_easy_init());
    if (!curl)
    {
        cerr << "autologin-cqu: error: curl init failed" << endl;
        return 1;
    }

    // 3. 设置 libcurl 选项
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, cfg.timeoutSec);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl.get(), CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    if (!cfg.caBundle.empty())
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, cfg.caBundle.c_str());
    // 设置 SERVER_IP 时通过 CURLOPT_RESOLVE 固定连接目标（绕过 DNS，Host 头保持 LOGIN_HOST）
    // 注意：CURLOPT_RESOLVE 要求 curl_slist*，且 libcurl 不深拷贝该列表，
    // 列表必须在 handle 生命周期内保持存活（在 main 作用域声明，与下方 headers 一致），
    // 否则 curl_easy_perform 读取已释放的列表，触发间歇性段错误。
    unique_ptr<curl_slist, decltype(&curl_slist_free_all)> resolveList(nullptr, curl_slist_free_all);
    if (!cfg.serverIp.empty())
    {
        string resolveEntry = LOGIN_HOST + ":" + to_string(LOGIN_PORT) + ":" + cfg.serverIp;
        if (cfg.serverIp.find(':') != string::npos)
            resolveEntry = LOGIN_HOST + ":" + to_string(LOGIN_PORT) + ":[" + cfg.serverIp + "]";
        resolveList.reset(curl_slist_append(NULL, resolveEntry.c_str()));
        if (!resolveList)
        {
            cerr << "autologin-cqu: error: curl resolve init failed" << endl;
            return 1;
        }
        curl_easy_setopt(curl.get(), CURLOPT_RESOLVE, resolveList.get());
    }
    // 显式设置 Host 头（不带端口，与门户协议保持一致）
    unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(curl_slist_append(NULL, ("Host: " + LOGIN_HOST).c_str()), curl_slist_free_all);
    if (!headers)
    {
        cerr << "autologin-cqu: error: curl header init failed" << endl;
        return 1;
    }
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());

    cout << "autologin-cqu: started interval=" << cfg.checkIntervalSec << "s" << endl;

    // 4. 主循环
    while (g_running)
    {
        PerformLogin(cfg, curl.get());

        // 睡眠等待
        // 如果收到信号，sleep 会被中断并返回剩余秒数，循环条件 g_running 变为 0，从而优雅退出
        if (g_running)
        {
            sleep(cfg.checkIntervalSec);
        }
    }

    cout << "autologin-cqu: stopped" << endl;
    // ScopedCurl 和 CurlGlobal 会自动清理资源
    return 0;
}
