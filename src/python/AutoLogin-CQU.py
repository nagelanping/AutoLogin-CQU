import socket
import time
import os
import sys
import configparser
from urllib.parse import urlencode

import requests

# 读取配置文件
config = configparser.ConfigParser()

# 获取当前脚本所在目录，兼容 PyInstaller 打包后的 exe 路径
if getattr(sys, "frozen", False):
    # 如果是打包后的 exe
    current_dir = os.path.dirname(sys.executable)
else:
    # 如果是脚本运行
    current_dir = os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(current_dir, "config.ini")

if not os.path.exists(config_path):
    print(f"错误: 找不到配置文件 {config_path}")
    # 可以选择在这里退出或者使用默认值，这里为了安全起见，如果找不到配置应该提示用户
    # 但为了保持代码结构简单，这里仅打印错误

config.read(config_path, encoding="utf-8")

# 配置常量
LOGIN_URL = "https://login.cqu.edu.cn:802/eportal/portal/login"

try:
    settings = config["Settings"]
    USER_ACCOUNT = settings.get("USER_ACCOUNT", "")
    USER_PASSWORD = settings.get("USER_PASSWORD", "")
    CHECK_INTERVAL = settings.getint("CHECK_INTERVAL", 20)
    TIMEOUT = settings.getint("TIMEOUT", 5)
except KeyError:
    print("错误: 配置文件格式不正确，缺少 [Settings] 部分")
    USER_ACCOUNT = ""
    USER_PASSWORD = ""
    CHECK_INTERVAL = 20
    TIMEOUT = 5


def get_local_ip():
    """获取本机IPv4和IPv6地址。"""
    hostname = socket.gethostname()
    ipv4 = ipv6 = ""

    try:
        ip_list = socket.gethostbyname_ex(hostname)[-1]
        ipv4 = ip_list[0] if ip_list else ""
    except socket.gaierror as e:
        print(f"获取IPv4地址失败: {e}")

    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
            addr = info[4][0]
            if not addr.startswith(("fe80:", "::1")):
                ipv6 = addr
                break
    except socket.gaierror:
        pass

    return ipv4, ipv6


def build_login_url(user_ip, user_ipv6=""):
    """构建登录URL"""
    params = {
        "callback": "dr1004",
        "login_method": "1",
        "user_account": USER_ACCOUNT,
        "user_password": USER_PASSWORD,
        "wlan_user_ip": user_ip,
        "wlan_user_ipv6": user_ipv6,
        "wlan_user_mac": "000000000000",
        "wlan_ac_ip": "",
        "wlan_ac_name": "",
        "term_ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
        "term_type": "1",
        "jsVersion": "4.2.2",
        "terminal_type": "1",
        "lang": "zh-cn,zh",
        "v": "6231",
    }
    return f"{LOGIN_URL}?{urlencode(params)}"


def main():
    """主函数，循环检测网络连接并尝试自动登录"""
    ipv4, ipv6 = get_local_ip()

    if not ipv4:
        print("错误：无法获取到本机IPv4地址，程序退出。")
        return

    if not ipv6:
        print("警告：未能获取到有效的IPv6地址，将仅使用IPv4尝试登录。")

    login_url = build_login_url(ipv4, ipv6)
    print(f"将使用 IPv4: {ipv4} 和 IPv6: {ipv6 or 'N/A'} 尝试登录...")

    session = requests.Session()
    session.trust_env = False

    while True:
        try:
            resp = session.get(login_url, timeout=TIMEOUT)
            status = (
                "网络连接正常或已成功登录。" if resp.ok else "网络连接异常，正在重试..."
            )
        except requests.RequestException as e:
            status = f"请求错误: {e}"

        print(status)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
