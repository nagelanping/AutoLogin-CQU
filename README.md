# AutoLogin-CQU (校园网自动登录工具)

校园网自动认证工具，定时向门户重发认证请求以保持登录状态，针对登录网页不弹出、登录网页异常、频繁掉登录状态等场景。提供 Windows 与 Linux 的 C++ 版本。

- **Python 版本不再维护**

## **项目背景与设计理念**

项目目标是提供在 Windows 与 Linux 上运行的校园网认证工具，支持 IPv6、通过 `SERVER_IP` 绕过 DNS 解析、以及不经过系统代理直连门户。配置文件与可执行文件分离。

**核心特性：**

- **配置分离**：账号信息和常规设置与核心代码严格分离，配置文件独立于可运行文件
- **多平台支持**：提供 Windows (.exe) 和 Linux 二进制可执行文件
- **C++ 实现**：Windows 版基于 WinHTTP 系统 API，Linux 版依赖 libcurl
- **运行模式**：Windows 版可把控制台隐藏到托盘（后台）或还原（前台）；Linux 版面向 systemd 后台服务，输出进入 systemd journal

---

## **快速开始**

### 使用 C++

预编译版本无需大型运行时环境；Linux 版本需要系统提供 libcurl 运行库。

**Windows 用户:**

1. 下载 `AutoLogin-CQU_Windows_CPP.zip`
2. 解压，**确保 `config.yaml` 与 `AutoLogin-CQU.exe` 在同一目录**
3. 使用记事本编辑 ``config.yaml`` ，按照注释的提示**补全上网账号信息**
4. 双击运行 `AutoLogin-CQU.exe`

**Linux 用户:**

1. 下载 `AutoLogin-CQU_Linux_CPP.tar.gz`
2. 解压并赋予执行权限，**确保 `config.yaml` 与 `AutoLogin-CQU` 在同一目录**
3. 编辑 ``config.yaml`` ，按照注释的提示**补全上网账号信息**
4. 确认系统已安装 libcurl 运行库（Arch Linux 由 `curl` 包提供）
5. 进入解压目录后运行 `./AutoLogin-CQU`（不推荐长期手动运行，建议配置 systemd 启动项，请参考 `linux_systemd-setup.md`）

离线自检：`./AutoLogin-CQU --self-test` 在不读取配置文件、不访问网络的情况下校验响应分类与本机地址选择逻辑，全部通过时退出码为 `0`。可用于部署前确认二进制在目标系统可正常运行。

---

## **许可证**

本项目基于 [MIT License](LICENSE) 开源。
