# AutoLogin-CQU (校园网自动登录工具)

一个轻量级、高性能、多平台、高易用的校园网自动认证工具，旨在解决校园网频繁掉登录状态、登录网页不弹出、登录网页异常等校园网连接问题。本项目提供基于系统 API 的 **C++ Windows/Linux 版本**。

- **Python 版本不再维护**

## **项目背景与设计理念**

项目目标是提供支持 IPv6、DNS 绕过、代理绕过和多平台运行的校园网认证工具，同时保持**配置分离**和较低资源占用。

**核心特性：**

- **配置分离**：账号信息和常规设置与核心代码严格分离，配置文件独立于可运行文件
- **多平台支持**：提供 Windows (.exe) 和 Linux 二进制可执行文件
- **高性能 C++ 实现**：调用系统 api，依赖项少；优化连接、检查、重试等逻辑
- **界面与输出优化**：Windows 版本支持前/后台任务模式切换，信息输出详细；Linux 版本专为 systemd 后台任务优化，输出符合 Linux 日志规范

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

---

## **许可证**

本项目基于 [MIT License](https://www.google.com/search?q=LICENSE) 开源。
