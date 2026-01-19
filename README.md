# AutoLogin-CQU (校园网自动登录工具)

一个轻量级、高性能、多平台、高易用的校园网自动认证工具，旨在解决校园网频繁掉登录状态、登录网页不弹出、登录网页异常等校园网连接问题。本项目包含 **Python 通用版** 以及基于系统 API 的 **C++ Windows/Linux 高性能版**。
- **注意：Python 版本不再维护**

## **项目背景与设计理念**

本项目起源于对网络上开源 Python 登录脚本的需求：ipv6 支持、DoH 支持、绕过代理、性能优化、处理逻辑完善、简单易用、多平台支持。目标是创建一个**不依赖大型运行时环境**、**配置分离**、且**资源占用极低**的**常驻后台工具**。

**核心特性：**
- **配置分离**：账号信息和常规设置与核心代码严格分离，配置文件 `config.ini` 独立于可运行文件
- **多平台支持**：提供 Windows (.exe) 和 Linux 二进制可执行文件
- **高性能 C++ 实现**：调用系统 api，依赖项少；优化连接、检查、重试等逻辑
- **界面与输出优化**：Windows 版本支持前/后台任务模式切换，信息输出详细；Linux 版本专为 systemd 后台任务优化，输出符合 Linux 日志规范

---

##  **快速开始**

#### 方案 A: 使用 C++ (推荐) ~~或 Python 预编译~~版本
~~*( Python 版本仅提供 Windows 下的可执行文件)*~~

无需安装任何环境，直接下载运行。

**Windows 用户:**
1. 下载 `AutoLogin-CQU_Windows_CPP.zip` ( C++ 版本) ~~或 `AutoLogin-CQU_Windows_Python.zip` ( Python 版本)~~
2. 解压，**确保 `config.ini` 与 `AutoLogin-CQU.exe` 在同一目录**
3. 使用记事本编辑 ``config.ini`` ，按照注释的提示**补全上网账号信息**
4. 双击运行 `AutoLogin-CQU.exe`

**Linux 用户:**
1. 下载 `AutoLogin-CQU_Linux_CPP.tar.gz`
2. 解压并赋予执行权限，**确保 `config.ini` 与 `AutoLogin-CQU` 在同一目录**
3. 编辑 ``config.ini`` ，按照注释的提示**补全上网账号信息**
4. **安装 `curl` 依赖包**
5. 在终端运行 `AutoLogin-CQU`（不推荐，建议配置 systemd 启动项，请参考`linux_systemd-setup.md`）

#### 方案 B: 使用 Python 脚本
- **注意：不再维护**

适用于所有安装了 Python 环境的系统。

1. 从仓库获取源码 (位于 `/src/python` )
2. 编辑 ``config.ini`` ，按照注释的提示补全上网账号信息
3. 使用 Python 运行 `AutoLogin-CQU.py`

---

## **许可证**

本项目基于 [MIT License](https://www.google.com/search?q=LICENSE) 开源。