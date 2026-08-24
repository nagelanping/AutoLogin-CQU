# AutoLogin-CQU Linux systemd 配置说明

本文说明如何将 Linux 版 AutoLogin-CQU 配置为 systemd 服务。Linux 版程序从进程工作目录读取 `config.yaml`，因此 `WorkingDirectory` 必须指向同时包含 `AutoLogin-CQU` 和 `config.yaml` 的目录。

## 前置条件

- 已获取 Linux 版 `AutoLogin-CQU` 可执行文件。
- 已编辑 `config.yaml`，并确认 `STUDENT_ID`、`USER_PASSWORD` 正确。
- 系统已安装 libcurl 运行库。源码编译还需要 C++ 编译器和 libcurl 开发头文件。
- 拥有 sudo 权限。

Arch Linux 上 libcurl 由 `curl` 包提供；如缺失，请按发行版标准手动安装系统包。

## 推荐安装方式：专用低权限用户

推荐把程序放在 `/opt/autologin-cqu`，并使用专用系统用户运行。这样比 root 运行更稳妥，也避免 home 目录加密、网络挂载或未登录时不可用导致开机启动失败。

```bash
sudo install -d -o root -g root -m 755 /opt/autologin-cqu
sudo cp AutoLogin-CQU config.yaml /opt/autologin-cqu/
sudo useradd --system --home-dir /opt/autologin-cqu --shell /usr/bin/nologin autologin-cqu
sudo chown root:autologin-cqu /opt/autologin-cqu
sudo chmod 750 /opt/autologin-cqu
sudo chown root:root /opt/autologin-cqu/AutoLogin-CQU
sudo chmod 755 /opt/autologin-cqu/AutoLogin-CQU
sudo chown root:autologin-cqu /opt/autologin-cqu/config.yaml
sudo chmod 640 /opt/autologin-cqu/config.yaml
```

如果发行版没有 `/usr/bin/nologin`，可用 `command -v nologin` 确认实际路径，再替换命令中的 shell 路径。

## 编辑 service 文件

编辑 `autologin-cqu.service`，替换以下占位符：

| 占位符 | 说明 | 推荐值 |
| --- | --- | --- |
| `<USERNAME>` | 运行服务的用户 | `autologin-cqu` |
| `<PROGRAM_DIR>` | 程序目录的绝对路径 | `/opt/autologin-cqu` |

推荐配置如下：

```ini
[Unit]
Description=CQU Campus Network Auto-Login Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=5min
StartLimitBurst=3

[Service]
Type=simple
User=autologin-cqu
WorkingDirectory=/opt/autologin-cqu
ExecStart=/opt/autologin-cqu/AutoLogin-CQU

Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=78

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
CapabilityBoundingSet=

StandardOutput=journal
StandardError=journal
SyslogIdentifier=AutoLogin-CQU

[Install]
WantedBy=multi-user.target
```

说明：

- `WorkingDirectory` 必须是 `config.yaml` 所在目录，否则程序无法读取配置。
- `RestartPreventExitStatus=78` 用于配置错误时停止反复重启；缺少配置或账号密码为空会直接失败并保留日志。
- `ProtectSystem=full` 会保护系统目录不被服务写入，但不影响读取 `/opt/autologin-cqu/config.yaml` 或发起网络请求。
- 如确认程序不放在 `/home` 下，可额外添加 `ProtectHome=true` 强化隔离。

## 安装 service

从包含 `autologin-cqu.service` 的目录执行：

```bash
sudo cp autologin-cqu.service /etc/systemd/system/autologin-cqu.service
sudo chmod 644 /etc/systemd/system/autologin-cqu.service
```

安装前建议检查占位符是否已经替换：

```bash
if grep -q '<.*>' /etc/systemd/system/autologin-cqu.service; then
  echo 'service 文件仍有未替换的占位符'
fi
```

验证 unit 语法和基础路径：

```bash
sudo systemd-analyze verify /etc/systemd/system/autologin-cqu.service
sudo -u autologin-cqu test -r /opt/autologin-cqu/config.yaml
sudo -u autologin-cqu test -x /opt/autologin-cqu/AutoLogin-CQU
```

重新加载 systemd：

```bash
sudo systemctl daemon-reload
```

## 启动和管理

```bash
sudo systemctl start autologin-cqu
sudo systemctl status autologin-cqu --no-pager
sudo systemctl enable autologin-cqu
```

查看日志：

```bash
sudo journalctl -u autologin-cqu -n 100 --no-pager
sudo journalctl -u autologin-cqu -f
```

停止或禁用：

```bash
sudo systemctl stop autologin-cqu
sudo systemctl disable autologin-cqu
```

修改 `config.yaml` 后只需要重启服务：

```bash
sudo systemctl restart autologin-cqu
```

修改 `.service` 文件后需要重新加载 unit，再重启服务：

```bash
sudo systemctl daemon-reload
sudo systemctl restart autologin-cqu
```

## home 目录安装

如果确实要把程序放在普通用户 home 目录，例如 `/home/abc/AutoLogin-CQU_Linux_CPP`，service 可设置为：

```ini
User=abc
WorkingDirectory=/home/abc/AutoLogin-CQU_Linux_CPP
ExecStart=/home/abc/AutoLogin-CQU_Linux_CPP/AutoLogin-CQU
```

同时确保该用户能遍历目录并读取配置：

```bash
sudo chown abc:abc /home/abc/AutoLogin-CQU_Linux_CPP/config.yaml
sudo chmod 600 /home/abc/AutoLogin-CQU_Linux_CPP/config.yaml
sudo chmod 755 /home/abc/AutoLogin-CQU_Linux_CPP/AutoLogin-CQU
sudo -u abc test -r /home/abc/AutoLogin-CQU_Linux_CPP/config.yaml
sudo -u abc test -x /home/abc/AutoLogin-CQU_Linux_CPP/AutoLogin-CQU
```

不建议在加密 home、网络挂载 home 或必须登录后才可访问的目录中配置开机自启服务。

- 如果使用 User 级 systemctl, 删除 .service 文件中 `User=<USERNAME>` 这一行

## root 运行

root 运行通常没有必要。程序只需要读取配置文件并发起出站 HTTPS 请求，不需要特权端口、网卡配置或额外 capability。只有在临时排查权限问题时才建议短时间改为 `User=root` 验证。

## 网络启动顺序

service 使用：

```ini
After=network-online.target
Wants=network-online.target
```

这只表示等待 systemd 认为网络 online。是否真的等待到地址/DNS 可用，取决于系统是否启用了对应的 wait-online 服务。

常见检查命令：

```bash
systemctl is-enabled NetworkManager-wait-online.service
systemctl is-enabled systemd-networkd-wait-online.service
```

如果使用 NetworkManager，可按需启用：

```bash
sudo systemctl enable --now NetworkManager-wait-online.service
```

如果使用 systemd-networkd，可按需启用：

```bash
sudo systemctl enable --now systemd-networkd-wait-online.service
```

即使启动早于校园网门户可用，程序也会按 `CHECK_INTERVAL` 周期重试。启动初期偶发 `warning: DNS resolution of login.cqu.edu.cn failed; falling back to heuristic address`，或 libcurl 的域名解析失败消息（如 `Could not resolve host`），不一定代表 service 配置错误。设置 `SERVER_IP` 后程序绕过 DNS 解析，不会出现上述消息。

## 配置项说明

`config.yaml` 必须与 `AutoLogin-CQU` 位于同一工作目录。

- `STUDENT_ID`：学号。
- `USER_PASSWORD`：校园网密码。
- `SERVER_IP`：认证服务器 IP。填写后跳过 `login.cqu.edu.cn` 的 DNS 解析，但请求仍发送 `Host: login.cqu.edu.cn`。IPv6 地址直接填写，不带方括号。
- `CA_BUNDLE`：CA 证书文件路径（可选）。门户证书不在系统 CA 中时使用；文件不可读时以退出码 `78` 失败。
- `LOGIN_IP`：提交给认证服务器的客户端 IPv4。路由器/NAT 代登录场景可能需要；普通主机通常留空。
- `CHECK_INTERVAL`：检查间隔（秒），有效范围 5-3600，默认 20；非法或超范围以退出码 `78` 失败。
- `TIMEOUT`：libcurl 请求超时（秒），有效范围 1-300，默认 5；非法或超范围以退出码 `78` 失败。

配置校验：`config.yaml` 由程序内建的简单校验读取。以下任一情况都会打印错误（含行号与原因）并以退出码 `78` 失败：文件缺失、非法行、空键、未知键、重复键、账号或密码为空、未替换的模板占位符（`xxxxxxxx`/`xxxxxx`）、`LOGIN_IP` 非合法 IPv4、`SERVER_IP` 非合法 IP、`CA_BUNDLE` 指向的文件不可读、数值超范围。

DNS 排查：

```bash
getent hosts login.cqu.edu.cn
nslookup login.cqu.edu.cn
# 如系统安装了 bind/dnsutils，也可使用 dig
dig login.cqu.edu.cn
```

## TLS 证书校验

程序启用 TLS 证书与主机名校验（`SSL_VERIFYPEER=1` / `SSL_VERIFYHOST=2`）。门户证书由系统 CA 签发时无需任何配置。

从旧版本升级时注意：若门户使用校园内部 CA 或自签名证书，升级后必须设置 `CA_BUNDLE` 指向 CA 证书文件，否则连接会因证书校验失败而持续失败。证书文件对运行服务的用户可读即可。

## 故障排查

### 服务无法启动

```bash
sudo systemctl status autologin-cqu --no-pager
sudo journalctl -u autologin-cqu -n 100 --no-pager
sudo systemd-analyze verify /etc/systemd/system/autologin-cqu.service
```

重点检查：

- `/etc/systemd/system/autologin-cqu.service` 中是否还有 `<USERNAME>` 或 `<PROGRAM_DIR>`。
- `WorkingDirectory` 是否为绝对路径，并指向 `config.yaml` 所在目录。
- `AutoLogin-CQU` 是否存在且可执行。
- 运行服务的用户是否能读取 `config.yaml`。

### 配置错误后不自动重启

这是预期行为。任何配置错误（`config.yaml` 缺失、非法行、未知/重复键、账号密码为空或未替换模板占位符、IP 格式非法、数值超范围、`CA_BUNDLE` 不可读）都会返回退出码 `78`，service 通过 `RestartPreventExitStatus=78` 停止反复重启。具体错误原因（含行号）可用 `journalctl -u autologin-cqu` 查看。修复配置后执行：

```bash
sudo systemctl restart autologin-cqu
```

### 权限不足

```bash
sudo namei -l /opt/autologin-cqu/config.yaml
sudo -u autologin-cqu test -r /opt/autologin-cqu/config.yaml
sudo -u autologin-cqu test -x /opt/autologin-cqu/AutoLogin-CQU
```

如果使用 home 目录安装，把命令中的用户和路径替换为实际值。

### 缺少 libcurl

如果日志或 `systemctl status` 显示动态库加载失败，检查二进制依赖：

```bash
ldd /opt/autologin-cqu/AutoLogin-CQU
```

缺少系统库时，请按发行版标准安装 libcurl 运行库。Arch Linux 上由 `curl` 包提供。

### 登录失败

```bash
sudo journalctl -u autologin-cqu -n 100 --no-pager
getent hosts login.cqu.edu.cn
cd /opt/autologin-cqu
sudo -u autologin-cqu ./AutoLogin-CQU
```

日志中的 `ip=...` 是程序选择并提交给门户的本机 IPv4，括号内标签表示该地址的来源：`manual` 为 `LOGIN_IP` 显式指定；`route` 为按到认证服务器的路由选定源地址；`route-v4-fallback` 为路由探测仅得到 IPv6 且同接口无可用 IPv4，上报 IPv4 退回启发式选定；`heuristic` 为按接口/网段启发式选定。多网卡、VPN、容器或路由器/NAT 环境下，如果该地址不是预期地址，可考虑在 `config.yaml` 中设置 `LOGIN_IP`。

如果日志显示证书校验失败（如 curl error 60 `certificate verify failed`），说明门户证书不在系统 CA 中，设置 `CA_BUNDLE` 指向对应的 CA 证书文件后重启服务。

## 日志与隐私

service 输出进入 systemd journal。日志可能包含本机 IP 和门户返回片段；不要在公共渠道直接粘贴完整日志。`config.yaml` 包含账号和密码，应保持最小可读权限。

## 卸载

```bash
sudo systemctl disable --now autologin-cqu
sudo rm -f /etc/systemd/system/autologin-cqu.service
sudo systemctl daemon-reload
sudo systemctl reset-failed autologin-cqu
```

如果使用推荐的专用用户和 `/opt/autologin-cqu`，确认不再需要配置后再删除：

```bash
sudo rm -rf /opt/autologin-cqu
sudo userdel autologin-cqu
```
