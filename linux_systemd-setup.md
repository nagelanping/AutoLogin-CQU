# AutoLogin-CQU 开机启动配置教程

本教程指导如何将 AutoLogin-CQU 配置为 systemd 开机自启服务

## 前置条件

- 已获取 `AutoLogin-CQU` 可执行程序（Linux 版本）
- 拥有 sudo 权限
- **已正确配置 `config.ini` 文件**

## 创建 Systemd 服务文件

### 编辑服务文件模板

编辑 `autologin-cqu.service` 文件，替换以下占位符：

| 占位符             | 说明          | 常见示例                                                                         |
| --------------- | ----------- | ---------------------------------------------------------------------------- |
| `<USERNAME>`    | 运行服务的用户名    | 你的用户名、root                                                                   |
| `<PROGRAM_DIR>` | 程序所在目录的绝对路径 | `/home/用户名/AutoLogin-CQU_Linux_CPP`、`/usr/local/bin/AutoLogin-CQU_Linux_CPP` |

**示例 1：以 root 用户运行（简化配置）**

假设：
- 用户名为 `root`
- 程序路径为 `/usr/local/bin/AutoLogin-CQU_Linux_CPP`

则服务文件应为：

```ini
[Unit]
Description=CQU Campus Network Auto-Login Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin/AutoLogin-CQU_Linux_CPP
ExecStart=/usr/local/bin/AutoLogin-CQU_Linux_CPP/AutoLogin-CQU
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=AutoLogin-CQU

[Install]
WantedBy=multi-user.target
```

**示例 2：以普通用户运行**

假设：
- 用户名为 `abc`
- 程序路径为 `/home/abc/AutoLogin-CQU_Linux_CPP`

则服务文件应为：

```ini
[Unit]
Description=CQU Campus Network Auto-Login Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=abc
WorkingDirectory=/home/abc/AutoLogin-CQU_Linux_CPP
ExecStart=/home/abc/AutoLogin-CQU_Linux_CPP/AutoLogin-CQU
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=AutoLogin-CQU

[Install]
WantedBy=multi-user.target
```

### 将服务文件复制到系统目录

```bash
sudo cp autologin-cqu.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/autologin-cqu.service
```

### 重新加载 systemd 配置

```bash
sudo systemctl daemon-reload
```

## 配置文件权限（普通用户）

为确保 systemd 服务能正确读取配置文件，请设置合适的权限：

```bash
# 假设程序目录为 /home/abc/AutoLogin-CQU_Linux_CPP
cd /home/abc/AutoLogin-CQU_Linux_CPP

# 配置文件权限（只有所有者可读）
chmod 600 config.ini

# 程序文件权限（可执行）
chmod 755 AutoLogin-CQU
```

## 启动和管理服务

### 启动服务

```bash
sudo systemctl start autologin-cqu
```

### 查看服务状态

```bash
sudo systemctl status autologin-cqu
```

### 启用开机自启

```bash
sudo systemctl enable autologin-cqu
```

### 查看实时日志

```bash
sudo journalctl -u autologin-cqu -f
```

### 停止服务

```bash
sudo systemctl stop autologin-cqu
```

### 禁用开机自启

```bash
sudo systemctl disable autologin-cqu
```

## 故障排查

### 问题 1：服务无法启动

**检查方案：**

```bash
# 查看详细错误信息
sudo systemctl status autologin-cqu
sudo journalctl -u autologin-cqu -n 50

# 检查文件路径是否正确
ls -la /home/abc/AutoLogin-CQU_Linux_CPP
```

### 问题 2：提示找不到 config.ini

**解决方案：**

- 确保 `config.ini` 与 `AutoLogin-CQU` 在同一目录
- 在服务文件中设置正确的 `WorkingDirectory`

```bash
pwd  # 确认当前目录
ls -la config.ini AutoLogin-CQU
```

### 问题 3：权限不足

**解决方案：**

```bash
# 检查文件权限
ls -la /home/abc/AutoLogin-CQU_Linux_CPP
stat config.ini

# 修复权限
chmod 600 config.ini
chmod 755 AutoLogin-CQU
```

### 问题 4：登录失败

**检查方案：**

```bash
# 查看详细日志
sudo journalctl -u autologin-cqu -n 100

# 检查网络连接
ping login.cqu.edu.cn
nslookup login.cqu.edu.cn

# 尝试手动运行程序
cd /home/abc/AutoLogin-CQU_Linux_CPP
./AutoLogin-CQU
```

## 常见问题 FAQ

**Q: `WorkingDirectory` 和 `ExecStart` 的区别是什么？**  
A: 
- `ExecStart` 是执行的程序文件路径
- `WorkingDirectory` 是程序运行时的工作目录，config.ini 必须在此目录下
- 两个路径通常相同

**Q: 服务修改后需要重新启动吗？**  
A: 修改 `.service` 文件后，需要运行 `sudo systemctl daemon-reload`，然后 `sudo systemctl restart autologin-cqu`

**Q: 如何检查自启是否生效？**  
A: 查看输出：`sudo systemctl is-enabled autologin-cqu`，应显示 `enabled`

**Q: 日志在哪里？**  
A: 系统日志存储在 `/var/log/journal/`，用 `journalctl` 命令查看。使用 `SyslogIdentifier=AutoLogin-CQU` 可在日志中快速识别该服务的输出

---

配置完成后，AutoLogin-CQU 将在系统启动时自动运行，并在后台持续保证网络连接
