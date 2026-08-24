# AutoLogin-CQU 修改日志

## 2026-08-24: systemd 部署文档补充 TLS 校验与 CA_BUNDLE 说明

**范围**：`linux_systemd-setup.md`

**改动**：

1. 新增 `CA_BUNDLE` 配置项说明；`SERVER_IP` 补充 IPv6 不带方括号的写法约定
2. 新增「TLS 证书校验」章节，说明门户使用内部 CA / 自签名证书时升级必须配置 `CA_BUNDLE`
3. exit 78 行为说明补入 `CA_BUNDLE` 文件不可读的情形
4. 「登录失败」排查新增证书校验失败（curl error 60）条目
5. 移除 `TIMEOUT` 的过时描述「不保证限制系统 DNS 解析耗时」（DNS 现由 libcurl 内部处理，受 `TIMEOUT` 覆盖）

**验证**：与代码行为逐项核对（`CURLOPT_SSL_VERIFYPEER/VERIFYHOST`、`CURLOPT_CAINFO`、exit 78 路径、`config.yaml` 字段）
## 2025-01-12: Linux TLS 校验恢复 + SERVER_IP 连接语义修正

**范围**：`src/linux/AutoLogin-CQU.cpp`, `src/linux/config.yaml`

**改动**：

1. 恢复 TLS 证书校验（`CURLOPT_SSL_VERIFYPEER=1` / `CURLOPT_SSL_VERIFYHOST=2`）
2. 新增 `CA_BUNDLE` 配置项，支持校园网自签名证书 / 内部 CA；文件不可读时 exit 78
3. `SERVER_IP` 改用 `CURLOPT_RESOLVE` 固定连接地址，URL 始终使用域名 `login.cqu.edu.cn`
4. 显式设置 `Host: login.cqu.edu.cn`（无端口），与门户协议保持一致
5. 移除 `ResolveHostToIP` / `GetPortalAddress` / `TruncateForLog`，DNS 交由 libcurl 内部处理
6. 失败日志不再输出响应体
7. `config.yaml` 新增 `CA_BUNDLE` 字段及 `SERVER_IP` IPv6 格式注释

**验证**：

- `g++ -Wall -Wextra` 零警告
- 无配置 / 空账号 / CA_BUNDLE 不可读 → exit 78
- `git diff --check` 通过

**遗留**：

- 已部署环境升级后若门户使用非系统 CA 证书，需配置 `CA_BUNDLE`
