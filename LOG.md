# AutoLogin-CQU 修改日志

## 2026-08-24: 响应分类统一（Linux 移植 Windows 严格实现）+ 离线自检

**范围**：`src/linux/AutoLogin-CQU.cpp`, `AUDIT.md`

**改动**（第二阶段第 2、5 项）：

1. 将 Windows 版严格 JSON 整数字段读取 `ContainsJsonIntField` 逐字移植到 Linux，重写 `ClassifyLoginResponse`；两端分类规则逐字节一致
   - 消除旧实现的两个误判：`"result":12` 被前缀匹配误判为成功；`"result": 1`（冒号后带空格）漏判
   - 现在支持：空格容忍、引号值、负号、完整整数边界（`12`≠`1`）
2. `PerformLogin` Failed 日志增加 `response_bytes=N` 与达到 4096 上限时的 `(truncated)` 截断标记（§5.2 要求标记截断）；响应正文默认不记录（§5.6）
3. 新增 `./AutoLogin-CQU --self-test`：14 例离线响应分类自检（成功/空格/字段顺序/引号值/ret_code 已在线/Drcom 已在线/认证失败/前缀不匹配/空响应/HTML 错误页/代理错误页/截断两种），覆盖 §5.2 点名的全部样例；任一失败退出 1，全过退出 0；不加载配置、不初始化 curl、不触网
4. 新增 `#include <cctype>`（`isspace`/`isdigit`）

**验证**：

- `g++ -Wall -Wextra` 零警告
- `--self-test` 14/14 通过；篡改一个期望值后正确报 FAIL 且退出 1（失败路径验证）
- 真实门户冒烟：启动→`already online`→SIGTERM 优雅退出
- 子代理审查：移植与 Windows 逐字节一致（diff 确认），14 例断言与统一规则自洽，无行为回归；4 条 P3 备注均维持现状
- `git diff --check` 通过

**遗留**：

- Windows 侧默认输出响应正文需按 §5.6 改为调试选项门控（两端一起做）
- 非 JSON 响应正文恰好含字面 `"result":1` 序列会误判（有效 JSON 无此风险；两端一致，§5.2 接受的小而严格路线）

## 2026-08-24: Linux 配置严格校验 + Config 结构

**范围**：`src/linux/AutoLogin-CQU.cpp`, `src/linux/config.yaml`, `linux_systemd-setup.md`, `AUDIT.md`, `.gitignore`

**改动**：

1. 引入 `Config` 值结构，删除全部全局可写配置变量（第二阶段第 4 项）
2. 配置校验统一进 `LoadConfig`，任何错误打印行号与原因后 exit 78：
   - 文件缺失/不可读、非法行（无 `:`）、空键、未知键、重复键
   - 账号或密码为空、未替换的模板占位符（`xxxxxxxx`/`xxxxxx`）
   - `LOGIN_IP` 非合法 IPv4；`SERVER_IP` 非合法 IP（IPv6 不带方括号，`inet_pton` 校验）
   - `CHECK_INTERVAL` 范围 5-3600、`TIMEOUT` 范围 1-300，非法数值不再静默回退默认值
   - `CA_BUNDLE` 非空时文件必须可读（检查从 `main` 移入配置校验）
3. `curl_global_init` 失败退出 1，成功时才执行 `curl_global_cleanup`
4. 删除静默回退的 `ParsePositiveLong` 与未使用的 `<limits>` 头文件
5. `config.yaml` 模板注释标注有效范围；部署文档同步校验规则与 exit 78 错误清单；`.gitignore` 忽略构建产物

**验证**：

- `g++ -Wall -Wextra` 零警告
- 17 个错误路径逐项返回 78（行号错误信息正确）；合法配置启动，SIGTERM 优雅退出
- 子代理审查：无阻塞问题；确认 URL 构造、TLS、RESOLVE、日志输出无行为回归
- `git diff --check` 通过

**遗留**：

- Windows 侧配置校验规则对齐（第二阶段第 1 项剩余部分）
- 存量部署若使用超范围值（如 `CHECK_INTERVAL: 4`）升级后会停服，需按报错修复配置

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
