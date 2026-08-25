# AutoLogin-CQU 修改日志
## 2026-08-25: 交付前全量安全扫描与防御性加固

**范围**：`src/windows/AutoLogin-CQU.cpp` 全量（约 1530 行）。子代理全量内存安全扫描（裸指针/RAII 句柄生命周期/goto cleanup/长驻循环/编码转换/多线程/整数溢出）：无阻断级缺陷——`ScopedMalloc` 重分配链无泄漏，`WinHttpCloseHandle` 仅 RAII 内一处，`PerformLogin` 全部 return 路径经 RAII，`wsaStarted` 标志防 WSACleanup 失衡，无 `TerminateThread`，`SecondsToMilliseconds` 先 clamp 防 DWORD 溢出。

**处置**：候选 🔴「键盘线程吞 Ctrl+C」经 MSDN《CTRL+C and CTRL+BREAK Signals》核对为误报——`ENABLE_PROCESSED_INPUT` 开启时 Ctrl+C 作为信号由控制台独立投递给全部挂接进程，不经过输入队列，`ConsoleHandler` 照常触发（该线程正是保持此模式）；已加语义注释说明。🟡 中两条一行项已修：`GetAdaptersAddresses` 分配失败空检查（两处）、接口查找 `ifIndex==0` 哨兵改 `BOOL found`。

**验证**：编译 0 错误；`--self-test` 19 例全过（exit 0）；持续发送失败 soak 45s 稳定不崩；真实门户 soak 42s 稳定（假凭据→认证失败循环，无崩溃）；5 类配置错误（`CHECK_INTERVAL` 4/7200、`TIMEOUT` 0、`LOGIN_IP` 非法、`DEBUG_RESPONSE` 非法）均以 78 干净退出。Ctrl+C 运行时注入在本无交互桌面的会话无法实测（`AllocConsole` 被拒），其信号路径不依赖代码。

**交付物**：`src/windows/AutoLogin-CQU.exe`（commit 51ba374，MinGW 静态链接）。
## 2026-08-25: Windows 第二阶段第 5 项完成——`--self-test` 离线自检

**范围**：`src/windows/AutoLogin-CQU.cpp`。`RunSelfTest()` 用例与 Linux 端逐条一致（19 例）：14 例响应分类（`ContainsJsonIntField` 严格读取：成功/已在线/失败/前缀不匹配/空响应/HTML 与代理错误页/截断场景）+ 5 项地址断言（`127.0.0.1` 与 `::1` 回环 UDP 探测、`SERVER_IP` 目的优先、同接口 `127.0.0.1`<->`::1` 双向查找）。`main` 签名改收 `argc/argv`，首分支处理 `--self-test`（不读配置、不触网、`RunSelfTest` 自带 `WSAStartup/WSACleanup`）：成功退出 0，任一失败退出 1 并打印 FAIL 行。

**验证**：编译 0 错误；在无配置文件目录运行 `--self-test` 全部通过退出 0（证明不依赖配置）；无参运行仍走配置校验以 78 退出。

**状态**：Windows 端第二阶段 5 项全部完成。剩余工作：第三阶段项级验证（第 1、2 项已代码改进，cf3a6b0）、第四阶段第 2 项（Windows 离线检查，`--self-test` 已覆盖其核心，剩文档化）。

## 2026-08-25: Windows 第二阶段第 3 项完成——IPv4/IPv6 路由探测与 `LOGIN_IP` 语义

**范围**：`src/windows/AutoLogin-CQU.cpp`。按 AUDIT 第 3 项修改方案落地，逻辑与 Linux 逐条对应：

1. 目的地址：`PortalTarget` 扩展 `destIp`——`SERVER_IP` 非空直接用（IPv4/IPv6 字面），否则 `getaddrinfo` 解析门户域名（优先首个 IPv4，其次首个 IPv6），解析失败退回启发式并告警；
2. `ProbeRouteSource`：按目的地址族建 UDP socket `connect()` 到 `<dest>:802`（不发包），`getsockname()` 取内核选定源地址；
3. `GetSameInterfaceAddress`：`GetAdaptersAddresses` 先按接口（IfIndex）定位含目标地址的适配器，再取该适配器另一地址族首个地址（v6 排除 `fe80::`/`::`）；
4. `GetLoginAddresses` 三级选择：`LOGIN_IP` 非空 → `manual`（同接口全局 v6，取不到退回 `GetLocalIPs` 的 v6）；否则探测得 IPv4 → `route`（同接口全局 v6，无则留空）；探测得全局 v6 → 同接口 v4，无则 v4 退回启发式（`route-v4-fallback`）；探测失败/无 `destIp` → `GetLocalIPs` 启发式（保留接口类型+网段优先级），v6 取所选 v4 同接口全局 v6；
5. 三条结果行追加来源标签，如 `[失败] 登录失败 (IPv4: 10.x.x.x, route)`；`使用配置的登录 IP` 信息行保持每周期打印。

**验证**：编译 0 错误；无 `SERVER_IP`/`LOGIN_IP` 时结果行显示 `(route)`（本机实际 IPv4）；`LOGIN_IP` 显式指定时显示 `(manual)` 并打印信息行；`SERVER_IP: 127.0.0.1` 钉解析与地址选择均正常（无本地 TLS 服务时发送失败提前返回，为既有行为）。

**状态**：Windows 端第二阶段第 1、2、3、4 项完成；剩余第 5 项（`--self-test` 离线自检）。

## 2026-08-25: Windows 第二阶段第 1、4 项完成——`CHECK_INTERVAL` 范围对齐 + `Config` 值结构

**范围**：`src/windows/AutoLogin-CQU.cpp`、`src/windows/config.yaml`。现实现：

1. `Config` 值结构替换全部配置全局变量（原 `USER_ACCOUNT`/`USER_PASSWORD`/`SERVER_IP`/`LOGIN_IP`/`CHECK_INTERVAL_MS`/`TIMEOUT_MS`/`DEBUG_RESPONSE`）：字段与 Linux 端对齐（`studentId`/`password`/`serverIp`/`loginIp`/`checkIntervalSec`/`timeoutSec`，另加 Windows 扩展 `debugResponse`）；`LoadConfig(Config&)` 起按 `const Config &` 传递到 `GetPortalTarget`/`BuildLoginPath`/`LogLoginResult`/`PerformLogin`；删除 `USER_ACCOUNT` 全局，`,0,` 前缀在 `BuildLoginPath` 内拼接（与 Linux 一致）；
2. `TryGetConfigSeconds` 增加下限校验，范围与 Linux 对齐：`CHECK_INTERVAL` 5-3600（原 1-86400）、`TIMEOUT` 1-300；`config.yaml` 注释补充范围说明；
3. 验证：编译 0 错误；`CHECK_INTERVAL: 4` 与 `7200` 均报错 exit 78 并显示 `5 到 3600`；`SERVER_IP` 钉解析、`DEBUG_RESPONSE` 门控回归正常。

**状态**：Windows 端第二阶段第 1、2、4 项完成；剩余第 3 项（IPv4/IPv6 路由探测与 `LOGIN_IP` 语义）与第 5 项（`--self-test` 离线自检）。

## 2026-08-25: Windows 第一阶段第 5 项完成——`DEBUG_RESPONSE` 响应正文门控

**范围**：`src/windows/AutoLogin-CQU.cpp`、`src/windows/config.yaml`。AUDIT §5.6 要求日志默认最小化，详细响应仅经显式调试选项启用且限制长度。此前 `LogLoginResult` 无条件输出响应正文（截断 200 字符）。现实现：

1. 新增 `DEBUG_RESPONSE` 配置键（可选，默认 `false`）：`false` 时不输出响应正文，`true` 时在结果行后输出截断 200 字符的正文；
2. 解析用 `TryGetConfigBool`，接受 `true`/`false`（大小写不敏感，兼容 `TRUE`/`FALSE`/`1`/`0`），其他值报错 exit 78；`config.yaml` 增加注释键 `DEBUG_RESPONSE: false`；
3. 验证：编译 0 错误；默认配置输出无 `[响应]` 行；`DEBUG_RESPONSE: true` 时输出正文；非法值 `yes` → exit 78。
**状态**：Windows 端第一阶段 5/5 完成。后续任务为第二阶段第 1/3/4/5 项与第三/四阶段（见 `AUDIT.md`）。

## 2026-08-25: Windows 第一阶段推进——TLS 严格校验 + 连接语义重构 + CA_BUNDLE 定为不支持

**范围**：`src/windows/AutoLogin-CQU.cpp`、`AUDIT.md`。Windows 端第一阶段 5 项中完成 4 项（①③④②-变体），与 Linux v2.0.0 连接/安全语义对齐：

1. **TLS 严格校验（第一阶段第 1 项）**：移除 `WINHTTP_OPTION_SECURITY_FLAGS` 的 `IGNORE_UNKNOWN_CA` / `IGNORE_CERT_CN_INVALID` / `IGNORE_CERT_DATE_INVALID` 三个标志，WinHTTP 默认校验 CA 链、主机名与有效期（commit d618da1）。
2. **连接语义重构（第一阶段第 3、4 项）**：删除“先 `ResolveHostToIP` 解析为 IP 再 `WinHttpConnect(IP)`”的旧模型（SNI 为 IP），改为 `PortalTarget`：逻辑主机名恒为域名 `login.cqu.edu.cn`；`SERVER_IP` 非空且为 IPv4 时用 `WINHTTP_OPTION_RESOLUTION_HOSTNAME`（165，Win10 21H1+）把 DNS 解析钉到该 IP，SNI/Host/证书校验仍为域名；旧系统 SetOption 失败或 `SERVER_IP` 为 IPv6 时回退“IP 直连 + 手动 Host 头”并打印警告（SNI 非域名，可能登录失败）。
3. **`CA_BUNDLE` 决策：Windows 端不支持**：调研证实 WinHTTP 没有替换系统信任库的公开选项——`WINHTTP_OPTION_SSL_CERT_STORE` 在 SDK 头文件与官方 option-flags 文档中均不存在；此前代码使用的选项编号 45 实为 `WINHTTP_OPTION_CONTEXT_VALUE`，对 TLS 校验毫无作用。机主决策：移除 Windows 端 `CA_BUNDLE` 配置键，配置出现该键时报错并提示“内部 CA 请安装到系统信任库（certmgr.msc）”，信任来源 = 系统信任库（与 Linux `CA_BUNDLE` 不对等，属平台能力限制，已写入 `AUDIT.md` §4.1）。
4. **实证验证**（本机 + 本地自签 TLS 服务器 127.0.0.1:802 + 真实门户）：
   - 钉解析生效：`SERVER_IP: 127.0.0.1` 时连接确实打到本地服务器（服务端日志确认），SNI 保持 `login.cqu.edu.cn`；自签证书被严格校验拒绝（错误码 12175 `SEC_E_CERT_UNKNOWN`）；
   - 无 `SERVER_IP` 时走真实门户：TLS 握手成功，登录走通（测试账号得到门户业务响应）；
   - `CA_BUNDLE` 键出现 → 专用错误提示 + exit 78；非法 `SERVER_IP` → exit 78；IPv6 `SERVER_IP` → 回退警告按预期打印。
5. **文档同步**：`AUDIT.md` 顶部现状、第一阶段/第二阶段状态注记、§4.1/§4.2 语义说明更新为按端细分的最新状态；`LOG.md` 08-25 条目同步。
**剩余（Windows 第一阶段第 5 项）**：`LogLoginResult` 响应正文门控——见上方后续条目，已完成。

## 2026-08-25: Linux 版本标记完成（v2.0.0）

**状态**：机主在真实校园网环境完成 v2.0.0 实机验证，确认将整个 Linux 版本标记为完成。`AUDIT.md` 状态注记已同步更新（顶部现状 + 第二/三/四阶段）。

**验证覆盖**（各条详见下方对应条目）：

- 编译：`g++ -O2 -Wall -Wextra`，0 警告；
- 离线：`--self-test` 19 项（14 响应分类 + 5 地址断言）全部通过，无需配置文件与网络；
- 实机：真实门户登录保活（`login success` / `already online`）、`systemctl start/stop/enable`、`SIGTERM`/`SIGINT` 优雅退出、配置错误退出码 `78`、`systemd-analyze verify` 通过（实机与 sudo 部分由机主执行）。

**剩余**（后记：原为“Windows 侧第二/三/四阶段多项未开始”，已按 AUDIT.md 按端细分修正）：Windows 端——第一阶段 5 项未开始；第二阶段第 1 项仅剩范围/键对齐、第 3/4/5 项未开始（第 2 项双端已完成）；第三阶段第 1/2 项代码已改进（cf3a6b0）但项级验证未做；第四阶段第 2 项未做。详见 `AUDIT.md` 各阶段状态注记。

## 2026-08-24: v2.0.0 交付前最后打磨——配置解析 `#` 修复 + 诊断日志/标签准确性

**范围**：`src/linux/AutoLogin-CQU.cpp`。子代理完整代码逻辑审查（13 处 setopt 类型、RAII/生命周期、资源获取返回值、核心逻辑）结论**可交付、无 🔴**；对其列出的可打磨项做取舍后修 3 处：

1. **配置解析 `#` 截断修复（🟡，正确性）**：`StripInlineComment` 原把任何位置的 `#` 当注释截断，违反 YAML 规范（`#` 仅在行首或前导空白时才起注释）。后果：真实密码含 `#`（如 `a#b`）被静默截断成 `a` → 每 20s 登录失败且难排查。修法：`#` 仅在 `i==0 || isspace(前一字符)` 时截断。独立小程序验证 7 用例全对（`a#b`→`a#b`、`a # c`→`a`、引号内 `#` 保护、尾部注释等）。
2. **DNS 失败诊断日志（🟢→修）**：`ResolvePortalDestination` 在 `getaddrinfo` 失败时原静默返回 false 回退启发式；现记 `warning: DNS resolution of login.cqu.edu.cn failed; falling back to heuristic address`。仅 DNS 真坏时触发，非常态噪音。
3. **地址标签准确性（🟢→修）**：v6 路由但同接口无 IPv4 的回退分支，上报 IPv4 实为启发式取值，原标 `route` 误导排障；现标 `route-v4-fallback` 并在函数注释中定义。self-test 不断言该标签，改动安全。

**跳过（评估后不值得）**：setopt/sigaction/close 返回值未检查（惯例，失败经 perform 暴露，加检查只增噪音）；WriteCallback 传完整 body 再截断（子代理建议维持现状，"传完+(truncated)"语义更清晰）。

**验证**：`-Wall -Wextra` 0 警告；`--self-test` 全过；正常路径无回归（v4 路由仍标 route）；SERVER_IP 崩溃回归 3/3 无崩；含 `#` 密码配置被接受且正常启动。

## 2026-08-24: v2.0.0 生产级测试版打磨——修复 SERVER_IP 段错误 + 可观测性

**范围**：`src/linux/AutoLogin-CQU.cpp`。目标：交付 v2.0.0 生产级测试版二进制。

**关键修复——CURLOPT_RESOLVE 段错误（🔴 阻断级）**：

- **症状**：配置 `SERVER_IP` 时，`curl_easy_perform` 内**间歇性段错误**（rc=139/SIGSEGV）。非确定性——取决于 ASLR/内存布局，有时崩有时不崩（此前 item 3 冒烟用 `SERVER_IP=10.244.99.99` 恰好没崩，掩盖了此 bug）。
- **根因**：`curl_easy_setopt(curl, CURLOPT_RESOLVE, resolveEntry.c_str())` 把 `const char*` 传给了要求 `curl_slist*` 的选项；libcurl 把字符串指针当链表头解引用。经 libcurl 官方文档确认：`CURLOPT_RESOLVE` 要求 `struct curl_slist*`，且 libcurl **不深拷贝**该列表，调用方必须让列表存活到 handle 不再做传输。
- **修法**：用 `curl_slist_append` 构建 slist，在 main 作用域声明 `unique_ptr<curl_slist, decltype(&curl_slist_free_all)> resolveList(nullptr, curl_slist_free_all);`（与既有 `headers` 同模式），条件 `.reset()` 后传 `.get()` 给 setopt。slist 存活覆盖主循环内所有 `curl_easy_perform`，析构顺序（slist 先于 handle）安全。
- **附带**：`(nullptr, deleter)` 两参构造需 C++14+（项目固定构建默认 gnu++14+，OK）；函数指针删除器的 `unique_ptr` 不可默认构造（SFINAE 约束），故不能用默认构造初始化。
- **验证**：修复前真实/假 SERVER_IP 均段错误；修复后均不再崩，优雅报 `Could not connect to server`；无 SERVER_IP 正常路径实测返回 `already online`，无回归。

**可观测性打磨**：

1. 新增 `SERVER_IP` 启动日志 `using configured server ip=X`（与既有 `LOGIN_IP` 日志对称，便于实机确认连接目标；SERVER_IP 为部署侧目标 IP，非凭据/非 URL，可入日志）。
2. 补 `GetLoginAddresses` route-v6-only 分支的失败日志（子代理审查发现）：纯 IPv6 主机探测到 v6 路由但无可用 IPv4 时，原代码 `return false` 无日志，服务每 20s 静默重试、journald 无痕迹；现报 `no local IPv4 available for login (v6 route only)`。

**审查**：子代理独立审查（重点段错误修复正确性/slist 生命周期/IPv6 分支/生产就绪度）结论**可提交**，无阻断项；采纳其 1 条 🟡 建议（上述失败日志），跳过 1 条（建议改用默认构造，实为不可行——默认构造编译不过）。

**验证**：`g++ -O2 -Wall -Wextra` 0 警告；`--self-test` 19 项全过；SERVER_IP 场景不再段错误；正常路径无回归。

## 2026-08-24: 第三阶段第 3 项——Linux systemd 服务路径 / 权限 / 信号退出验证

**范围**：无代码改动（验证类任务）。验证目标：`src/linux/AutoLogin-CQU`、`src/linux/autologin-cqu.service`、`linux_systemd-setup.md`。

**验证结果**（无 root 部分，全部通过）：

1. **信号退出**：`CHECK_INTERVAL=30` 下进程进入 `sleep(30)` 后发信号——SIGTERM 与 SIGINT 均立即优雅退出（时延 0.00s，退出码 0，打印 `stopped`），证明 `sleep` 被信号正确中断，不会傻等完整间隔。
2. **退出码**：14 种配置错误（缺文件/账号密码空/未知键/重复键/非法行/超范围下限上限/非数字/IP 非法/模板占位符/CA_BUNDLE 不可读）全部返回 `78`；正常启动 + SIGTERM 返回 `0`。与 `RestartPreventExitStatus=78` 配合语义一致。
3. **工作目录要求**：程序从工作目录读 `config.yaml`——有配置的目录启动成功；空目录（无 config.yaml）返回 `78` 并报 `config.yaml not found or not readable`。
4. **无临时文件 / 无残留进程**：运行前后工作目录与 `/tmp` 快照对比无新增文件；主进程运行期间子进程数为 0，信号后主进程干净退出。
5. **systemd unit 语法**：`systemd-analyze verify`（占位符替换后）返回 0，`RestartPreventExitStatus=78`、`Restart=on-failure`、`After/Wants=network-online.target`、`WorkingDirectory`、`ExecStart` 等关键指令齐全。两条提示均为测试环境因素（占位路径 `/opt/autologin-cqu` 本机不存在、临时用 `nobody` 触发 special-user 警告），非 unit 缺陷。
6. **权限模型**：config 可读（644）→ 启动；config 不可读（000）→ 返回 `78`；二进制可执行位正常；`ldd` 确认 `libcurl.so.4` 已解析、无缺失依赖。

**已知边界（非缺陷，无需改代码）**：

- 信号若落在 `curl_easy_perform` 进行中的长请求里，优雅退出会延迟到该请求结束，最长等于 `TIMEOUT`。默认 `TIMEOUT=5` 时无影响（远小于 systemd 默认 `TimeoutStopSec=90s`）；仅当用户把 `TIMEOUT` 调到接近上限 300 且网络挂死时，`systemctl stop` 会在 90s 后 SIGKILL（仍会停，只是不优雅）。如部署时把 `TIMEOUT` 调大，可在 unit 里显式加 `TimeoutStopSec=` 对齐预期。

**需 sudo / systemd 实机执行的步骤（本机无 root，交机主执行）**：

```bash
# 按 linux_systemd-setup.md 推荐方式安装后：
sudo systemctl daemon-reload
sudo systemctl start autologin-cqu
sudo systemctl status autologin-cqu --no-pager      # 应 active (running)
sudo journalctl -u autologin-cqu -n 50 --no-pager    # 应见 started / already online 或 login success
sudo systemctl stop autologin-cqu                    # 应立即停止并打印 stopped
sudo systemctl enable autologin-cqu                  # 开机自启
```

第四阶段第 5 项（systemd 容器内验证：有效配置启动 / 无效配置立即 78 / SIGTERM 干净退出 / 无残留）与上述步骤重叠，容器可用时按 `AUDIT.md` §4 复核即可。

## 2026-08-24: 统一 IPv4/IPv6 与 LOGIN_IP 语义（Linux 路由探测）

**范围**：`src/linux/AutoLogin-CQU.cpp`, `AUDIT.md`

**改动**（第二阶段第 3 项）：

1. 新增 `ResolvePortalDestination`：`SERVER_IP` 非空直接用（字面 IP），否则 `getaddrinfo` 解析门户域名（IPv4 优先，其次 IPv6）
2. 新增 `ProbeRouteSource`：UDP socket `connect()`（不发真实报文）+ `getsockname()` 探测内核为到门户路由选定的源地址
3. 新增 `GetOtherFamilyOnInterface`：定位包含给定地址的接口，取该接口另一地址族首个地址（v6 排除 `fe80::`/`::`）
4. 重写 `GetLoginAddresses` 为 manual/route/heuristic 三级：
   - manual：`LOGIN_IP` 非空 → `wlan_user_ip=LOGIN_IP`，v6 取同接口全局 v6（取不到退回首个全局 v6）
   - route：探测得 v4 → v4 + 同接口 v6；探测得全局 v6 → v6 + 同接口 v4（无则启发式 v4）
   - heuristic：探测失败退回既有接口/网段启发式，v6 优先取所选 v4 同接口全局 v6
5. `PerformLogin` 三条结果行（success/already online/failed）追加地址来源 `(manual|route|heuristic)`
6. `--self-test` 新增 5 个确定性断言：回环 UDP 探测 v4/v6、`SERVER_IP` 优先、同接口查找 `127.0.0.1<->::1` 双向

**AUDIT.md**：写入第 3 项统一语义（两端一致的定义）+ Windows 修改方案（待 Windows 会话实施）；状态行更新。

**验证**：

- `g++ -Wall -Wextra` 零警告；`--self-test` 19 例（14 分类 + 5 地址）全过
- 真实门户冒烟（route 模式）：`already online ip=10.244.77.2 (route)`，与 `ip route get <门户IP>` 的 `src 10.244.77.2 dev enp7s0` 一致
- LOGIN_IP 冒烟（manual 模式）：`already online ip=10.244.99.99 (manual)` + 启动行 `using configured login ip`
- 子代理审查：可提交，无阻塞；6 条低级别问题（文档措辞/边界）已修正进 AUDIT.md 与代码注释
- `git diff --check` 通过

**遗留 / 已知限制**：

- `SERVER_IP` 为空时探测反映 v4 路由；libcurl 双栈可能走 v6 路由（单网卡同接口，影响可忽略；多网卡失配时再按族分别探测）
- Windows 侧第 3 项待做（方案已写入 AUDIT.md）

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
