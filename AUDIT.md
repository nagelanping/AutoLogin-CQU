# AutoLogin-CQU 项目改进指南

本文是给后续 agent 的实施顺序和边界说明。修改前先读本文件、`README.md`和 `linux_systemd-setup.md`。

> Python 版本不再维护；请勿查看或改动其归档内容。
>
> **现状（按端细分）**：Linux 端（`src/linux/`）已完成——四个阶段的 Linux 侧项全部完成并通过实机验证（v2.0.0，详见 `LOG.md`）。Windows 端（`src/windows/`）逐项状态：第一阶段 5 项全部完成（TLS 严格校验、默认域名目标、`SERVER_IP` 钉解析、自定义信任来源按平台限制定为系统信任库、`DEBUG_RESPONSE` 响应门控）；第二阶段 5 项全部完成（配置校验含 `CHECK_INTERVAL` 5-3600 范围对齐、响应分类、IPv4/IPv6 路由探测与 `LOGIN_IP` 语义、`Config` 值结构替换全局变量、`--self-test` 离线自检 19 例）；第三阶段第 1、2 项代码层面已改进（commit cf3a6b0），项级验证未做；第四阶段第 2 项（Windows 离线检查）未做。详见各阶段状态注记。

## 1. 产品定位：先不要改错目标

项目有两个明确不同的运行目标：

- **Linux**：只面向 systemd 常驻服务。没有托盘、暂停快捷键或前台交互需求；手动前台运行只用于排错。
- **Windows**：既要低占用后台常驻，也要支持前台控制，包括托盘、显示/隐藏、暂停/继续和退出快捷键。

两端共同的业务流程是：

```text
加载并校验配置
    ↓
获取认证所需的本机地址
    ↓
构造校园网门户请求
    ↓
分类响应：成功 / 已在线 / 失败 / 暂时不可用
    ↓
按周期重试，直到收到退出信号
```

不要因为 Windows 比 Linux 多了托盘和快捷键，就把这些功能判定为无用复杂度。应审计的是 Windows 前台控制层与登录核心的边界、事件传递和线程清理。

## 2. 当前代码边界

| 部分    | 当前实现                                                             | 后续 agent 的边界                               |
| ------- | -------------------------------------------------------------------- | ----------------------------------------------- |
| Linux   | `src/linux/AutoLogin-CQU.cpp`，libcurl、POSIX API                  | 保持 systemd 服务模型，修复网络、配置和退出处理 |
| Windows | `src/windows/AutoLogin-CQU.cpp`，WinHTTP、Win32 事件、托盘和快捷键 | 保留前后台双模式，收敛控制层与服务核心          |
| systemd | `src/linux/autologin-cqu.service`                                  | 继续作为模板使用，替换占位符后部署              |
| 配置    | 两端各自的`config.yaml`                                            | 保持键名一致、校验规则一致                      |
| Python  | 已归档                                                               | 不查看、不修改、不做功能对齐                    |

当前没有构建系统、测试套件、格式化工具、静态检查配置或 CI。不要假设存在 `make test`、`cmake --build` 或统一测试命令。

## 3. 推荐目标架构

只抽取真正共享的协议逻辑，不要引入工厂、插件系统、依赖注入或跨平台网络框架。

```text
共享协议规则
  ├─ Config：配置字段、默认值、范围和错误码
  ├─ Request：URL、参数、Host 和 TLS 主机名规则
  ├─ Response：成功 / 已在线 / 失败 / 未知
  └─ Log：结构化结果和脱敏规则
       ↓
Linux 服务适配层                         Windows 服务核心
  ├─ libcurl                                ├─ WinHTTP
  ├─ getifaddrs / 地址选择                  ├─ IP Helper / 地址选择
  ├─ SIGTERM / SIGINT                       ├─ 退出、暂停、继续事件
  └─ systemd 周期循环                       └─ 后台周期循环
                                                   ↓
                                           Windows 前台控制层
                                             ├─ 托盘消息窗口
                                             ├─ 快捷键监听
                                             └─ pause/resume/exit 事件
```

最小重构方向：

1. 先建立一个简单的 `Config` 值对象，减少全局可变配置；
2. 将配置校验、请求参数和响应分类的规则写成两端共同遵守的协议；
3. Linux 只保留服务循环；
4. Windows 保留 UI，但让 UI 只发送控制事件，不直接操作网络句柄；
5. 不为了几段字符串处理代码创建大型共享库。

## 4. P0：必须先处理的安全和连接语义

### 4.1 TLS 校验：自定义证书不是错误，但关闭全部校验是风险

校园网门户可能使用不公开的自签名证书或内部 CA。这不意味着必须使用公网 CA，也不能直接把该证书判定为错误。历史版本中 Linux、Windows 都关闭了证书校验：

- Linux 曾设置 `CURLOPT_SSL_VERIFYPEER = 0` 和 `CURLOPT_SSL_VERIFYHOST = 0`（已修复，恢复严格校验，`CA_BUNDLE` 提供自定义信任来源）；
- Windows 曾忽略未知 CA、域名不匹配和证书过期（已修复，移除 `WINHTTP_OPTION_SECURITY_FLAGS` 三个 ignore 标志）。Windows 端不支持自定义 CA 文件：WinHTTP 没有替换系统信任库的公开选项（`WINHTTP_OPTION_SSL_CERT_STORE` 不存在，经 SDK 头文件与官方 option-flags 文档核实），内部 CA 须安装到系统信任库（`certmgr.msc` → 受信任的根证书颁发机构）。

后续修改必须遵循：

1. 默认启用证书链和主机名校验；
2. 支持校园网自定义信任来源：系统已安装的内部 CA、用户指定的 CA 文件，或明确的证书固定方案；
3. 不要假设公网 CA 一定能验证门户证书；
4. 只有显式调试选项才允许跳过校验，默认关闭，并输出警告；
5. 不要为了绕过证书错误而关闭全部 TLS 安全检查。

### 4.2 默认使用域名，`SERVER_IP` 只作为高级覆盖

默认请求目标是：

```text
https://login.cqu.edu.cn:802/eportal/portal/login
```

`SERVER_IP` 是高级配置，用于 DNS 绕过、特殊路由或直连场景，不应改变默认行为，也不应把 IP 直接作为 HTTPS URL 的逻辑主机名。

正确的连接语义应是：

```text
逻辑主机名：login.cqu.edu.cn
实际连接地址：默认由 DNS 得到；高级模式可固定为 SERVER_IP
TLS SNI：login.cqu.edu.cn
证书主机名：login.cqu.edu.cn
HTTP Host：login.cqu.edu.cn
```

Linux 应优先使用 libcurl 的 `CURLOPT_RESOLVE` 或等价能力。Windows 应使用能够保留逻辑主机名和 TLS 主机名的等价方案；不要仅靠“连接 IP + 手动 Host 头”假设 SNI 一定正确。（已实现：Linux 用 `CURLOPT_RESOLVE`；Windows 用 `WINHTTP_OPTION_RESOLUTION_HOSTNAME`（165，Win10 21H1+，钉 DNS 解析到 IP 字面量，SNI/Host 仍为域名），旧系统 SetOption 失败时回退“IP 直连 + 手动 Host 头”并打印警告，IPv6 `SERVER_IP` 直接走该回退。）

### 4.3 代理绕过是功能选择，不要擅自改成代理模式

当前项目的校园网认证场景倾向直连，Linux、Windows 当前实现也主动绕过系统代理。后续 agent 不应把“禁用代理”直接当作缺陷。

只有在明确提出代理兼容需求时，才增加代理模式；否则保持直连，避免引入代理配置、代理认证和额外网络分支。

如果未来确实需要扩展，优先使用简单的显式模式，而不是自动猜测：

```text
PROXY_MODE: direct | system | explicit
```

### 4.4 登录密码位于 GET 参数中

门户协议可能强制使用 GET，因此不能未经验证直接改为 POST。风险在于 URL 可能进入代理、网关、调试工具或监控日志。

修改原则：

- 先确认门户协议是否允许 POST；
- 若只能 GET，保持协议兼容；
- 不记录完整 URL；
- 不在错误信息中输出 URL；
- 日志只输出脱敏后的请求摘要；
- 不要为了日志排查把密码重新打印出来。

## 5. P1：正确性和可维护性问题

### 5.1 配置文件不是完整 YAML

`config.yaml` 实际由自定义的单层键值解析器读取，不支持完整 YAML。当前问题：

- 非法行被静默跳过；
- 未知键和重复键不报错；
- 非法数值回退默认值；
- IP 地址没有统一校验；
- Linux 和 Windows 校验规则有漂移风险。

推荐的最小方案：

- 不继续扩展半套 YAML 解析器；
- 保留现有单层格式，或改名为明确的简单配置格式；
- 统一两端的必需项、默认值、范围、未知键和错误码；
- 用户填写了非法值时明确报错并返回 `78`；
- 模板账号和密码不能被 Linux 当成有效配置启动请求。

除非确实需要嵌套 YAML，否则不要为几个字段引入大型配置依赖。

### 5.2 响应分类不能依赖脆弱字符串片段

Linux 和 Windows 都通过搜索 JSON 片段判断结果。应保持小而严格，不必立即引入完整 JSON 框架：

- 限制响应体大小；
- 标记响应是否被截断；
- 严格读取门户需要的字段；
- 字段缺失、格式错误、HTML 错误页和空响应都归类为未知/失败；
- 分类函数保持纯函数，方便离线验证。

至少准备以下响应样例：成功、已在线、认证失败、字段顺序变化、空响应、截断响应、HTML 错误页和代理错误页。

### 5.3 DNS 超时和 HTTP 超时是两个阶段

当前先调用同步 `getaddrinfo`，再发起 HTTP 请求。`TIMEOUT` 不一定覆盖 DNS 阶段。后续 agent 不应在文档中声称它限制整个请求。

优先使用 HTTP 客户端的域名解析和超时能力；固定 IP 时使用受控域名映射。除非实测存在长期 DNS 阻塞，不要为了异步 DNS 引入线程池。

### 5.4 地址选择必须支持 IPv4、IPv6 和复杂网络环境

IPv6 是正式功能，不要删除或弱化。当前通过接口名前缀和网段启发式选择地址，可能误选 VPN、容器、桥接或不可达接口。

后续修改应：

- 保留 IPv6 参数；
- 过滤链路本地地址；
- 尽量根据到认证服务器的实际路由选择源地址；
- 保留 `LOGIN_IP` 等高级覆盖能力；
- 日志中明确地址是自动选择还是手动指定；
- 不要仅因为找到了一个非链路本地 IPv6，就认定它可用于认证。

### 5.5 初始化和错误返回值不能全部忽略

Linux 需要检查 `curl_global_init`、`curl_easy_init`、关键 `curl_easy_setopt` 和 header 创建结果。非关键优化项可以警告后继续，关键初始化失败必须停止。

配置数值建议区分：

- 未填写：使用默认值；
- 已填写但格式非法：报错并返回 `78`；
- 超出允许范围：报错并显示范围。

### 5.6 日志默认最小化

当前响应正文可能被写入 stdout/stderr 或 systemd journal。默认只记录：

- 阶段；
- 状态码或错误类别；
- 是否成功 / 已在线；
- 脱敏后的本机地址；
- 重试和退出原因。

详细响应只能通过显式调试选项启用，并限制长度、过滤凭据和会话信息。

## 6. Windows 专项指导

### 6.1 必须保留的功能

不要删除以下正式需求：

- 低占用后台常驻；
- 托盘显示和隐藏；
- 暂停 / 继续；
- 前台快捷键；
- Ctrl+C、关闭窗口和托盘退出。

### 6.2 需要重构的不是功能，而是边界

建议将 Windows 代码分成两个概念层，即使暂时仍在一个 `.cpp` 文件中：

```text
登录服务核心
  ├─ 请求和周期
  ├─ pause/resume/exit 状态
  └─ WinHTTP 句柄

前台控制层
  ├─ 托盘消息窗口
  ├─ 快捷键监听
  └─ 发送控制事件
```

前台控制层不得直接销毁 HTTP 句柄或决定服务资源释放顺序。

### 6.3 退出清理是当前明确风险

当前 cleanup 对线程只等待 `500ms` 或 `1000ms`，超时后仍关闭句柄。后续修改必须保证：

1. 每个线程都有明确的退出条件；
2. 退出事件先发送给所有工作线程；
3. 等待线程真正结束；
4. 再销毁窗口、事件和 HTTP 句柄；
5. `CreateThread` 部分失败时仍能安全清理；
6. 线程未结束时不能假定关闭句柄就是安全退出。

低占用应通过实际测量确认，不要仅凭线程数量认定资源过高。

## 7. Linux 专项指导

Linux 版本以 systemd 为唯一主要运行模型：

- `WorkingDirectory` 必须指向可执行文件和 `config.yaml` 所在目录；
- 配置错误使用退出码 `78`，避免 systemd 无限重启；
- 使用 `SIGTERM` / `SIGINT` 优雅退出；
- 日志进入 journal；
- 不增加 Windows 式托盘、快捷键或暂停 UI；
- `network-online.target` 不是 DNS 或门户可用性的绝对保证，程序应继续按周期处理暂时网络失败。

## 8. 推荐实施顺序

### 第一阶段：先修连接和安全

1. 恢复 TLS 校验；
2. 增加校园网自定义 CA 或证书固定的明确配置路径；
3. 保持默认域名请求目标；
4. 将 `SERVER_IP` 改成“域名逻辑主机名 + 固定实际连接地址”的高级模式；
5. 默认停止输出完整响应和 URL。

> 状态（按端细分）：**Linux 端 5 项均已完成**（commit f691b06，含 `CA_BUNDLE` 配置项与 `CURLOPT_RESOLVE` 语义，详见 `LOG.md`）。**Windows 端 5 项均已完成**：① TLS 严格校验已恢复（移除 `WINHTTP_OPTION_SECURITY_FLAGS` 三个 ignore 标志，commit d618da1）；② 自定义信任来源——Windows 端不支持 `CA_BUNDLE`：WinHTTP 无替换系统信任库的公开选项（`WINHTTP_OPTION_SSL_CERT_STORE` 不存在），决定采用系统信任库，`CA_BUNDLE` 配置键在 Windows 端报错并提示用 certmgr 安装内部 CA（与 Linux 不对等，属平台能力限制，见 §4.1）；③ 默认域名目标已实现（逻辑主机名恒为域名，commit 3f8e17b）；④ `SERVER_IP` 高级模式已实现（`WINHTTP_OPTION_RESOLUTION_HOSTNAME` 钉解析，旧系统/IPv6 回退 IP 直连 + 手动 Host 头并告警）；⑤ 响应正文门控已实现（`DEBUG_RESPONSE` 配置键，默认不输出响应正文，`true` 时输出截断 200 字符的正文，§5.6；Linux 端默认仅输出响应字节数，无调试选项，双端不对等项以 Windows 更完整）。
>
### 第二阶段：统一协议行为

1. 统一两端配置字段和校验规则；
2. 统一响应分类和错误类别；
3. 统一 IPv4/IPv6 和 `LOGIN_IP` 语义；
4. 用最小 `Config` 结构替换全局配置；
5. 添加离线响应分类检查。

**第 3 项统一语义（IPv4/IPv6 与 `LOGIN_IP`，Linux 已实现，Windows 按此跟进）**：

- **目的地址**：`SERVER_IP` 非空则直接用（字面 IP）；否则 `getaddrinfo` 解析门户域名 `login.cqu.edu.cn`，优先首个 IPv4，其次首个 IPv6。
- **路由探测**：向 `<目的地址>:<门户端口>` 建 UDP socket 并 `connect()`（不实际发包），用 `getsockname()` 得到内核为该路由选定的源地址。
- **源地址映射**：
  - 探测得 IPv4 → `wlan_user_ip` 用该地址；`wlan_user_ipv6` 取该 IPv4 所在接口的全局 IPv6（排除 `fe80::`/`::`），无则留空。
  - 探测得全局 IPv6（非链路本地）→ `wlan_user_ipv6` 用该地址；`wlan_user_ip` 取同接口 IPv4，无则退回启发式。
  - 探测失败（DNS 失败/无路由/仅链路本地源）→ 退回既有接口/网段启发式；此时 `wlan_user_ipv6` 优先取最终所选 IPv4 同接口的全局 v6。
- **`LOGIN_IP`（manual）**：非空则 `wlan_user_ip = LOGIN_IP`（须为 IPv4），不做路由探测；`wlan_user_ipv6` 仍自动选取（LOGIN_IP 同接口全局 v6，取不到则首个全局 v6）。
- **日志**：每次尝试的结果行（success/already online/failed）追加地址来源 `manual` / `route` / `heuristic`。
- **原则**：不得仅因存在某个非链路本地 IPv6 就认定其可用于认证——自动模式（route/heuristic）下上报的 IPv6 必须绑定到实际通往认证服务器的接口，或留空；manual 兜底（LOGIN_IP 定位不到接口时取首个全局 v6）是用户显式指定路径的既有行为，NAT 场景常见。
- **已知限制**：`SERVER_IP` 为空时目的地址取首个 IPv4（或唯一存在的族），探测反映的是 v4 路由；libcurl 双栈（Happy Eyeballs）实际可能走 v6 路由。单网卡时 v4/v6 源通常同接口，影响可忽略；多网卡且门户按源 IP 校验失配时，再改为按族分别探测取对。

**第 3 项 Windows 修改方案**（待 Windows 会话实施，逻辑须与 Linux 逐条对应）：

1. 目的地址：现有 `PortalTarget`/`GetPortalTarget` 已实现“`SERVER_IP` 优先（IPv4 钉解析 / IPv6 回退 IP 直连）+ 域名连接”，在其基础上扩展，不要新建第二个同职责函数。
2. 新增 `ProbeRouteSource(destIp, srcIp)`：按目的地址族建 UDP socket（`WSASocket` 或 `socket`，`SOCK_DGRAM`），`connect()` 到 `<dest>:<LOGIN_PORT>`，`getsockname()` + `getnameinfo(NI_NUMERICHOST)` 得源地址；失败返回 false。
3. 新增 `GetSameInterfaceAddress(addr, wantedFamily, out)`：遍历 `GetAdaptersAddresses` 的各 adapter，先定位包含 `addr` 的 adapter，再取该 adapter 上另一地址族的首个地址（v6 排除 `fe80::`/`::`）。
4. 改造 `PerformLogin` 内（非 `main`）的地址选择为 manual/route/heuristic 三级：`LOGIN_IP` 非空 → manual（同接口 v6 取不到退回 `GetLocalIPs` 的 v6）；否则探测成功按映射规则；探测失败退回现有 `GetLocalIPs`（保留其接口类型 + 网段优先级，作为 heuristic 兜底），随后 v6 按“所选 v4 同接口全局 v6，取不到保留 `GetLocalIPs` 的 v6”覆盖，与 Linux 一致。
5. 日志：三条结果行 `[成功] 登录成功` / `[成功] 设备已在线` / `[失败] 登录失败`（`LogLoginResult` 需扩签名接收 source）追加 `(route|manual|heuristic)`；`使用配置的登录 IP` 行现在在 `PerformLogin` 内每周期打印，保持不变。
6. 不改动 `ContainsJsonIntField`/`ClassifyLoginResponse`（第 2 项已统一）；不引入新依赖。

> 状态（按端细分，逐项）：
>
> - 第 1 项配置校验：**双端已完成**。Linux：未知键/重复键/非法行/非法数值/超范围/模板占位符/IP 格式/CA_BUNDLE 不可读均报错 exit 78。Windows：未知键/重复键/空键/缺 `:`/模板占位符/IP 格式/数值超范围均带行号报错并返回 exit 78（`CA_BUNDLE` 键按平台能力限制不支持并给出专用提示，见第一阶段第 2 项）；范围已对齐（`CHECK_INTERVAL` 5-3600、`TIMEOUT` 1-300 双端一致）。
> - 第 2 项响应分类：**双端已完成**。以 Windows 既有严格读取 `ContainsJsonIntField` 为基准移植到 Linux，两端 `ClassifyLoginResponse` 分类规则逐字节一致。
> - 第 3 项 IPv4/IPv6 与 `LOGIN_IP`：**双端已完成**。Linux：目的地址 + UDP 路由探测 + 同接口 IPv6 绑定 + `manual/route/heuristic` 来源日志（统一语义见上方第 3 项说明）。Windows：按修改方案落地——`PortalTarget` 扩展 `destIp`（`SERVER_IP` 或域名解析首个 IPv4/IPv6）、新增 `ProbeRouteSource`（UDP connect 探测）、`GetSameInterfaceAddress`（`GetAdaptersAddresses` 按接口定位跨族地址）、`GetLoginAddresses` 三级选择（`manual`/`route`/`route-v4-fallback`/`heuristic`，兜底保留 `GetLocalIPs` 接口类型+网段优先级），三条结果行追加来源标签。
> - 第 4 项 `Config` 结构：**双端已完成**。Linux：`Config` 值结构替换全局配置。Windows：`Config` 值结构（与 Linux 字段对齐，另加 Windows 端扩展 `debugResponse`）替换全部配置全局变量（原 `USER_ACCOUNT`/`USER_PASSWORD`/`SERVER_IP`/`LOGIN_IP`/`CHECK_INTERVAL_MS`/`TIMEOUT_MS`/`DEBUG_RESPONSE`），`LoadConfig` 起按 `const Config &` 向下传递。
> - 第 5 项离线响应分类检查：**双端已完成**。Linux：`--self-test` 19 例离线自检（14 分类 + 5 地址断言，失败退出 1，不读配置不触网，v2.0.0）。Windows：用例与 Linux 逐条一致（14 分类 + 回环 UDP 探测×2 + `SERVER_IP` 目的优先 + 同接口双向查找 2 项），`RunSelfTest` 自带 `WSAStartup/WSACleanup`，`main` 首分支处理 `--self-test`，成功退出 0、失败退出 1。
>
> 关联遗留：Windows 端响应正文门控已完成（第一阶段第 5 项，`DEBUG_RESPONSE`）。
>
> **汇总：Linux 端 5 项全部完成并通过实机验证（v2.0.0）。Windows 端 5 项全部完成（第 1 项含 `CHECK_INTERVAL` 5-3600 / `TIMEOUT` 1-300 范围对齐，第 3 项含 UDP 路由探测与 `manual/route/heuristic` 来源日志，第 4 项 `Config` 值结构替换全局变量，第 5 项 `--self-test` 19 例与 Linux 逐条一致）。**

### 第三阶段：修平台生命周期

1. Windows 保留前台控制，拆分控制事件和登录核心；
2. 修正 Windows 线程、事件、窗口和句柄清理顺序；
3. Linux 只验证 systemd 服务路径、权限和信号退出；
4. 不为两端强行统一不相同的生命周期。

> 状态：第 3 项（Linux）已完成：无 root 部分（信号退出、退出码、工作目录、无临时文件/残留进程、unit 语法、权限模型）全部通过；实机 `systemctl start/stop/enable` 与长时运行由机主完成（v2.0.0，详见 `LOG.md`）。第 1、2 项（Windows 端）：代码层面已改进（commit cf3a6b0）——前台控制层（托盘/快捷键/窗口监控线程）只操作事件与原子标志，不接触 `hSession`（满足 §6.2 边界要求）；清理时先 `SetEvent(g_hExitEvent)` 再 `PostMessage(WM_APP_EXIT/WM_QUIT)`，全部线程 `WaitForSingleObject(INFINITE)` 等待结束后再关闭事件句柄；`CreateThread` 部分失败时告警降级、不影响核心登录循环；§6.3 指出的“只等待 500ms/1000ms 超时后强关句柄”风险已不在当前代码中（`main` cleanup 全为 INFINITE 等待，HTTP 句柄由 `ScopedWinHttp` RAII 在主作用域内先行释放）。**项级验证（长时运行退出、部分线程创建失败场景、Windows Terminal 场景）未做，不计为完成。**

### 第四阶段：补发布验证

1. 固定 Linux 和 Windows 的实际编译命令；
2. 增加不依赖真实账号和校园网的离线检查；
3. 验证配置错误返回 `78`；
4. 用 `systemd-analyze verify` 验证 service 模板生成的最终 unit；
5. 文档区分编译验证、离线验证和真实门户验证。

> 状态：第 1 项双端完成（两端实际编译命令记录于 `AGENTS.md`）。第 2 项离线检查：**Linux 端完成**（`--self-test` 19 例，无需配置文件与网络）；**Windows 端未开始**（无 `--self-test`）。第 3 项配置错误返回 78：**Linux 端完成**（14 场景逐项验证）；**Windows 端已实现**（`CONFIG_ERROR_EXIT_CODE=78`，各错误路径均返回），场景化验证未记录。第 4 项 `systemd-analyze verify`：仅适用 Linux 端，**Linux 端完成**（此前“Windows 侧第 4 项待做”的说法有误，systemd 与 Windows 无关）。第 5 项文档区分离线/实机验证：双端完成（README/LOG.md）。

## 9. 后续 agent 不应做的事

- 不要查看或修改归档 Python 内容；
- 不要删除 Windows 托盘、快捷键或前台控制功能；
- 不要把 Linux 改造成带 UI 的常驻程序；
- 不要把 `SERVER_IP` 删除或改成默认请求目标；
- 不要为了自定义证书再次关闭全部 TLS 校验；
- 不要未经协议验证把 GET 改成 POST；
- 不要引入跨平台 GUI、IoC、插件系统、连接池或线程池来解决尚未证实的问题；
- 不要新增独立网络在线探测请求，除非真实故障证明现有登录请求不足；
- 不要把真实账号、密码、完整 URL 或完整响应提交到日志和版本库。

## 10. 最小验证清单

修改后至少完成与变更相关的检查：

```text
[ ] git diff --check
[ ] Linux 源码可用仓库记录的 g++ 命令编译
[ ] Windows 源码可用 MinGW 命令编译（若环境具备）
[ ] 无真实凭据的配置错误返回 78
[ ] 响应分类离线样例通过
[ ] 默认 URL 仍使用 login.cqu.edu.cn
[ ] SERVER_IP 只影响高级连接地址，不改变逻辑主机名
[ ] TLS 校验和自定义 CA 行为符合部署要求
[ ] Windows 退出时所有线程先结束再释放句柄
[ ] Linux systemd unit 通过 systemd-analyze verify
[ ] 日志没有密码、完整登录 URL 或未经脱敏的响应正文
```
