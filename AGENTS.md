# Repository instructions

## Scope

- The maintained implementation is the platform-specific C++ code under `src/linux/` and `src/windows/`.
- The Python version is no longer maintained. Do not inspect or modify its archived contents.
- Linux and Windows are separate implementations with separate `config.yaml` files; do not assume changes in one are shared by the other.
- `src/linux/autologin-cqu.service` is a systemd template containing `<USERNAME>` and `<PROGRAM_DIR>` placeholders. The complete deployment procedure is in `linux_systemd-setup.md`.

## Status

- Linux 端完成（v2.0.0）：四阶段 Linux 侧项全部完成并通过实机验证。
- Windows 端：第一阶段（连接与安全）与第二阶段（协议行为，含 `--self-test`）全部完成；第三阶段代码已改进并通过交付前安全扫描，项级验证（长时运行退出、部分线程创建失败、Windows Terminal 托盘场景）待真实桌面环境。
- v1.x.x → v2.0.0 的改进计划与执行记录归档于 `archive/dev-log/v1-to-v2/`（AUDIT.md、LOG.md），为历史快照，不再更新；新问题的修复直接记录到新的日志文件中。
- 双端不对等项（有意保留）：`CA_BUNDLE` 仅 Linux 支持（WinHTTP 无替换系统信任库的公开选项，内部 CA 装系统信任库）；`DEBUG_RESPONSE` 仅 Windows 支持。

## Build and verification

- No build system, test suite, formatter, linter, type checker, or CI workflow is present. Verify C++ changes by compiling the affected source directly.
- Linux (run from `src/linux/`, with the libcurl development package installed): `g++ AutoLogin-CQU.cpp -o AutoLogin-CQU -lcurl -O2`
- Windows MinGW (run from `src/windows/`): `g++ AutoLogin-CQU.cpp -o AutoLogin-CQU.exe -lwinhttp -liphlpapi -lws2_32 -lshell32 -luser32 -static`
- Quick offline check (no config, no network; exit 0 = pass): `./AutoLogin-CQU --self-test` (Linux) or `AutoLogin-CQU.exe --self-test` (Windows). 19 cases, identical on both platforms.
- The C++ programs are long-running network clients; a real run requires valid credentials, the adjacent config file, and access to the CQU portal. Do not expose `config.yaml` or full logs because they contain credentials and may contain IPs/portal responses.

## Runtime details

- Linux C++ reads `config.yaml` from the process working directory, so `config.yaml` must be beside the executable and systemd `WorkingDirectory` must point there.
- Windows C++ resolves `config.yaml` relative to the executable directory.
- Both binaries return exit code `78` for missing/invalid account configuration; the Linux service uses `RestartPreventExitStatus=78` to avoid restart loops.
- Windows launched by double-click waits for Enter before exiting when the exit code is non-zero, so errors remain visible; interactive-console detection must keep pipeline/hidden-console/service launches unblocked.
- `SERVER_IP` pins the connect address but requests still send the portal `Host` header and keep the domain for SNI/certificate validation; `LOGIN_IP` overrides the client IPv4 submitted to the portal. Treat both as deployment-specific settings, not code defaults.

## Editing conventions

- Keep platform-specific behavior in its existing platform source; avoid introducing a cross-platform abstraction unless both implementations actually need it.
- Preserve the existing line-ending style (LF) and concise C++ style. Do not add dependencies or generated/build artifacts to the repository.
