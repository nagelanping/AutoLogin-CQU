# Repository instructions

## Scope

- The maintained implementation is the platform-specific C++ code under `src/linux/` and `src/windows/`.
- The Python version is no longer maintained. Do not inspect or modify its archived contents.
- Linux and Windows are separate implementations with separate `config.yaml` files; do not assume changes in one are shared by the other.
- `src/linux/autologin-cqu.service` is a systemd template containing `<USERNAME>` and `<PROGRAM_DIR>` placeholders. The complete deployment procedure is in `linux_systemd-setup.md`.
- `windows-headless-setup.md` is the step-by-step Task Scheduler guide for running the Windows build unattended (hidden window, start at logon). Update it if the Windows CLI or config keys change.

## Status

- Linux: feature-complete and verified on a real campus network deployment (v2).
- Windows: aligned with Linux on connection/security semantics, config validation, response classification, address selection, and `--self-test`. Still to verify on a real desktop: long-run shutdown, partial thread-creation failure, tray behavior under Windows Terminal.
- Intentional platform asymmetries: `CA_BUNDLE` is Linux-only (WinHTTP has no public option to replace the system trust store; install internal CAs via certmgr.msc); `DEBUG_RESPONSE` is Windows-only.
- Historical audit and change log (v1 to v2) are read-only archives under `archive/dev-log/v1-to-v2/`. Record new work in fresh log files, not in the archives.

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
