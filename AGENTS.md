# Repository instructions

## Scope

- The maintained implementation is the platform-specific C++ code under `src/linux/` and `src/windows/`.
- The Python version is no longer maintained. Do not inspect or modify its archived contents.
- Linux and Windows are separate implementations with separate `config.yaml` files; do not assume changes in one are shared by the other.
- `src/linux/autologin-cqu.service` is a systemd template containing `<USERNAME>` and `<PROGRAM_DIR>` placeholders. The complete deployment procedure is in `linux_systemd-setup.md`.

## Build and verification

- No build system, test suite, formatter, linter, type checker, or CI workflow is present. Verify C++ changes by compiling the affected source directly.
- Linux (run from `src/linux/`, with the libcurl development package installed): `g++ AutoLogin-CQU.cpp -o AutoLogin-CQU -lcurl -O2`
- Windows MinGW (run from `src/windows/`): `g++ AutoLogin-CQU.cpp -o AutoLogin-CQU.exe -lwinhttp -liphlpapi -lws2_32 -lshell32 -luser32 -static`
- The C++ programs are long-running network clients; a real run requires valid credentials, the adjacent config file, and access to the CQU portal. Do not expose `config.yaml` or full logs because they contain credentials and may contain IPs/portal responses.

## Runtime details

- Linux C++ reads `config.yaml` from the process working directory, so `config.yaml` must be beside the executable and systemd `WorkingDirectory` must point there.
- Windows C++ resolves `config.yaml` relative to the executable directory.
- The Linux binary returns exit code `78` for missing/invalid account configuration; the provided service uses `RestartPreventExitStatus=78` to avoid restart loops.
- `SERVER_IP` bypasses DNS resolution but requests still send the portal `Host` header; `LOGIN_IP` overrides the client IPv4 submitted to the portal. Treat both as deployment-specific settings, not code defaults.

## Editing conventions

- Keep platform-specific behavior in its existing platform source; avoid introducing a cross-platform abstraction unless both implementations actually need it.
- Preserve the existing line-ending style (LF) and concise C++ style. Do not add dependencies or generated/build artifacts to the repository.
