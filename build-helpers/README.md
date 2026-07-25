# Platform build helpers

Each platform has a build and clean entrypoint:

| Platform | Build | Clean |
| --- | --- | --- |
| macOS | `build-helpers/mac/build.sh` | `build-helpers/mac/clean.sh` |
| macOS universal DMG | `build-helpers/mac/build-universal.sh` | `build-helpers/mac/clean.sh` |
| Windows | `build-helpers/windows/build.ps1` | `build-helpers/windows/clean.ps1` |
| Linux | `build-helpers/linux/build.sh` | `build-helpers/linux/clean.sh` |

Build helpers install JavaScript dependencies from `pnpm-lock.yaml`, use the
Rust version in `rust-toolchain.toml`, run the verification suite, and package
the Tauri application. The macOS helpers use `nvm` to install and select
Node.js 24.18.0 when the active `node` is missing or at a different version,
then activate pnpm 11.9.0 through Corepack. `build-helpers/mac/build.sh`
packages the current architecture as a `.app`; `build-helpers/mac/build-universal.sh`
adds the `x86_64-apple-darwin` and `aarch64-apple-darwin` Rust targets through
`rustup`, requires Apple's `lipo` and `hdiutil` tools, and builds a universal
`.app` plus `.dmg` under `target/universal-apple-darwin/release/bundle`.
The Windows helper also bootstraps
missing native build tools with `winget`: Visual Studio 2022 C++ Build Tools, Node.js 24.18.0,
Rustup/Rust 1.97.1 with `clippy` and `rustfmt`, Microsoft Edge WebView2
Runtime, NASM, NSIS, and pnpm 11.9.0 through Corepack. When a tool is missing,
the Windows helper lists the exact install action it will run and asks before
continuing. NASM is installed from the official portable ZIP under
`%LOCALAPPDATA%\dnswg\build-tools` because the Winget installer may register
successfully without making `nasm.exe` discoverable. Corepack pnpm shims are
also written under `%LOCALAPPDATA%\dnswg\build-tools` so the helper does not
require Administrator access. The helper writes an explicit `pnpm.cmd` shim
there and validates it with `cmd.exe`, matching the shell used by package
lifecycle scripts. Set `VAM_SKIP_CHECKS=1` for a packaging-only iteration, pass
`-SkipToolInstall` to make missing tools a hard error instead of installing
them, or pass `-AssumeYes` only when tool installation has already been approved
for the current machine. PATH updates are kept session-local and deduplicated so
reruns do not grow the environment.

The Linux helper always builds inside Docker. Its builder uses an immutable,
multi-platform Node 24.18.0 Bookworm image digest and pins Rust 1.97.1 and pnpm
11.9.0. Set `VAM_DOCKER_PLATFORM` to `linux/amd64` or `linux/arm64` to select a
platform explicitly.

The clean helpers remove only these generated paths:

- `target`
- repository and desktop `node_modules`
- `apps/desktop/dist`

The Linux builder image is retained as a cache. Set
`VAM_CLEAN_DOCKER_IMAGE=1` when invoking `linux/clean.sh` to remove it too.
