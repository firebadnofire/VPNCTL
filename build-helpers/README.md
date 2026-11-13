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

Tagged Forgejo CI releases are also mirrored to
`https://github.com/firebadnofire/VPNCTL`. Configure the Forgejo Actions secret
`GH_KEY` with GitHub repository Contents read/write permission. Each packaging
job safely synchronizes the immutable release tag and replaces only the assets
it built; an existing GitHub tag pointing at another commit is never forced.
Every published artifact is accompanied by a verified detached armored GPG
signature named `<artifact>.asc`. Configure `CI_KEY` as the base64 encoding of
exactly one GPG private key and set its passphrase in `CI_KEY_PASSPHRASE`.
Signing uses an isolated temporary GPG home that is removed after each job.

The clean helpers remove only these generated paths:

- `target`
- repository and desktop `node_modules`
- `apps/desktop/dist`

The Linux builder image is retained as a cache. Set
`VAM_CLEAN_DOCKER_IMAGE=1` when invoking `linux/clean.sh` to remove it too.

## Embedded server helpers

Release desktop builds require matching Linux x86_64 and aarch64 helper payloads
in `target/vam-server-dist/<architecture>-unknown-linux-musl/vam-server`.
Run `bash build-helpers/server/bundle.sh` with Docker and amd64/arm64 emulation
before packaging, or set `VAM_HELPER_BUNDLE_DIR` to that directory from a trusted
build of the same source. Never use an unverified downloaded executable here:
the desktop package's signature covers these embedded bytes.

The helper builder pins Rust 1.97.1 and the existing immutable Node Bookworm base,
uses musl and vendored OpenSSL, runs a storage-free executable check, and emits
SHA-256 sidecars. Helper builds transfer tracked working-tree files through the
Docker API and copy checked artifacts back; the checkout need not exist at the
same path on the Docker daemon host. Stage new source files before bundling.
Ignored/untracked files and Git metadata are not transferred. The builder image
uses an empty build context, and build containers retain normal SELinux confinement.
Cargo and compilation caches live in named Docker volumes, retained across runs.
Set `VAM_HELPER_BUILD_NAMESPACE` to isolate image/cache names (default
`vpnctl-helper`).
Build containers default to 4 CPUs/6 GiB (`VAM_HELPER_BUILD_CPUS` and
`VAM_HELPER_BUILD_MEMORY` override these). `VAM_HELPER_ARCHITECTURES=x86_64` can
limit a development validation build; production packaging requires both.
Tagged release CI builds these artifacts once, then embeds the same artifacts in
each desktop package. Debug builds allow absent payloads and report automatic
repair as unavailable rather than downloading replacement code. Release builds
fail clearly when either payload is absent or has the wrong ELF architecture.

`tests/helper-update/installer.sh` exercises install, idempotence, checksum/ABI
failure, post-install rollback, symlink refusal, and control-data preservation.
Run it only in a disposable Linux container with
`VPNCTL_DISPOSABLE_INSTALLER_TEST=1`; optionally set `VPNCTL_TEST_HELPER` to a
built static helper to exercise the real executable. Never run this root-path
fixture on a managed host.

For the complete SSH/SFTP repair acceptance check, see
[`tests/helper-update/README.md`](../tests/helper-update/README.md). It uses a
loopback-only disposable SSH container and generated keys, not a managed server.

The helper release job bootstraps missing Linux tools before checkout. It needs
an apt-based job image and an existing reachable Docker endpoint. Runner setup
must supply that endpoint; installing the Docker CLI does not start a daemon or
grant socket access. Prefer an isolated builder as described in the
[Forgejo Docker access documentation](https://forgejo.org/docs/latest/admin/actions/docker-access/).

Run `bash tests/build-helpers/helper-bundle.sh` on a Docker host with amd64/arm64
emulation to check source/artifact transfer and failure cleanup without compiling
Rust. The test uses isolated image/cache names and removes its containers/caches.
