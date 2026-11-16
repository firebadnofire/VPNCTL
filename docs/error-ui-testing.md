# Error feedback checks

The active remote interface uses `ErrorFeedback.svelte` for operational errors,
including configuration retrieval dialogs. It shows the failed action and current
host/instance context, the supplied cause and remediation, and a collapsed
Technical details disclosure with the code, stage and existing safe diagnostics.
Missing diagnostics are explicitly identified. Runtime-change/recovery warnings
remain visible without opening details. Dismissing an error does not resolve a
revision conflict or pending operation.

Generic validation errors must not claim fields were highlighted. Native form
constraints provide field feedback; server prerequisites provide their own
message. A runtime backup requires successful deployment. Its recovery action
opens Deployment; preview and apply remain separate explicit actions. Older
helpers' backup message and misleading highlighted-fields advice are handled by
the desktop as well, without a protocol/schema change.

Run `pnpm --dir apps/desktop dev:web`, then open
`http://127.0.0.1:1420/src/test/errors.html` for disposable component fixtures.
This development-only entry is not part of the production web build and issues
no native commands or server connections. Check Backup, Deployment, Conflict,
Connection and Validation at the supported 800×600 minimum and desktop size.
Use Tab/Enter/Space to operate Technical details and dismissal. Check multiline
output wrapping, actual required-field feedback, and recovery guidance. The
full application workflow tests separately verify backup navigation, retained
conflicts, failed deployment and unrelated-success error persistence.

Validation performed on macOS with Node 24.18.0, pnpm 11.9.0 and Rust 1.97.1:
component/browser checks at 800×600 and 1280×800, frontend check/tests/build,
application Rust tests, formatting and strict application Clippy. Windows native
rendering and assistive-technology announcement delivery require platform checks;
semantic alerts/disclosures are covered here without mutating a managed server.
