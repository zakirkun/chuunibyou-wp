# Agent instructions

## Project shape

- This is a Go 1.25 module (`github.com/lab/wpforge`) with the executable entrypoint at `cmd/wpforge/main.go`.
- `internal/modules/modules.go` is the module wiring point: it imports module packages for `init()` registration; new module packages must be added there or they will not be discovered.
- `internal/registry` owns the runtime module list, while `internal/scan/pipeline.go` runs all registered modules automatically in recon → exploit/access → backdoor order.
- `internal/tui` is console-first: setting a target with Ctrl+T, or `-target`, starts the automatic scan; there is no manual module-selection workflow. Ctrl+S opens shell sessions.
- `internal/engine` owns the shared HTTP client, cookie jar, WordPress login, form requests, and multipart uploads; reuse it instead of creating ad-hoc clients in modules.
- `internal/shell` owns webshell/reverse sessions, and `internal/payload` owns token-gated PHP payload rendering.

## Commands

- Format changed Go files with `gofmt -w <files>`.
- Verify the repository with `go vet ./...`.
- Build the executable with `go build -o wpforge.exe ./cmd/wpforge`.
- Check CLI flags with `./wpforge.exe -h` (PowerShell: `./wpforge.exe -h`).
- Run with a target: `./wpforge.exe -target http://host[:port]`; optional credentials are `-user` and `-pass`.
- Use `-timeout <seconds>` to change the CLI HTTP timeout; CLI targets must be absolute HTTP(S) URLs, and credentials require `-target`.
- No test suite is currently present; do not claim tests passed when only vet/build were run.

## Development constraints

- This framework is for authorized WordPress lab environments. Preserve that scope in new module metadata, documentation, and user-facing help.
- CVE modules must use a verified HTTP recipe from the research notes or a cited primary source; do not invent endpoints, nonce names, fields, or success markers.
- Keep one CVE/module per file using the existing `cve_YYYY_NNNNN_name.go` or `edb_#####_name.go` naming style. Put shared exploit helpers in the existing package helper file.
- Module parameters must have defaults so the automatic pipeline can invoke every registered module without a manual form.
- Return findings through `module.Result`, chain credentials through `Result.Creds`, and expose shell/session identifiers in `Result.Artifacts`.
- Use `tview.Escape` for untrusted output before writing to the TUI; do not allow target responses to inject tview color markup.
- Do not use `as any`, `@ts-ignore`, or analogous type-error suppression; do not commit unless the user explicitly requests it.
