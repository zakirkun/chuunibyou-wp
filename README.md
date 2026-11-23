# wpforge

`wpforge` is a Go + tview WordPress security research framework for authorized home-lab testing. It discovers compiled-in modules, runs the automatic scan pipeline, chains credentials between stages, and exposes returned webshell/reverse-shell sessions through the TUI.

## Requirements

- Go 1.25 or newer.
- Network access to the authorized WordPress lab target.
- Optional: a local checkout or reachable URL for SecLists wordlists. The built-in presets use `danielmiessler/SecLists` raw URLs.

## Build and verify

```powershell
gofmt -w internal\...
go vet ./...
go build -o wpforge.exe ./cmd/wpforge
```

There are currently no repository tests. `go vet ./...` and the build are the focused verification commands.

## Run

Pre-seed the target from the command line:

```powershell
.\wpforge.exe -target http://127.0.0.1:8080
.\wpforge.exe -target http://127.0.0.1:8080 -user admin -pass 'lab-password'
.\wpforge.exe -target http://127.0.0.1:8080 -timeout 30
```

Or start without flags and press **Ctrl+T** to enter the target, optional credentials, and timeout.

After the target is saved, the scan starts automatically. There is no module-selection step. The CLI target must be an absolute `http://` or `https://` URL; `-user` and `-pass` require `-target`:

1. Recon modules fingerprint WordPress and enumerate exposed routes/plugins.
2. Access and exploit modules run with their declared defaults.
3. Successful credentials are chained into the target state.
4. Authenticated backdoor modules upload token-gated shells and attempt the configured callback flow.
5. Returned sessions are registered automatically.

Press **Ctrl+C** once to cancel a running scan, again to quit. Press **Ctrl+T** to edit the target, but target replacement is blocked while a scan is active. Press **Ctrl+S** to open the sessions console, select a session with Enter, use `r` to refresh and `k` to kill the selected session, and type commands into the terminal prompt.

The automatic reverse-shell callback currently defaults to `127.0.0.1:4444` in the pipeline. For a non-local lab target, use the dedicated backdoor/chain parameters or update the pipeline default before running.

## Architecture

- `cmd/wpforge`: CLI flags and application startup.
- `internal/tui`: target prompt, console, automatic scan launch, and session UI.
- `internal/scan`: ordered pipeline that iterates `registry.All()`; it does not maintain a manual module list.
- `internal/module`: module contract, target state, credentials, parameters, and results.
- `internal/registry`: module registration and lookup.
- `internal/modules/recon`: fingerprinting and exposure discovery.
- `internal/modules/access`: XML-RPC and `wp-login.php` credential modules.
- `internal/modules/exploit`: CVE/EDB-specific HTTP modules.
- `internal/modules/backdoor`: authorized shell upload, reverse deployment, and full chain modules.
- `internal/engine`: shared HTTP behavior, cookies, WordPress login, forms, and multipart uploads.
- `internal/wordlist`: SecLists presets plus URL, local-file, and inline list loading.
- `research_notes/WordPress CVE exploit modules`: source-backed research used to implement CVE recipes.

## Adding a module

Implement `module.Module` with `Meta`, `Params`, and `Run`. Give every parameter a safe default because the automatic pipeline invokes modules without opening a form. Register the module in `init()` and ensure its package is side-effect imported from `internal/modules/modules.go`. Use a verified endpoint recipe, preserve the shared target client, return structured artifacts, then run:

```powershell
gofmt -w <changed-files>
go vet ./...
go build -o wpforge.exe ./cmd/wpforge
```

For upload modules, use token-gated payloads and register successful webshells through `shell.M().RegisterWebshell(...)`; reverse callbacks are registered by `shell.StartListener(...)`.

## Safety

Use only against systems you own or are explicitly authorized to test. Modules can perform state-changing requests, upload files, create credentials, and open shell sessions; use disposable lab targets and clean up artifacts after testing.
