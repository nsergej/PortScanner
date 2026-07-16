# Contributing

Thank you for helping improve PortScanner. This project is a Delphi VCL desktop
application, so changes should keep the Windows GUI workflow simple and
reproducible.

## Before You Start

1. Open an issue for larger changes before implementing them.
2. Keep pull requests focused on one topic.
3. Do not include generated binaries, local IDE files, or scan reports unless
   they are intentional documentation samples.
4. Use clear commit messages.

## Development Environment

- Windows 10 or newer.
- Delphi 10.4 Sydney or a compatible Delphi version with VCL.
- Delphi command-line tools in `PATH` when building from a terminal.
- No third-party runtime libraries are required.

The application currently supports TCP scanning for numeric IPv4 addresses only.
Do not add host-name, IPv6, UDP, or multi-target behavior in an unrelated change.

## Branches

Use descriptive branch names:

```text
docs/update-build-guide
fix/stop-scan-state
feature/export-option
```

## Build

See the detailed build instructions in [`README.md`](README.md#build-requirements).

At minimum, verify one supported target before opening a pull request:

```powershell
Set-Location .\src
if (-not (Test-Path .\PortScanner.res)) {
    'MAINICON ICON "forbidden.ico"' | Set-Content -Encoding ASCII .\PortScanner.rc
    cgrc .\PortScanner.rc
}
Set-Location ..

$out = Join-Path (Get-Location) "build\Win32"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
dcc32 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

## Manual Test Checklist

For code changes, test the changed behavior directly:

1. Start `PortScanner.exe`.
2. Enter a permitted IPv4 target.
3. Scan a small port range.
4. Confirm that progress, stop behavior, and open-port count still work.
5. Confirm that HTML, CSV, and JSON reports are generated.
6. Open the generated reports and compare them with the UI.

For documentation-only changes, check Markdown rendering and every changed link.

## Security Expectations

Network scanning tools need careful handling:

- Do not weaken input validation.
- Do not log secrets or private network data in committed examples.
- Do not add automatic scanning of broad network ranges without explicit review.
- Keep generated reports local to the executable unless a user explicitly chooses
  another location in a reviewed change.

## Pull Request Checklist

Before requesting review:

- The branch is up to date with `main`.
- The pull request describes what changed and why.
- Documentation is updated when behavior changes.
- Build or manual validation results are included in the PR description.
- Generated artifacts are not committed accidentally.
