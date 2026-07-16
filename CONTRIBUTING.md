# Contributing

Thank you for helping improve PortScanner. This project is a small Delphi VCL
application, so contributions should stay focused, buildable, and safe to use.

## Clone The Repository

```powershell
git clone https://github.com/nsergej/PortScanner.git
Set-Location PortScanner
```

## Create A Branch

Use a descriptive branch name:

```powershell
git switch -c fix/thread-lifecycle
```

## Development Environment

- Windows 10 or newer.
- Delphi 10.4 Sydney or a compatible Delphi version with VCL.
- Delphi command-line tools in `PATH` for terminal builds.
- No third-party runtime libraries are required.

Open the project from `src/PortScanner.dpr`. A `.dproj` file is not currently
tracked.

## Build

See [BUILDING.md](BUILDING.md) for complete instructions.

At minimum, verify one supported target before opening a pull request:

```powershell
$out = Join-Path (Get-Location) "build\Win32"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
dcc32 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

## Manual Testing

Follow [docs/TEST_PLAN.md](docs/TEST_PLAN.md) for manual validation. For code
changes, include the relevant checked scenarios in the pull request.

## Code Style

- Keep Delphi 10.4 compatibility.
- Keep the UI VCL-based.
- Preserve the current scope: TCP scanning of one numeric IPv4 address.
- Do not add stealth, evasion, credential testing, telemetry, or automatic
  network discovery.
- Do not commit generated binaries, `.res` files, DCUs, local IDE files, or real
  private scan reports.
- Update documentation when behavior changes.

## Pull Requests

Before requesting review:

- Rebase or merge the latest `main`.
- Describe what changed and why.
- List build and manual test results.
- Confirm no secrets, generated binaries, or private reports are included.
- Link related issues when applicable.
