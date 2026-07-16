# Building PortScanner

This document describes the build state that is confirmed by the current
repository contents.

## Confirmed Environment

- Project type: Delphi VCL desktop application.
- Confirmed compiler: Embarcadero Delphi 10.4 Sydney command-line tools
  (`dcc32` and `dcc64` from Studio 21.0).
- Entry point: `src/PortScanner.dpr`.
- Form: `src/Unit1.dfm`.
- Main source: `src/Unit1.pas`.
- Resource source: `src/PortScanner.rc`.
- Project icon asset: `src/forbidden.ico`.

The repository does not currently track a `.dproj` file. Open
`src/PortScanner.dpr` directly in Delphi.

## Resource File

`PortScanner.dpr` uses this resource directive:

```delphi
{$R PortScanner.res PortScanner.rc}
```

The tracked `PortScanner.rc` file is the source for the generated
`PortScanner.res` binary resource. Do not commit generated `.res` files.

## Build With Delphi IDE

1. Open RAD Studio or Delphi.
2. Open `src/PortScanner.dpr`.
3. Select `Win32` or `Win64`.
4. Select `Debug` or `Release`.
5. Build the project.

If the IDE asks to save a `.dproj`, review the generated file before committing
it. Do not add a hand-written placeholder `.dproj`.

## Build Win32 From PowerShell

Run from the repository root in a Delphi-enabled shell:

```powershell
$out = Join-Path (Get-Location) "build\Win32"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
dcc32 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

Output:

```text
build\Win32\PortScanner.exe
```

## Build Win64 From PowerShell

Run from the repository root in a Delphi-enabled shell:

```powershell
$out = Join-Path (Get-Location) "build\Win64"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Push-Location .\src
dcc64 -B -E"$out" -N0"$out" -NH"$out" -NO"$out" -NB"$out" .\PortScanner.dpr
Pop-Location
```

Output:

```text
build\Win64\PortScanner.exe
```

## Typical Build Problems

### `Vcl.Samples.Spin` cannot be found

Install or enable the VCL sample controls package in Delphi.

### `PortScanner.res` should not be committed

The resource is generated from `src/PortScanner.rc`. Keep the `.rc` source and
icon asset tracked, and keep generated `.res` files ignored.

### Mixed Win32 and Win64 unit output

Use separate output directories for each platform. The documented commands place
DCU and executable output under `build\Win32` or `build\Win64`.
