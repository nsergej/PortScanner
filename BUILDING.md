# Building PortScanner

## Supported Build Target

The repository documents the **32-bit Windows** target with Embarcadero Delphi 10.4 Sydney. A Win64 project configuration is not tracked in the repository and is therefore not documented as a supported build target.

## Prerequisites

- Embarcadero Delphi 10.4 Sydney
- Windows VCL application development components
- The Delphi 32-bit Windows compiler
- A writable local copy of the repository

No third-party Delphi packages are referenced by the current source.

## Required Repository Files

Keep these files together in the `src` directory:

| File | Purpose | Required for build |
|---|---|---|
| `PortScanner.dpr` | Program entry point | Yes |
| `Unit1.pas` | Form logic, worker threads, WinSock operations, and export | Yes |
| `Unit1.dfm` | VCL form definition paired with `Unit1.pas` | Yes |
| `forbidden.ico` | Application icon source | Required for the documented resource setup |
| `forbidden.png` | Image asset included with the source | No direct reference in the current project source |

The program entry point contains `{$R *.res}`. The corresponding `PortScanner.res` file is generated locally and is not tracked in the repository.

## Create the Local Delphi Project Configuration

1. Start Embarcadero RAD Studio 10.4.
2. Select **File > Open**.
3. Open `src/PortScanner.dpr`. Do not open `Unit1.pas` as a standalone project.
4. If RAD Studio asks to create or save project metadata, save the generated `PortScanner.dproj` in the `src` directory.
5. Select **File > Save All**.

The generated `.dproj`, `.dproj.local`, `.res`, compiler output, and IDE cache files are local build artifacts unless the repository explicitly starts tracking them later.

## Configure the Project Resource

1. Open **Project > Options**.
2. Select **Application > Icons**.
3. Load `src/forbidden.ico` as the application icon.
4. Apply the setting and select **Save All**.

This step creates or updates `PortScanner.res`, which is required by the resource directive in `PortScanner.dpr`.

## Configure the VCL Style

The current `PortScanner.dpr` requests the `Auric` VCL style at startup.

1. Open **Project > Options**.
2. Select **Application > Appearance**.
3. Enable the `Auric` custom style.
4. Apply the setting and select **Save All**.

If the style is not included in the generated project resources, the application can display `Style 'Auric' not found` at startup.

## Select Win32

In **Project Manager**, confirm that the active target platform is **32-bit Windows**. If it is not listed, add the 32-bit Windows platform through the project manager and select it before building.

Do not assume that Win64 is configured merely because the Delphi installation contains a 64-bit compiler.

## Debug Build

1. Select the **Debug** build configuration.
2. Confirm that **32-bit Windows** is active.
3. Select **Project > Build PortScanner**.
4. Review the Build output for compiler errors and warnings.

Depending on the generated project settings, the executable is normally written to a configured output directory such as `src/Win32/Debug`, or to `src` when no separate output directory is configured.

## Release Build

1. Select the **Release** build configuration.
2. Confirm that **32-bit Windows** is active.
3. Review project options that differ from Debug, including compiler diagnostics and runtime-package settings.
4. Select **Project > Build PortScanner**.
5. Review the Build output and locate `PortScanner.exe` in the configured Release output directory.

A common generated output directory is `src/Win32/Release`, but the actual location is controlled by the local `.dproj` settings.

## Command-Line Builds

Opening and saving the project in RAD Studio is required before relying on command-line builds because the repository does not track the `.dproj`, project resource, application icon configuration, or VCL style selection.

Use the RAD Studio command prompt only after the IDE project setup is complete. Build the generated `.dproj` so that its resource and style settings are applied; compiling `PortScanner.dpr` alone does not reproduce all generated project metadata.

## Verify a Local Build

For a build you perform locally:

1. Confirm that the compiler completed without errors.
2. Record the Delphi version, target platform, and Debug or Release configuration.
3. Start the executable only in an environment where application execution is permitted.
4. Confirm that the main form opens without a missing-resource or missing-style error.
5. Perform network-related checks only against systems you own or are authorized to test.

The repository does not currently provide an automated build or test workflow, so contributors must report the checks they actually performed.

## Common Build Problems

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for missing `PortScanner.res`, missing `Auric` style, report permissions, and runtime input errors.
