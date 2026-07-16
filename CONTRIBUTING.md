# Contributing to PortScanner

Thank you for contributing to PortScanner. Keep changes focused, factual, compatible with the existing project, and easy to review.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before Opening an Issue

1. Search existing issues and pull requests for the same topic.
2. Confirm that the issue applies to the current source or documented release.
3. Remove credentials, tokens, private IPv4 addresses, internal host names, and other confidential data.
4. Use the appropriate bug-report or feature-request template.

For a bug report, include:

- PortScanner version or commit
- Windows version
- Delphi version for build problems
- A concise problem description
- Minimal reproduction steps
- Expected and actual behavior
- Relevant error text with sensitive data removed

Do not use public issues for potential security vulnerabilities. Follow [SECURITY.md](SECURITY.md) instead.

## Responsible Testing

Test network-related changes only on systems and networks that you own or are explicitly authorized to use. A contribution must not contain scan results or target details from an unauthorized system.

## Development Environment

Source changes must remain compatible with Embarcadero Delphi 10.4 Sydney and the Windows VCL framework. Follow [BUILDING.md](BUILDING.md) for the current Win32 project setup.

Documentation-only changes do not require compiling or running the application, but they must accurately describe behavior present in the source.

## Create a Branch

Create a separate branch from an up-to-date `main` branch. Use a short descriptive name, for example:

```text
fix/progress-counter
docs/export-format-description
feature/configurable-timeout
```

Keep unrelated code, formatting, generated files, and documentation changes out of the branch.

## Commit Messages

Write concise imperative messages that identify the change. A conventional prefix is encouraged:

```text
fix: correct scan progress counter
docs: clarify automatic report export
refactor: simplify result formatting
```

Each commit should represent one logical change. Do not commit executables, DCUs, IDE caches, local project settings, or other generated output unless maintainers explicitly request them.

## Pull Request Requirements

Open pull requests against `main`. The description should include:

- What changed and why
- User-visible behavior affected by the change
- Files or components involved
- Build configuration used, when applicable
- Tests or manual checks actually performed
- Known limitations or follow-up work

Do not state that a build or test passed unless it was actually run. Keep the pull request small enough to review and do not combine unrelated fixes.

## Source-Code Requirements

- Preserve Delphi 10.4 Sydney compatibility.
- Preserve the VCL desktop application model.
- Keep UI updates synchronized with the main thread.
- Keep shared worker data correctly synchronized.
- Handle Windows and WinSock errors without exposing sensitive information.
- Avoid new dependencies unless their need and licensing are clearly justified.
- Update documentation when behavior, requirements, report fields, or user-visible text changes.

## Documentation Requirements

- Write clear professional English.
- Use `PortScanner`, `TCP port scanner`, `IPv4 address`, `open ports`, and `response time` consistently.
- Use relative links for repository files.
- Keep README examples synchronized with `docs/sample_report.csv`, `docs/sample_report.html`, and `docs/sample_report.json`.
- Do not document IPv6, DNS host-name scanning, manual export, configurable workers, or other features absent from the current source.
- Update [CHANGELOG.md](CHANGELOG.md) for notable user-facing changes.

## Validation

For source changes:

1. Build the affected Win32 Debug or Release target with Delphi 10.4.
2. Review all compiler errors and warnings.
3. Run only the minimum authorized manual scenario needed to verify the change.
4. Record the exact checks in the pull request.

For documentation changes:

1. Review the rendered GitHub Markdown structure.
2. Check relative links and file names.
3. Validate YAML issue forms when changed.
4. Parse JSON and review CSV and HTML samples when changed.
5. Confirm through `git diff` that no Delphi source or generated files were modified unintentionally.

## Review Checklist

- The contribution has one clear purpose.
- Claims match the current implementation.
- Delphi 10.4 compatibility is preserved for source changes.
- Relevant validation is documented honestly.
- No credentials, private network details, or confidential data are included.
- Security-sensitive information is reported privately.
