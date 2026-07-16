# Contributing to PortScanner

Thank you for contributing to PortScanner. Contributions should be focused, documented, and easy to review.

## Before You Start

- Search existing issues and pull requests before opening a new one.
- Use PortScanner only on systems and networks that you own or are authorized to test.
- Report security-sensitive problems privately by following [SECURITY.md](SECURITY.md).

## Development Setup

Code changes require Embarcadero Delphi 10.4 Sydney with the Windows VCL components installed. Follow the build procedure in [README.md](README.md#build-instructions-for-delphi).

Documentation-only changes do not require compiling or running the application.

## Contribution Workflow

1. Create a branch from `main` with a descriptive name.
2. Keep each contribution limited to one logical change.
3. Preserve the existing Delphi 10.4 and VCL compatibility requirements.
4. Do not commit generated executables, compiler output, or local IDE files unless the repository explicitly tracks them.
5. Update the documentation and `CHANGELOG.md` when behavior, requirements, or user-facing output changes.
6. Commit with a concise message that explains the purpose of the change.
7. Open a pull request against `main` and describe the change and its verification.

## Documentation Guidelines

- Write documentation in clear English.
- Use descriptive Markdown headings and meaningful link text.
- Keep line endings and file naming consistent with the repository.
- Use relative links for files stored in the repository.
- Keep README report examples synchronized with the files in `docs`.
- State explicitly when a feature or protocol is not supported. PortScanner supports IPv4 only.

## Validation

Before submitting a code change:

1. Build the affected target in Delphi 10.4.
2. Confirm that the compiler reports no errors.
3. Test the changed behavior on a system you are authorized to use.
4. Record the build configuration and manual checks in the pull request.

Before submitting a documentation-only change:

1. Review the rendered Markdown structure.
2. Check all relative links and file names.
3. Validate JSON, CSV, and HTML examples when they are changed.
4. Confirm that no generated or source-code files were modified unintentionally.

## Pull Request Checklist

- The change has a clear purpose and limited scope.
- Documentation matches the implemented behavior.
- Relevant validation has been completed and described.
- No sensitive information, credentials, or private network data is included.
- Security-sensitive details are not disclosed publicly.
