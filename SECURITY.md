# Security Policy

PortScanner is a local Windows desktop utility for TCP port scanning. It should
be used only on systems and networks where scanning is authorized.

## Supported Versions

Security fixes are accepted for the current `main` branch and the latest
published release, when a release exists.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` branch | Yes |
| Older releases | No |

## Reporting a Vulnerability

Please do not publish exploit details in a public issue.

Preferred reporting flow:

1. Use GitHub private vulnerability reporting or a GitHub Security Advisory for
   this repository if it is enabled.
2. If private reporting is not available, open a minimal public issue asking for
   a private contact path. Do not include sensitive technical details in that
   issue.
3. Include the affected version or commit, a concise impact summary, and safe
   reproduction steps.

## Scope

Security reports are most useful when they relate to:

- Unsafe file handling in report export.
- Incorrect input validation.
- UI behavior that causes unintended scans.
- Crashes or resource exhaustion caused by normal user input.
- Insecure use of Windows networking APIs.

The current application is IPv4-only and TCP-only. Lack of IPv6, UDP, host-name,
or multi-target scanning support is a feature request, not a security issue by
itself.

## Responsible Use

Unauthorized scanning may violate laws, contracts, or network policies. Users are
responsible for obtaining permission before scanning any target.
