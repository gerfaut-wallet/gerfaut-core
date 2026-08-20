# Security policy

Gerfaut is a watch-only Bitcoin wallet. It never generates, stores, or handles private keys, and it never signs transactions. Even so, wallet software carries real risk: extended public keys, descriptors, addresses, and balances are sensitive data, and a flaw in what the app displays or in how it alerts you can be used to misdirect funds. Security reports are taken seriously and handled as a priority.

## Reporting a vulnerability

Do not report security vulnerabilities through public issues, discussions, or pull requests.

- Email: info@pandul.fr (Loïc Morel, maintainer)
- Once this repository is public, GitHub [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) will also be enabled (Security tab, then "Report a vulnerability") and will become the preferred channel.

Please include as much of the following as you can:

- The type of issue and the component or file affected
- Step-by-step reproduction instructions, or a proof of concept
- The impact as you assess it, meaning what an attacker gains
- Any suggested remediation

Reports are welcome in English or French.

## What to expect

- Acknowledgement within 7 days.
- A triage verdict (accepted, duplicate, needs more information, out of scope) as soon as the issue is understood, with status updates while a fix is in progress.
- Coordinated disclosure: please keep the issue confidential until a fix is released. Accepted issues are fixed before any public disclosure, and reporters are credited in the release notes unless they prefer to remain anonymous.
- There is no bug bounty program at this time.

## Scope

In scope, in decreasing order of severity:

- Anything that could lead to loss of funds through misdirection: address substitution, tampering with balance or transaction display, malicious descriptor handling
- Leakage of wallet data: extended public keys, descriptors, addresses, balances, transaction history
- Suppression, forgery, or delay of security alerts
- Remote code execution, or compromise of the dependency chain or build pipeline

Out of scope:

- Attacks requiring a fully compromised device or operating system
- Social engineering of users or the maintainer
- Denial of service against third-party public infrastructure (for example public Esplora instances)
- Vulnerabilities in dependencies that are already publicly known and tracked upstream, unless Gerfaut's usage makes them exploitable in a specific way, in which case please do report

## Supported versions

Gerfaut is pre-release. No version is supported yet; report findings against the `main` branch. A supported-versions table will be published with the first release.

## Safe harbor

Good-faith security research conducted on your own instances and data is welcome. No legal action will be taken against researchers who follow this policy, avoid privacy violations and service disruption, and allow reasonable time for remediation.
