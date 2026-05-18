# Security Policy

## Supported versions

`logparser` is distributed as a Go library and a CLI. Only the `main` branch
and the latest tagged release receive security fixes. Older tags are not
patched.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/nudgebee/logparser/security/advisories/new)
  for this repository (preferred).
- Email: `security@nudgebee.com`

Please include:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal log sample or code snippet.
- Affected version / commit SHA.
- Any suggested mitigation.

We aim to acknowledge reports within 3 business days and to provide a status
update within 10 business days. Once a fix is available we will coordinate a
disclosure timeline with the reporter.

## Scope

In scope:

- Parser crashes or excessive resource consumption on attacker-controlled
  log input (DoS).
- Bugs in the sensitive-data redaction patterns that cause secrets to leak
  through the sanitized output.
- Vulnerabilities in the CLI tooling that ships from this repository.

Out of scope:

- Findings in upstream dependencies — please report those to the relevant
  project.
- Reports that require an attacker to already control the host running
  `logparser`.

## Sensitive data in test fixtures

If you spot real-looking IDs, hostnames, internal paths, or secret-like
strings in test fixtures or sample data, please report it via the channels
above so we can scrub it. Do not paste the offending data into a public
issue.
