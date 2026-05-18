# Contributing

Thanks for your interest in contributing to `logparser`. This repository is a
fork of [coroot/logparser](https://github.com/coroot/logparser) maintained by
Nudgebee. Contributions are welcome via GitHub issues and pull requests.

## Reporting issues

- Search [existing issues](https://github.com/nudgebee/logparser/issues) first
  to avoid duplicates.
- Include a minimal log sample that reproduces the problem when filing parser
  bugs. **Do not paste real production data** — scrub any IDs, hostnames,
  internal paths, secrets, or PII before posting. The `aaaaaaaa-…`,
  `example-org/…`, and `/app/example/…` placeholders used in the test fixtures
  are good models to follow.
- Include the Go version (`go version`) and OS.

## Reporting security issues

Please report security vulnerabilities privately following [SECURITY.md](./SECURITY.md).
Do not file public issues for vulnerabilities.

## Pull requests

1. Fork the repo and create a topic branch from `main`.
2. Run `go build ./...` and `go test -race ./...` locally. CI runs both on
   every PR.
3. Run `go vet ./...` and `gofmt -s -w .` before pushing.
4. Keep changes focused. Unrelated cleanups belong in separate PRs.
5. Write commit messages in the imperative mood (`fix: …`, `feat: …`,
   `docs: …`) so they read consistently with the existing history.
6. PR descriptions should explain *why* the change is needed, not just what
   it does. Link any related issues.

## Test fixtures

The pattern, parser, and level tests rely on synthetic log lines. When adding
a new fixture, prefer obviously fake placeholders (`example.com`,
`aaaaaaaa-0000-0000-0000-000000000000`, etc.) over anything that resembles a
real customer record, hostname, or internal service name.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License, Version 2.0](./LICENSE), the same license as the rest of the
project.
