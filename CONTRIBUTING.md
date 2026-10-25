# Contributing

Thank you for helping. The most useful contributions are new rules with good fixtures, fixes for false positives, and support for more languages and frameworks.

1. Read the maintainer guide, [AGENTS.md](AGENTS.md) (for people and AI tools alike).
2. Branch from `main` and open a pull request. Direct pushes to `main` are not accepted; every change needs a code owner's review.
3. Before pushing, run:
   ```sh
   python3 prufgate/cli.py --self-check
   python3 -m unittest discover -s tests
   ruff check --config configs/ruff.toml prufgate/ tests/
   ```
4. A new or changed rule comes with at least one invented sample it must flag and one near miss it must not. A bug fix comes with a test that fails without it.
5. Fixtures use invented code, `example.com` domains and documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Never paste private code into a test, an issue or a pull request.

## Reporting a problem

- A bug: open a **Bug report** issue.
- A false positive or a missed pattern: open a **False positive or false negative** issue with a minimal invented sample.
- A new rule, pack, language or integration: open a **Rule, pack or feature request**.
- A security issue: report it privately, see [SECURITY.md](SECURITY.md).

## Licence of contributions

By opening a pull request you agree that your contribution is licensed under the [Apache License 2.0](LICENSE), like the rest of the project (section 5 of the licence).

## Maintainers

PrufGate is maintained by the GuardianVigil team, listed as the `@GuardianVigil-Labs/prufgate-maintainers` code owners. Maintainers review and merge pull requests, triage issues, and cut releases by pushing a `v*` tag, which only admins can create (`SECURITY.md` says how releases are built and verified). Decisions are made in public issues and pull requests; security reports stay private until fixed.
