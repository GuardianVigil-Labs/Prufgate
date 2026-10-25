## What and why

## Checks
- [ ] `python3 prufgate/cli.py --self-check` passes.
- [ ] `python3 -m unittest discover -s tests` passes (it includes the leak guard).
- [ ] `ruff check --config configs/ruff.toml prufgate/ tests/` passes.
- [ ] A rule change has a fixture it must match and a near miss it must not.
- [ ] Docs and `CHANGELOG.md` updated where behaviour changed.

## Before you open this (the repository is public)
- [ ] No private code, personal data, local paths, hostnames or credentials in the diff, the commit messages or this description.
- [ ] Fixtures use invented examples (`example.com`, documentation IP ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
