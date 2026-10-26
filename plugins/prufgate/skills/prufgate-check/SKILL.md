---
name: prufgate-check
description: Run PrufGate on the changed files (prufgate check --changed) and summarise the findings. Use before saying a coding task is done, or when asked to run PrufGate.
argument-hint: "[base-ref]"
allowed-tools: Bash(prufgate check *)
---

Run PrufGate on what this branch changed, from the repository root:

```sh
prufgate check --changed --format json
```

Base ref given by the user, if any: `$ARGUMENTS`. When there is one, add `--base <ref>` to the command.

If `prufgate` is not found, stop and tell the user to install it (`pipx install prufgate`). Do not report the work as checked.

Read the exit code:

- **0**: clean. Say so in one line.
- **1**: blocking findings. List every P0 and P1 finding as `file:line rule-id: message`, then the count of P2 and P3 findings. Fix the P0 and P1 findings in the code, then run the check again.
- **2**: PrufGate could not run (bad configuration, bad base ref, engine error). Show the error. The work is not checked; never call it a pass.

Never silence a finding by adding `prufgate-ignore` without a real reason after `--`, or by editing `.prufgate/` configuration.
