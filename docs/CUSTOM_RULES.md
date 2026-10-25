# Configuring PrufGate (`.prufgate/config.yaml`) & Custom Rules

PrufGate runs out-of-the-box with zero configuration required. To customize rule packs, authentication guards, multi-tenant scoping keys, exemptions, or technical debt ratchets, create `.prufgate/config.yaml` (or run `prufgate init`).

---

## 1. Universal `.prufgate/config.yaml` Schema

```yaml
# Rule packs to enable (core, web-ui, ai-safety, cti)
packs:
  - core
  - web-ui
  - ai-safety

# Paths/globs excluded across all 6 engines
exclude:
  - dist/
  - build/
  - vendor/
  - fixtures/

# Custom authentication guard function/decorator names (Engine 5 & Engine 6)
auth_guards:
  - requireAuth
  - verifySession
  - Depends(get_current_user)
  - "@PreAuthorize"

# Custom multi-tenant isolation column/parameter names (Engine 5: BOLA)
tenant_keys:
  - tenant_id
  - org_id
  - organization_id
  - workspace_id
  - account_id

# Files authorized to assign .score or .reputation (Engine 1)
score_owners:
  - src/billing/pricing.ts

# Reviewed false-positive exemptions (stale entries fail full sweeps)
exempt:
  - path: src/components/ExampleInput.tsx
    rule: documentation-address
    reason: Placeholder text for the input box, never returned as runtime data

# Tracked technical debt (reason must start with an issue reference like #42:)
known_debt:
  - path: src/legacy/feed.ts
    rule: demo-named-data
    reason: "#42: Replace legacy sample feed before the next release"
```

---

## 2. Project-Specific AST-grep Rules (`.prufgate/rules/`)

When `ast-grep` is installed, PrufGate automatically executes any custom structural AST rules placed in `.prufgate/rules/*.yml` or `.prufgate/rules/*.yaml`.

PrufGate ships one built-in rule, `configs/ast-grep/rules/action-authorization-guard.yml` (exported server actions must call an auth guard), applied to JavaScript/TypeScript projects. Two opinionated rules are provided as examples only, because they suit some architectures and not others: `configs/ast-grep/examples/db-pool-isolation.yml` (no `new Pool()` outside a database module) and `configs/ast-grep/examples/go-egress.yml` (no bare `http.Get` / `http.DefaultClient` in Go). Copy one into `.prufgate/rules/` to turn it on.

A rule that ast-grep cannot run is reported as an error, never as an empty result.

Example `.prufgate/rules/no-raw-sql.yml`:
```yaml
id: no-raw-sql-query
message: Use parameterized queries instead of raw string concatenation
severity: error
language: TypeScript
rule:
  pattern: db.execute(`SELECT $$$`)
```

---

## 3. Custom Audit Hooks (`.prufgate/hooks/`)

Scripts in `.prufgate/hooks/*.py` or `.prufgate/hooks/*.sh` run during `./prufgate.sh fast` and `./prufgate.sh full` **only when the operator sets `PRUFGATE_ALLOW_REPO_HOOKS=1`**. They are code from the repository being scanned, so running them by default would let any pull request execute commands on the scanning machine. Leave the variable unset in CI jobs that scan untrusted pull requests. A hook that exits non-zero is reported as a failed gate.
