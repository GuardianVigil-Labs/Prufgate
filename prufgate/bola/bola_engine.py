#!/usr/bin/env python3
"""PrufGate Universal Multi-Tenant BOLA / IDOR Verification Engine (Engine 5).

Performs dual-mode Broken Object Level Authorization (BOLA/IDOR) verification across
Python (FastAPI, Django, Flask), TypeScript/Node.js (Next.js App/Pages Router, Express,
Fastify, NestJS), Go (net/http, Gin, Echo, Chi), Java/Kotlin (Spring Boot), Ruby (Rails),
and PHP (Laravel):

1. Universal Route & Dynamic Resource Parameter Discovery:
   - Discovers API endpoints and dynamic object ID parameters (`{id}`, `:id`, `[id]`, `<id>`)
     from OpenAPI/Swagger specs and framework route declarations.
2. Static Authorization & Tenant Isolation Verification (`static-bola-unscoped-access`):
   - Verifies that dynamic-ID route handlers enforce authentication guards (`auth_guards`)
     and scope database/ORM lookups by a tenant/owner key (`tenant_keys`) rather than
     querying solely by primary key.
   - Verifies Next.js Server Actions (`BOLA-UNGUARDED-SERVER-ACTION`) and SQL schema tables
     (`BOLA-TABLE-MISSING-TENANT-COLUMN`).
3. Live Two-Token Differential Matrix Probe (`BOLA-UNAUTHENTICATED-ACCESS`, `BOLA-CROSS-TENANT-ACCESS`):
   - Evaluates 4-request differential matrix (`Unauthenticated` vs `Tenant A -> Self` vs
     `Tenant A -> Tenant B` vs `Tenant B -> Tenant A`) with `curl` PoC generation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from prufgate import __version__  # noqa: E402
from prufgate.config import ConfigError, PrufGateConfig  # noqa: E402


class BolaFinding:
    """A static or dynamic BOLA / multi-tenant isolation finding."""

    def __init__(
        self,
        rule_id: str,
        severity: str,
        message: str,
        endpoint_or_file: str,
        line: int = 1,
        curl_poc: str = "",
        details: str = "",
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.endpoint_or_file = endpoint_or_file
        self.line = line
        self.curl_poc = curl_poc
        self.details = details

    @property
    def rule(self) -> str:
        return self.rule_id

    @property
    def path(self) -> str:
        return self.endpoint_or_file

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "target": self.endpoint_or_file,
            "file": self.endpoint_or_file,
            "line": self.line,
            "curl_poc": self.curl_poc,
            "details": self.details,
        }


@dataclass
class DiscoveredRoute:
    """A discovered API route across any supported web framework or OpenAPI spec."""

    path: str
    raw_path: str
    methods: list[str] = field(default_factory=lambda: ["GET"])
    framework: str = "generic"
    file_path: str = ""
    line: int = 1
    has_dynamic_param: bool = False
    param_names: list[str] = field(default_factory=list)
    handler_snippet: str = ""
    file_content: str = ""


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "reports",
    "out",
}

# PrufGate's own engine sources carry rule patterns as string literals. They are
# skipped only when PrufGate scans its own repository, never in a user's project.
INTERNAL_SCANNER_PATHS = ("prufgate/", "tests/")
_PRUFGATE_ROOT = _THIS_DIR.parent.parent

TEST_DIR_SEGMENTS = {"test", "tests", "__tests__", "spec", "specs", "test_samples", "testdata", "__mocks__"}
_TEST_FILE_RE = re.compile(
    r"(?:^test_.*\.py$|_test\.(?:py|go)$|^conftest\.py$|\.(?:test|spec)\.[cm]?[jt]sx?$"
    r"|(?:Test|Tests|Spec)\.(?:java|kt|cs|php|scala)$|_spec\.rb$)"
)


def is_test_path(rel_path: str) -> bool:
    """True for test files and files inside test directories, matched on whole path segments."""
    parts = rel_path.replace("\\", "/").split("/")
    return any(seg in TEST_DIR_SEGMENTS for seg in parts[:-1]) or bool(_TEST_FILE_RE.search(parts[-1]))


def is_self_scan(workspace: Path) -> bool:
    """True when `workspace` is the PrufGate checkout this engine runs from."""
    try:
        return workspace.resolve() == _PRUFGATE_ROOT
    except OSError:
        return False


def iter_workspace_files(workspace: Path, suffixes: set[str] | None = None) -> list[Path]:
    """Walk `workspace`, pruning SKIP_DIRS by name relative to the workspace (never its parents)."""
    skip_internal = is_self_scan(workspace)
    out: list[Path] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            p = Path(root) / name
            if suffixes is not None and p.suffix.lower() not in suffixes:
                continue
            if skip_internal and str(p.relative_to(workspace)).replace("\\", "/").startswith(INTERNAL_SCANNER_PATHS):
                continue
            out.append(p)
    return out


PUBLIC_ROUTE_KEYWORDS = (
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/metrics",
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/public",
    "/webhook",
    "/api-docs",
    "/openapi",
    "/swagger",
)

DEFAULT_AUTH_GUARD_PATTERNS = (
    r"\bassert[A-Z]\w*",
    r"\bverifySession\b",
    r"\bverify[A-Z]\w*",
    r"\brequireAuth\b",
    r"\brequire[A-Z]\w*",
    r"\bauth\s*\(",
    r"\bauthCheck\b",
    r"\bgetSession\b",
    r"\bgetCurrentUser\b",
    r"\bget_current_user\b",
    r"\bget_current_active_user\b",
    r"\bprotect[A-Z]\w*",
    r"\bcheckPermission\b",
    r"\bDepends\s*\(\s*(?:get_current\w*|require_\w*|verify_\w*|auth\w*)",
    r"@login_required\b",
    r"@permission_required\b",
    r"\bIsAuthenticated\b",
    r"@UseGuards\b",
    r"@PreAuthorize\b",
    r"@Secured\b",
    r"@RolesAllowed\b",
    r"\bauthenticate_user!\b",
    r"\bauth\(\)->",
    r"\bmiddleware\s*\(\s*['\"]auth",
)

DEFAULT_TENANT_KEYS = (
    "tenant_id",
    "tenantId",
    "organization_id",
    "organizationId",
    "org_id",
    "orgId",
    "workspace_id",
    "workspaceId",
    "user_id",
    "userId",
    "owner_id",
    "ownerId",
    "account_id",
    "accountId",
    "customer_id",
    "customerId",
    "member_id",
    "author_id",
    "created_by",
)

DB_OBJECT_LOOKUP_RE = re.compile(
    # Prisma / Drizzle / TypeORM / Mongoose / Sequelize
    r"\b(?:prisma|db|repo|repository|model|\w+Repository|\w+Repo|\w+Model|\w+Dao)\b[\s\S]{0,80}?\."
    r"(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findById|findOne|findByPk|update|delete|findByIdAndUpdate|findByIdAndDelete|getById|deleteById|getReferenceById)\s*\("
    # Sequelize / Mongoose / Spring Data lookups on any model, e.g. `Invoice.findByPk(id)`
    r"|\.(?:findByPk|findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|getReferenceById)\s*\("
    # Python SQLAlchemy / Django ORM / Tortoise
    r"|\b(?:db|session|async_session)\.(?:get|query|execute|scalar|scalars)\s*\("
    r"|\b[A-Z]\w*\.objects\.(?:get|filter)\s*\("
    r"|\bget_object_or_404\s*\("
    r"|\bfilter_by\s*\(\s*id\s*="
    # Go GORM / sqlx / database/sql
    r"|\b(?:db|tx|conn|r\.db|s\.db|h\.db)\.(?:First|Take|Last|Find|Delete|QueryRow|QueryRowContext|Get|Exec|ExecContext)\s*\("
    # Ruby ActiveRecord / PHP Eloquent
    r"|\b[A-Z]\w*(?:\.find|\.find_by|::find|::findOrFail)(?:\s*\(|\s+params\b)"
    r"|\.(?:find|find_by|findOrFail)\s*\(\s*(?:params\[|\$\w*id\b)"
    # Raw SQL by ID
    r"|\b(?:SELECT|UPDATE|DELETE)\b[\s\S]{0,100}?\bWHERE\s+id\s*=",
    re.MULTILINE,
)


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only within the target's origin (scheme, host, port).

    The target URL is checked before probing; a redirect to another origin (a
    metadata address, say) must not receive the probe or its bearer tokens. A
    refused redirect becomes an HTTPError and is recorded in `refused`, so the
    caller can report the routes it could not test instead of passing them."""

    def __init__(self, target_url: str, refused: list[str] | None = None):
        super().__init__()
        self.origin = _origin(target_url)
        self.refused = refused if refused is not None else []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) == self.origin:
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        self.refused.append(req.full_url)
        print(f"  [BOLA] Not following HTTP {code} redirect to another origin from {req.full_url}", file=sys.stderr)
        return None


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlparse(url)
    try:
        port = p.port or {"http": 80, "https": 443}.get(p.scheme)
    except ValueError:
        port = None
    return (p.scheme.lower(), (p.hostname or "").lower(), port)


def _with_refused_redirects(findings: list, refused: list[str], target_url: str) -> list:
    if refused:
        findings.append(
            BolaFinding(
                rule_id="BOLA-PROBE-REDIRECT-REFUSED",
                severity="P1",
                message=f"{len(refused)} probe request(s) were redirected to another origin and not followed; those routes were not tested",
                endpoint_or_file=target_url,
                details="Point the probe at the final origin (for example the https:// URL) so every route can be tested.",
            )
        )
    return findings


def check_server_active(target_url: str) -> bool:
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": f"PrufGate-BOLA-Probe/{__version__}"})
        with urllib.request.build_opener(SameOriginRedirectHandler(target_url)).open(req, timeout=2) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def _is_meaningful_api_payload(content_type: str, body: str) -> bool:
    """Return True only if response body is non-empty structured API data (not an SPA HTML fallback or error payload)."""
    stripped = body.strip()
    if not stripped or len(stripped) <= 2 or stripped in ("[]", "{}"):
        return False
    ct_lower = (content_type or "").lower()
    if "text/html" in ct_lower or stripped.lower().startswith(("<!doctype", "<html", "<head", "<body")):
        return False
    try:
        parsed = json.loads(stripped)
    except Exception:
        return "application/json" in ct_lower or "application/vnd.api+json" in ct_lower

    if isinstance(parsed, list):
        return len(parsed) > 0
    if isinstance(parsed, dict):
        if not parsed:
            return False
        keys_lower = {k.lower() for k in parsed.keys()}
        if keys_lower <= {"error", "errors", "message", "status", "statuscode", "code", "detail", "ok", "success"}:
            if parsed.get("ok") is False or parsed.get("success") is False or parsed.get("error") or parsed.get("errors"):
                return False
            msg = str(parsed.get("message") or parsed.get("detail") or "").lower()
            if any(w in msg for w in ("unauthorized", "unauthenticated", "forbidden", "not found", "invalid token", "denied")):
                return False
        if "data" in parsed and parsed["data"] in (None, [], {}) and len(parsed) <= 2:
            return False
        return True
    return False


def _normalize_route_template(raw_route: str) -> tuple[str, list[str]]:
    """Normalize framework parameter syntax (`:id`, `[id]`, `<int:id>`, `{id}`) to `{param}` and return `(norm_path, params)`."""
    route = raw_route.strip()
    # Strip Go 1.22 method prefix like "GET /api/items/{id}"
    m_go_method = re.match(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/.*)$", route, re.IGNORECASE)
    if m_go_method:
        route = m_go_method.group(1).strip()

    if not route.startswith("/"):
        route = "/" + route

    params: list[str] = []

    def _record(name: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_]", "", name) or "id"
        params.append(clean)
        return f"{{{clean}}}"

    # Flask / Django: <int:item_id> or <uuid:pk> or <id>
    route = re.sub(r"<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>", lambda m: _record(m.group(1)), route)
    # Next.js: [...slug] or [id]
    route = re.sub(r"\[\.{0,3}([a-zA-Z0-9_]+)\]", lambda m: _record(m.group(1)), route)
    # Express / Gin / Rails: :id
    route = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", lambda m: _record(m.group(1)), route)
    # OpenAPI / FastAPI / Spring / Chi: {id}
    for m_brace in re.finditer(r"\{([a-zA-Z0-9_]+)\}", route):
        p_name = m_brace.group(1)
        if p_name not in params:
            params.append(p_name)

    route = re.sub(r"//+", "/", route)
    if len(route) > 1 and route.endswith("/"):
        route = route.rstrip("/")
    return route, params


def _join_route_prefix(prefix: str, sub: str) -> str:
    p = ("/" + prefix.strip("/")) if prefix.strip("/") else ""
    s = ("/" + sub.strip("/")) if sub.strip("/") else ""
    joined = (p + s) or "/"
    return re.sub(r"//+", "/", joined)


# A line that starts another route handler: the current handler's window ends there.
_NEXT_HANDLER_RE = re.compile(
    r"^(?:@\w+\.(?:get|post|put|patch|delete|route|api_route)\s*\("  # FastAPI / Flask
    r"|@(?:Get|Post|Put|Delete|Patch|RequestMapping)\w*\b"  # NestJS / Spring
    r"|export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|DELETE|PATCH)\b"  # Next.js
    r"|(?:app|router|server|fastify|api|hono)\.(?:get|post|put|patch|delete|all)\s*\("  # Express & co
    r"|\w+\.(?:GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\s*\(\s*\""  # Go routers
    r"|func\s+(?:\([^)]*\)\s*)?\w+\s*\("  # Go functions
    r"|(?:def|public\s+function|private\s+function|protected\s+function)\s"  # Python / Ruby / PHP
    r"|Route::"  # Laravel
    r"|@[A-Za-z]"  # an annotation/decorator after the body has started opens the next method
    r")"
)


def _extract_handler_window(lines: list[str], start_line: int, max_lines: int = 60) -> str:
    """Lines of the handler starting at `start_line` (1-indexed), up to the next handler or `max_lines`.

    Decorators and the definition they decorate stay together; the window never
    bleeds into the next route definition.
    """
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), start_idx + max_lines)
    window: list[str] = []
    in_header = True  # decorators / the definition line the route starts with
    for idx in range(start_idx, end_idx):
        s = lines[idx].strip()
        if idx > start_idx:
            if in_header and (s.startswith("@") or s.startswith(("def ", "async def ", "func ", "public ", "fun "))):
                window.append(lines[idx])
                if not s.startswith("@"):
                    in_header = False
                continue
            in_header = False
            if _NEXT_HANDLER_RE.match(s):
                break
        window.append(lines[idx])
    return "\n".join(window)


def discover_all_routes(workspace: Path | None) -> list[DiscoveredRoute]:
    """Discover API routes across OpenAPI specs and 10+ web frameworks in `workspace`."""
    if not workspace or not workspace.is_dir():
        return []

    routes: list[DiscoveredRoute] = []

    # 1. OpenAPI / Swagger JSON & YAML files
    openapi_candidates = (
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
        "docs/openapi.json",
        "docs/openapi.yaml",
        "api/openapi.json",
        "api/openapi.yaml",
    )
    for spec_rel in openapi_candidates:
        spec_path = workspace / spec_rel
        if not spec_path.is_file():
            continue
        try:
            raw_text = spec_path.read_text(encoding="utf-8", errors="ignore")
            if spec_path.suffix.lower() in (".yaml", ".yml"):
                spec_data = yaml.safe_load(raw_text) if yaml is not None else {}
            else:
                spec_data = json.loads(raw_text)
            if isinstance(spec_data, dict) and isinstance(spec_data.get("paths"), dict):
                for r_path, methods_obj in spec_data["paths"].items():
                    if not isinstance(r_path, str) or not r_path.startswith("/"):
                        continue
                    norm_path, params = _normalize_route_template(r_path)
                    methods = (
                        [m.upper() for m in methods_obj.keys() if m.lower() in ("get", "post", "put", "patch", "delete")]
                        if isinstance(methods_obj, dict)
                        else ["GET"]
                    )
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=r_path,
                            methods=methods or ["GET"],
                            framework="openapi",
                            file_path=spec_rel,
                            line=1,
                            has_dynamic_param=bool(params),
                            param_names=params,
                        )
                    )
        except Exception:
            pass

    # Walk source files in workspace
    route_suffixes = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".py", ".go", ".java", ".kt", ".rb", ".php"}
    for src_file in iter_workspace_files(workspace, route_suffixes):
        rel_file = str(src_file.relative_to(workspace)).replace("\\", "/")
        if is_test_path(rel_file):
            continue
        sfx = src_file.suffix.lower()

        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = content.splitlines()

        # 2. Next.js App Router (**/app/api/**/route.{ts,js}) & Pages Router (**/pages/api/**/*.{ts,js})
        parts = Path(rel_file).parts
        if src_file.stem == "route" and "app" in parts and sfx in (".ts", ".tsx", ".js", ".jsx"):
            app_idx = parts.index("app")
            seg_parts = [s for s in parts[app_idx + 1 : -1] if not (s.startswith("(") and s.endswith(")"))]
            raw_route = "/" + "/".join(seg_parts)
            norm_path, params = _normalize_route_template(raw_route)
            # Find exported HTTP method functions (GET, POST, PUT, PATCH, DELETE)
            found_handler = False
            for idx, line in enumerate(lines, start=1):
                m_fn = re.search(
                    r"\bexport\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b",
                    line,
                )
                if m_fn:
                    found_handler = True
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[m_fn.group(1)],
                            framework="nextjs",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )
            if not found_handler:
                routes.append(
                    DiscoveredRoute(
                        path=norm_path,
                        raw_path=raw_route,
                        methods=["GET"],
                        framework="nextjs",
                        file_path=rel_file,
                        line=1,
                        has_dynamic_param=bool(params),
                        param_names=params,
                        handler_snippet=content[:2000],
                        file_content=content,
                    )
                )
            continue

        if "pages" in parts and "api" in parts and sfx in (".ts", ".tsx", ".js", ".jsx"):
            pages_idx = parts.index("pages")
            seg_parts = list(parts[pages_idx + 1 : -1])
            if src_file.stem != "index":
                seg_parts.append(src_file.stem)
            raw_route = "/" + "/".join(seg_parts)
            norm_path, params = _normalize_route_template(raw_route)
            routes.append(
                DiscoveredRoute(
                    path=norm_path,
                    raw_path=raw_route,
                    methods=["ALL"],
                    framework="nextjs",
                    file_path=rel_file,
                    line=1,
                    has_dynamic_param=bool(params),
                    param_names=params,
                    handler_snippet=content[:2500],
                    file_content=content,
                )
            )
            continue

        # 3. Express / Fastify / NestJS (TypeScript / JavaScript)
        if sfx in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            # Check NestJS @Controller('prefix')
            ctrl_m = re.search(r"""@Controller\(\s*["'`]([^"'`]*)["'`]\s*\)""", content)
            if ctrl_m:
                ctrl_prefix = ctrl_m.group(1)
                nest_re = re.compile(
                    r"""@(Get|Post|Put|Patch|Delete)\(\s*(?:["'`]([^"'`]*)["'`])?\s*\)"""
                )
                for idx, line in enumerate(lines, start=1):
                    m_nest = nest_re.search(line)
                    if m_nest:
                        method = m_nest.group(1).upper()
                        sub_path = m_nest.group(2) or ""
                        raw_route = _join_route_prefix(ctrl_prefix, sub_path)
                        norm_path, params = _normalize_route_template(raw_route)
                        routes.append(
                            DiscoveredRoute(
                                path=norm_path,
                                raw_path=raw_route,
                                methods=[method],
                                framework="nestjs",
                                file_path=rel_file,
                                line=idx,
                                has_dynamic_param=bool(params),
                                param_names=params,
                                handler_snippet=_extract_handler_window(lines, idx),
                                file_content=content,
                            )
                        )

            # Express / Fastify / Hono route registrations: app.get('/api/...', ...) or router.get('/items/:id', ...)
            exp_re = re.compile(
                r"""\b(?:app|router|server|fastify|api|hono)\.(get|post|put|patch|delete|all)\s*\(\s*["'`]([^"'`]+)["'`]"""
            )
            for idx, line in enumerate(lines, start=1):
                m_exp = exp_re.search(line)
                if m_exp:
                    method = m_exp.group(1).upper()
                    raw_route = m_exp.group(2)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework="express",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

        # 4. Python: FastAPI, Flask, Django
        elif sfx == ".py":
            prefix_m = re.search(
                r"""(?:APIRouter|Blueprint)\([^)]*(?:prefix|url_prefix)\s*=\s*["']([^"']+)["']""",
                content,
            )
            router_prefix = prefix_m.group(1) if prefix_m else ""

            py_route_re = re.compile(
                r"""^\s*@\w+\.(get|post|put|patch|delete|route|api_route)\s*\(\s*["']([^"']+)["']"""
            )
            for idx, line in enumerate(lines, start=1):
                m_py = py_route_re.search(line)
                if m_py:
                    method_raw = m_py.group(1).upper()
                    method = "GET" if method_raw in ("ROUTE", "API_ROUTE") else method_raw
                    raw_route = _join_route_prefix(router_prefix, m_py.group(2))
                    norm_path, params = _normalize_route_template(raw_route)
                    fw = "flask" if "<" in m_py.group(2) or "Blueprint" in content else "fastapi"
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework=fw,
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

            # Django urls.py: path("items/<uuid:id>/", views.detail)
            django_re = re.compile(r"""\b(?:path|re_path)\s*\(\s*["']([^"']+)["']""")
            if "urlpatterns" in content or src_file.name.endswith("urls.py"):
                for idx, line in enumerate(lines, start=1):
                    m_dj = django_re.search(line)
                    if m_dj:
                        raw_route = "/" + m_dj.group(1).lstrip("^/")
                        norm_path, params = _normalize_route_template(raw_route)
                        routes.append(
                            DiscoveredRoute(
                                path=norm_path,
                                raw_path=raw_route,
                                methods=["ALL"],
                                framework="django",
                                file_path=rel_file,
                                line=idx,
                                has_dynamic_param=bool(params),
                                param_names=params,
                                handler_snippet=_extract_handler_window(lines, idx),
                                file_content=content,
                            )
                        )

        # 5. Go: net/http, Gin, Echo, Chi, Gorilla Mux
        elif sfx == ".go":
            go_route_re = re.compile(
                r"""\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\s*\(\s*"([^"]+)"(?:\s*,\s*([a-zA-Z0-9_.]+))?"""
            )
            for idx, line in enumerate(lines, start=1):
                m_go = go_route_re.search(line)
                if m_go:
                    verb = m_go.group(1).upper()
                    method = "ALL" if verb.startswith("HANDLE") else verb
                    raw_route = m_go.group(2)
                    handler_ref = m_go.group(3) or ""
                    norm_path, params = _normalize_route_template(raw_route)
                    snippet = _extract_handler_window(lines, idx)
                    # If handler is a named function in the same file, append its body to snippet
                    if handler_ref:
                        fn_short = handler_ref.split(".")[-1]
                        m_fn_def = re.search(rf"\bfunc\s+(?:\([^)]+\)\s*)?{re.escape(fn_short)}\s*\(", content)
                        if m_fn_def:
                            fn_ln = content[: m_fn_def.start()].count("\n") + 1
                            snippet = snippet + "\n" + _extract_handler_window(lines, fn_ln)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework="go",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=snippet,
                            file_content=content,
                        )
                    )

        # 6. Java / Kotlin: Spring Boot (@RequestMapping, @GetMapping, @PostMapping, etc.)
        elif sfx in (".java", ".kt"):
            cls_map = re.search(
                r"""@RequestMapping\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']""",
                content,
            )
            base_prefix = cls_map.group(1) if cls_map else ""
            spring_re = re.compile(
                r"""@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']*)["'][^)]*\))?"""
            )
            for idx, line in enumerate(lines, start=1):
                if idx == (content[: cls_map.start()].count("\n") + 1 if cls_map else -1):
                    continue
                m_sp = spring_re.search(line)
                if m_sp:
                    ann = m_sp.group(1)
                    method = ann.replace("Mapping", "").upper()
                    if method == "REQUEST":
                        method = "ALL"
                    sub_path = m_sp.group(2) or ""
                    raw_route = _join_route_prefix(base_prefix, sub_path)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[method],
                            framework="spring",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

        # 7. Ruby on Rails & PHP Laravel
        elif sfx == ".rb":
            rails_re = re.compile(r"""^\s*(get|post|put|patch|delete)\s+["']([^"']+)["']""")
            res_re = re.compile(r"""^\s*resources\s+:([a-zA-Z0-9_]+)""")
            for idx, line in enumerate(lines, start=1):
                m_rl = rails_re.search(line)
                if m_rl:
                    raw_route = m_rl.group(2)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[m_rl.group(1).upper()],
                            framework="rails",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )
                m_res = res_re.search(line)
                if m_res:
                    res_name = m_res.group(1)
                    routes.append(
                        DiscoveredRoute(
                            path=f"/{res_name}/{{id}}",
                            raw_path=f"/{res_name}/:id",
                            methods=["GET", "PUT", "DELETE"],
                            framework="rails",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=True,
                            param_names=["id"],
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )
        elif sfx == ".php":
            laravel_re = re.compile(
                r"""\bRoute::(get|post|put|patch|delete|any)\s*\(\s*["']([^"']+)["']""",
                re.IGNORECASE,
            )
            for idx, line in enumerate(lines, start=1):
                m_lv = laravel_re.search(line)
                if m_lv:
                    raw_route = m_lv.group(2)
                    norm_path, params = _normalize_route_template(raw_route)
                    routes.append(
                        DiscoveredRoute(
                            path=norm_path,
                            raw_path=raw_route,
                            methods=[m_lv.group(1).upper()],
                            framework="laravel",
                            file_path=rel_file,
                            line=idx,
                            has_dynamic_param=bool(params),
                            param_names=params,
                            handler_snippet=_extract_handler_window(lines, idx),
                            file_content=content,
                        )
                    )

    return routes


def discover_workspace_api_routes(workspace: Path | None) -> list[str]:
    """Discover API endpoint strings for dynamic probing (backward-compatible with `bola_matrix.py`)."""
    all_routes = discover_all_routes(workspace)
    discovered: list[str] = []
    for r in all_routes:
        low = r.path.lower()
        if any(pub in low for pub in PUBLIC_ROUTE_KEYWORDS):
            continue
        # Convert any `{param}` in dynamic routes to `{tenant_id}` for cross-tenant probe substitution
        probe_route = re.sub(r"\{[^}]+\}", "{tenant_id}", r.path)
        discovered.append(probe_route)

    seen: set[str] = set()
    unique: list[str] = []
    for route_str in discovered:
        if route_str not in seen:
            seen.add(route_str)
            unique.append(route_str)
    return unique[:25]


def _build_auth_guard_regex(config: PrufGateConfig) -> re.Pattern[str]:
    patterns = list(DEFAULT_AUTH_GUARD_PATTERNS)
    for custom in config.auth_guards:
        clean = custom.strip()
        if clean:
            patterns.append(rf"\b{re.escape(clean)}\b")
    return re.compile("|".join(patterns))


def _build_tenant_key_regex(config: PrufGateConfig) -> re.Pattern[str]:
    keys = list(DEFAULT_TENANT_KEYS) + [k.strip() for k in config.tenant_keys if k.strip()]
    escaped = [re.escape(k) for k in dict.fromkeys(keys)]
    return re.compile(r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE)


# The authenticated caller as a value (`req.user.id`, `current_user.projects`, `Auth::user()->`).
# It proves scoping only inside the lookup itself or in an ownership comparison.
_ID = (
    r"(?:\b(?:current_user|currentUser|current_account|current_tenant|current_organization|Current\.(?:user|account|tenant))\??\.\w[\w.]*"
    r"|\b(?:req|request|ctx|c|context|session|auth|g)\??\.(?:user|session|auth|principal|tenant|org)\??\.\w[\w.]*"
    r"|\bprincipal\.\w[\w.]*|\bc\.(?:MustGet|Get)\(\s*\"(?:user|tenant|claims|org)\w*\"\)"
    r"|\bAuth::user\(\)|\bauth\(\)->(?:user|id)\(\)|\$request->user\(\))"
)
CALLER_IDENTITY_RE = re.compile(_ID, re.IGNORECASE)
# `doc.ownerId !== req.user.id`, `if record.user_id != current_user.id` (but not `!req.user.id` or `== null`).
OWNERSHIP_COMPARE_RE = re.compile(
    rf"[\w\])]\s*(?:===?|!==?)\s*{_ID}|{_ID}\s*(?:===?|!==?)\s*(?!null\b|undefined\b|nil\b|None\b)[\w$@]",
    re.IGNORECASE,
)
# An explicit authorization/ownership check anywhere in the handler.
OWNERSHIP_CALL_RE = re.compile(
    r"\b(?:authorize|checkOwnership|verifyOwnership|assertTenant|assertMembership|assertOwner|canAccess|isMember|hasAccess|checkAccess)\s*\("
    r"|\bauthorize\s+@|\$this->authorize\(|\bGate::(?:authorize|allows)\(",
)

# A tenant key read from the request (URL params, query string or body) is attacker-controlled.
_REQUEST_VALUE_PREFIX_RE = re.compile(
    r"(?:\b(?:params|query|body|args|path_params|query_params|route|GET|POST)\s*(?:\??\.|\[\s*[\"':]?|\.get\(\s*[\"'])"
    r"|\.(?:Param|Query|PostForm|FormValue|PathValue)\(\s*\"|\$request->(?:input|route|query|get)\(\s*[\"'])\s*$"
)


# The value assigned to a tenant key (`orgId: req.query.orgId`, `org_id=org_id`).
_KEY_VALUE_RE = re.compile(r"""\s*(?:===?|=>|:|=)\s*([\w$.>\[\]'"-]+(?:\(\s*["']?\w*)?)""")
_REQUEST_SOURCE_RE = re.compile(
    r"""^(?:\w+\.)?(?:params|query|body|args|path_params|query_params|form)\b"""
    r"""|^\$request->(?:input|route|query|get)\b|^\$_(?:GET|POST|REQUEST)\b|^\w+\.(?:Param|Query|PostForm|FormValue|PathValue)\("""
)


def _norm_key(name: str) -> str:
    return name.replace("_", "").lower()


_REQUEST_INPUT_RE = re.compile(
    r"\b(?:req|request|ctx|c|context)\.(?:params|query|body|args|path_params|query_params|Param|Query|PostForm|FormValue|PathValue)\b"
    r"|\bparams\s*[\[.]|\$request->|\$_(?:GET|POST|REQUEST)\b"
)


def _lookup_regions(snippet: str) -> list[str]:
    """The statement around each DB lookup: from the start of its line until the
    brackets balance (following `.chain()` continuation lines), capped at 800 chars."""
    regions: list[str] = []
    for m in DB_OBJECT_LOOKUP_RE.finditer(snippet):
        start = snippet.rfind("\n", 0, m.start()) + 1
        depth, i, end = 0, start, min(len(snippet), start + 800)
        while i < end:
            ch = snippet[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth <= 0 and i > m.start():
                break
            elif ch == "\n" and depth <= 0 and i > m.start():
                if not snippet[i + 1 : i + 80].lstrip().startswith((".", "->")):
                    break
            i += 1
        regions.append(snippet[start:i])
    return regions


def _region_scoped(region: str, params: set[str], tenant_re: re.Pattern[str]) -> bool:
    if CALLER_IDENTITY_RE.search(region):
        return True
    for m in tenant_re.finditer(region):
        if _norm_key(m.group(0)) in params:
            continue
        if _REQUEST_VALUE_PREFIX_RE.search(region[max(0, m.start() - 40) : m.start()]):
            continue
        mv = _KEY_VALUE_RE.match(region, m.end())
        if mv:
            value = mv.group(1)
            if _REQUEST_SOURCE_RE.match(value) or _norm_key(value.split("(")[0]) in params:
                continue
        return True
    return False


def _has_tenant_scope(snippet: str, route_params: list[str], tenant_re: re.Pattern[str]) -> bool:
    """True when every lookup in the handler is scoped by something the caller cannot forge.

    Scoped means: the caller's identity or a tenant key not taken from the request
    appears in the lookup statement itself, or the handler compares the record's owner
    with the caller, or calls an explicit authorization check. A tenant key that is only a
    route parameter or request value (`orgId: req.params.orgId`) proves nothing, and the
    identity merely appearing elsewhere (`log(req.user.email)`) proves nothing either.
    """
    if OWNERSHIP_CALL_RE.search(snippet) or OWNERSHIP_COMPARE_RE.search(snippet):
        return True
    params = {_norm_key(p) for p in route_params}
    regions = _lookup_regions(snippet) or [snippet]
    # Lookups fed by request input must be scoped; one keyed by an already-loaded record
    # (`where: { id: order.customerId }`) is not the IDOR entry point.
    param_word = (
        re.compile(r"(?<![.\w])(?:" + "|".join(re.escape(p) for p in route_params) + r")\b(?!\s*:[^:])")
        if route_params
        else None
    )
    fed = [r for r in regions if _REQUEST_INPUT_RE.search(r) or (param_word and param_word.search(r))]
    return all(_region_scoped(r, params, tenant_re) for r in (fed or regions))


# Auth applied to every handler in a file: Express/Fastify `router.use(auth)`, Rails
# `before_action :authenticate...`, Laravel `$this->middleware('auth')`, a class-level
# Spring/NestJS guard, a Go router group `.Use(authMiddleware)`.
FILE_LEVEL_AUTH_RE = re.compile(
    r"^\s*(?:app|router|server|api|r|g|e|v1|group|\w+Router)\.use\s*\(\s*(?:[\"'][^\"']*[\"']\s*,\s*)?\w*(?:auth|Auth|session|Session|jwt|Jwt|JWT|guard|Guard|protect|Protect|require|Require)"
    r"|^\s*before_action\s+:(?:authenticate|require_login|require_user|authorize)\w*"
    r"|\$this->middleware\(\s*\[?\s*[\"']auth"
    r"|^\s*(?:@UseGuards|@PreAuthorize|@Secured|@RolesAllowed)\b[^\n]*\n(?:\s*@[^\n]*\n)*\s*(?:export\s+)?(?:public\s+)?class\b"
    r"|\.Use\(\s*\w*(?:auth|Auth|jwt|JWT|Jwt|session|Session)",
    re.MULTILINE,
)
_SKIPPED_AUTH_RE = re.compile(r"^\s*skip_before_action\s+:authenticate", re.MULTILINE)


_USE_SERVER_RE = re.compile(r"""^\s*(?:(?://[^\n]*|/\*[\s\S]*?\*/)\s*)*["']use server["']""")
_SERVER_ACTION_EXPORT_RE = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+function\s+(\w+)|const\s+(\w+)\s*=\s*async\b)"
)


def _server_action_findings(workspace: Path, cfg: PrufGateConfig, auth_re: re.Pattern[str]) -> list[BolaFinding]:
    """Exported functions of a `"use server"` module without an authorization guard."""
    findings: list[BolaFinding] = []
    for af in iter_workspace_files(workspace, {".ts", ".tsx", ".js", ".jsx", ".mjs"}):
        rel_path = str(af.relative_to(workspace)).replace("\\", "/")
        if is_test_path(rel_path) or cfg.is_excluded(rel_path) or cfg.is_exempt(rel_path, "BOLA-UNGUARDED-SERVER-ACTION"):
            continue
        try:
            text = af.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _USE_SERVER_RE.match(text):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = _SERVER_ACTION_EXPORT_RE.match(line)
            if not m:
                continue
            end_idx = len(lines)
            for j in range(i + 1, len(lines)):
                if lines[j].lstrip().startswith("export "):
                    end_idx = j
                    break
            if auth_re.search("\n".join(lines[i:end_idx])):
                continue
            name = m.group(1) or m.group(2)
            findings.append(
                BolaFinding(
                    rule_id="BOLA-UNGUARDED-SERVER-ACTION",
                    severity="P0",
                    message=f"Server Action '{name}' has no authorization guard (e.g. auth(), requireAuth(), verifySession())",
                    endpoint_or_file=rel_path,
                    line=i + 1,
                    curl_poc=f"# Invoke the Server Action directly without a valid session cookie\n# Path: {rel_path}:{i + 1}",
                    details="Next.js Server Actions are publicly reachable HTTP endpoints. Without a session guard they can be invoked unauthenticated.",
                )
            )
    return findings


_RAILS_MEMBER_ACTION_RE = re.compile(r"^\s*def\s+(show|edit|update|destroy)\b")
_LARAVEL_MEMBER_ACTION_RE = re.compile(r"^\s*public\s+function\s+(show|edit|update|destroy)\s*\(([^)]*)\)")


def _controller_routes(workspace: Path) -> list[DiscoveredRoute]:
    """Rails and Laravel controller member actions, whose routes live in a separate routes file.

    ponytail: actions are matched by conventional name (show/edit/update/destroy) and an
    explicit `find`; Laravel implicit route-model binding (`show(Invoice $invoice)`) is not
    analysed, because the lookup is invisible in the controller.
    """
    routes: list[DiscoveredRoute] = []
    rails_app_auth = ""
    app_ctrl = workspace / "app" / "controllers" / "application_controller.rb"
    if app_ctrl.is_file():
        rails_app_auth = app_ctrl.read_text(encoding="utf-8", errors="ignore")
    laravel_routes = ""
    routes_dir = workspace / "routes"
    if routes_dir.is_dir():
        laravel_routes = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in sorted(routes_dir.glob("*.php")))

    for f in iter_workspace_files(workspace, {".rb", ".php"}):
        rel = str(f.relative_to(workspace)).replace("\\", "/")
        is_rails = rel.endswith("_controller.rb") and "/controllers/" in f"/{rel}"
        is_laravel = rel.endswith("Controller.php") and "/Controllers/" in f"/{rel}"
        if not (is_rails or is_laravel) or is_test_path(rel):
            continue
        content = f.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
        # Auth inherited from ApplicationController, or applied to the controller in routes/*.php.
        inherited = ""
        if is_rails and "< ApplicationController" in content and not _SKIPPED_AUTH_RE.search(content):
            inherited = rails_app_auth
        if is_laravel and re.search(re.escape(f.stem) + r"\b", laravel_routes):
            for ln in laravel_routes.splitlines():
                if f.stem in ln and re.search(r"middleware\(\s*\[?\s*['\"]auth", ln):
                    inherited = "$this->middleware('auth')"
        action_re = _RAILS_MEMBER_ACTION_RE if is_rails else _LARAVEL_MEMBER_ACTION_RE
        for idx, line in enumerate(lines, start=1):
            m = action_re.match(line)
            if not m:
                continue
            snippet = _extract_handler_window(lines, idx)
            if is_rails and not re.search(r"params\[:\w*id\]", snippet):
                continue
            if is_laravel and not re.search(r"\$\w*[iI]d\b", m.group(2)):
                continue
            routes.append(
                DiscoveredRoute(
                    path=f"{f.stem}#{m.group(1)}",
                    raw_path=f"{f.stem}#{m.group(1)}",
                    methods=["ALL"],
                    framework="rails" if is_rails else "laravel",
                    file_path=rel,
                    line=idx,
                    has_dynamic_param=True,
                    param_names=["id"],
                    handler_snippet=snippet,
                    file_content=content + "\n" + inherited,
                )
            )
    return routes


def run_static_matrix_audit(
    workspace: Path,
    config: PrufGateConfig | None = None,
) -> list[BolaFinding]:
    """Scan workspace for unguarded server actions, unscoped multi-tenant tables, and unscoped BOLA route handlers."""
    if config is not None:
        cfg = config
    else:
        cfg = PrufGateConfig.load(workspace) if (workspace / ".prufgate").exists() else PrufGateConfig()
    auth_re = _build_auth_guard_regex(cfg)
    tenant_re = _build_tenant_key_regex(cfg)

    print("  [BOLA Static Matrix] Scanning server actions and database queries for missing tenant constraints...")

    # 1. Next.js Server Actions
    findings: list[BolaFinding] = _server_action_findings(workspace, cfg, auth_re)

    # 2. Scan SQL migrations and repositories for missing tenant scoping
    for sf in iter_workspace_files(workspace, {".sql"}):
        rel_path = str(sf.relative_to(workspace)).replace("\\", "/")
        rel_dirs = rel_path.split("/")[:-1]
        if not ("migrations" in rel_dirs[-1:] or "database" in rel_dirs):
            continue
        if cfg.is_excluded(rel_path) or cfg.is_exempt(rel_path, "BOLA-TABLE-MISSING-TENANT-COLUMN"):
            continue
        try:
            text = sf.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\);",
                text,
                re.DOTALL | re.IGNORECASE,
            ):
                table_name = match.group(1).lower()
                table_body = match.group(2)
                if table_name in ("migrations", "schema_migrations", "tenants", "organizations", "roles", "permissions"):
                    continue
                if not tenant_re.search(table_body):
                    line_no = text[: match.start()].count("\n") + 1
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-TABLE-MISSING-TENANT-COLUMN",
                            severity="P1",
                            message=f"Multi-tenant table '{table_name}' declared without tenant_id or org_id foreign key",
                            endpoint_or_file=rel_path,
                            line=line_no,
                            details="Tables storing customer data without tenant_id require complex join constraints for RLS, increasing BOLA leakage risk.",
                        )
                    )
        except Exception:
            pass

    # 3. Universal Multi-Framework Route Handler BOLA Verification (`static-bola-unscoped-access`)
    discovered_routes = discover_all_routes(workspace) + _controller_routes(workspace)
    seen_handler_locs: set[tuple[str, int]] = set()

    for route in discovered_routes:
        if route.framework == "openapi" or not route.has_dynamic_param:
            continue
        if any(pub in route.path.lower() for pub in PUBLIC_ROUTE_KEYWORDS):
            continue
        if cfg.is_excluded(route.file_path) or cfg.is_exempt(route.file_path, "static-bola-unscoped-access"):
            continue
        if "prufgate-ignore" in route.handler_snippet.lower():
            continue

        loc_key = (route.file_path, route.line)
        if loc_key in seen_handler_locs:
            continue

        # Check if the handler performs a direct database/ORM object lookup or mutation
        if not DB_OBJECT_LOOKUP_RE.search(route.handler_snippet):
            continue

        # Auth counts per handler; a file-wide guard counts only when it is applied to every handler.
        has_auth = bool(auth_re.search(route.handler_snippet) or FILE_LEVEL_AUTH_RE.search(route.file_content))
        has_tenant_scope = _has_tenant_scope(route.handler_snippet, route.param_names, tenant_re)

        if not has_tenant_scope or not has_auth:
            seen_handler_locs.add(loc_key)
            missing_desc = (
                "missing both authentication guard and tenant/owner scoping"
                if (not has_auth and not has_tenant_scope)
                else ("missing authentication guard" if not has_auth else "missing tenant/owner key scoping on object lookup")
            )
            findings.append(
                BolaFinding(
                    rule_id="static-bola-unscoped-access",
                    severity="P0",
                    message=(
                        f"Route '{','.join(route.methods)} {route.path}' ({route.framework}) performs direct object lookup "
                        f"by '{route.param_names[-1] if route.param_names else 'id'}' {missing_desc}."
                    ),
                    endpoint_or_file=route.file_path,
                    line=route.line,
                    curl_poc=(
                        f"curl -X {'GET' if route.methods[0] == 'ALL' else route.methods[0]} "
                        f'-H "Authorization: Bearer $PRUFGATE_TOKEN_A" "$TARGET_URL{route.path}"'
                        if route.path.startswith("/")
                        else ""
                    ),
                    details=(
                        f"Scope database queries in '{route.file_path}:{route.line}' by a tenant/owner key "
                        f"(e.g. `tenant_id`, `organization_id`, `user_id`) and enforce caller authentication."
                    ),
                )
            )

    return findings


def run_dynamic_matrix(
    target_url: str,
    workspace: Path | None = None,
    config: PrufGateConfig | None = None,
) -> list[BolaFinding]:
    """Execute the 4-request two-token differential BOLA probe matrix against a live target."""
    findings: list[BolaFinding] = []
    parsed_target = urllib.parse.urlparse(target_url)
    if parsed_target.scheme not in ("http", "https") or not parsed_target.netloc:
        print(f"  [BOLA Dynamic Matrix] Invalid target URL scheme or host: {target_url}", file=sys.stderr)
        return findings
    print(f"  [BOLA Dynamic Matrix] Probing cross-tenant authorization boundaries on {target_url}...")

    refused: list[str] = []
    opener = urllib.request.build_opener(SameOriginRedirectHandler(target_url, refused))
    discovered_routes = discover_workspace_api_routes(workspace)

    env_paths = os.environ.get("PRUFGATE_BOLA_PATHS")
    if env_paths:
        test_paths = [p.strip() for p in env_paths.split(",") if p.strip()]
    else:
        default_paths = [
            "/api/v1/tenant/profile",
            "/api/v1/workspaces/current",
            "/api/v1/users/me",
            "/api/v1/projects",
            "/api/v1/settings",
            "/api/v1/billing/subscription",
            "/api/v1/audit-logs",
        ]
        static_discovered = [r for r in discovered_routes if "{tenant_id}" not in r]
        test_paths = list(dict.fromkeys(static_discovered + default_paths))

    # Real tokens for two tenants are required for the cross-tenant probes: a made-up
    # token only measures the 401 path. Tokens never appear in findings or reports.
    token_a = os.environ.get("PRUFGATE_TEST_PROBE_TOKEN_A") or os.environ.get("PRUFGATE_TENANT_A_TOKEN") or ""
    token_b = os.environ.get("PRUFGATE_TEST_PROBE_TOKEN_B") or os.environ.get("PRUFGATE_TENANT_B_TOKEN") or ""
    tenant_a_id = os.environ.get("PRUFGATE_TEST_PROBE_TENANT_A_ID", os.environ.get("PRUFGATE_TENANT_A_ID", "tenant-a-1111"))
    tenant_b_id = os.environ.get("PRUFGATE_TEST_PROBE_TENANT_B_ID", os.environ.get("PRUFGATE_TENANT_B_ID", "tenant-b-2222"))

    # 1. Unauthenticated request check across protected paths
    for path in test_paths:
        full_url = f"{target_url.rstrip('/')}{path}"
        try:
            req = urllib.request.Request(
                full_url,
                headers={"User-Agent": f"PrufGate-BOLA-Probe/{__version__}", "Accept": "application/json"},
            )
            with opener.open(req, timeout=3) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                content_type = resp.headers.get("Content-Type", "")
                if resp.status == 200 and _is_meaningful_api_payload(content_type, body):
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-UNAUTHENTICATED-ACCESS",
                            severity="P0",
                            message=f"Endpoint {path} accessible without authentication token",
                            endpoint_or_file=path,
                            curl_poc=f"curl -s -i '{full_url}'",
                            details="Expected 401 Unauthorized, received HTTP 200 with structured JSON payload.",
                        )
                    )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    # 2. Cross-Tenant Two-Token Matrix Probes
    if not (token_a and token_b):
        print(
            "  [BOLA Dynamic Matrix] Cross-tenant probes skipped: set PRUFGATE_TEST_PROBE_TOKEN_A and "
            "PRUFGATE_TEST_PROBE_TOKEN_B (or --token-a/--token-b) to two real tenant tokens."
        )
        return _with_refused_redirects(findings, refused, target_url)
    env_cross = os.environ.get("PRUFGATE_CROSS_TENANT_PATHS")
    if env_cross:
        cross_tenant_paths = [p.strip().replace("{tenant_id}", tenant_b_id) for p in env_cross.split(",") if p.strip()]
    else:
        param_discovered = [r.replace("{tenant_id}", tenant_b_id) for r in discovered_routes if "{tenant_id}" in r]
        default_cross = [
            f"/api/v1/workspaces/{tenant_b_id}",
            f"/api/v1/tenants/{tenant_b_id}",
            f"/api/v1/users?tenant_id={tenant_b_id}",
            f"/api/v1/projects?organization_id={tenant_b_id}",
            f"/api/v1/billing/subscription?tenant_id={tenant_b_id}",
        ]
        cross_tenant_paths = list(dict.fromkeys(param_discovered + default_cross))

    for path in cross_tenant_paths:
        full_url = f"{target_url.rstrip('/')}{path}"
        url_for_a = full_url.replace(tenant_b_id, tenant_a_id)

        unauth_baseline = None
        try:
            req_unauth = urllib.request.Request(
                full_url,
                headers={"User-Agent": f"PrufGate-BOLA-Probe/{__version__}", "Accept": "application/json"},
            )
            with opener.open(req_unauth, timeout=3) as resp_u:
                if resp_u.status == 200:
                    unauth_baseline = resp_u.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        self_a_body = None
        try:
            req_self_a = urllib.request.Request(
                url_for_a,
                headers={
                    "User-Agent": f"PrufGate-BOLA-Probe/{__version__}",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token_a}",
                    "X-Tenant-ID": tenant_a_id,
                    "Cookie": f"session={token_a}; auth_token={token_a}",
                },
            )
            with opener.open(req_self_a, timeout=3) as resp_self_a:
                if resp_self_a.status == 200:
                    self_a_body = resp_self_a.read().decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        headers_a = {
            "User-Agent": f"PrufGate-BOLA-Probe/{__version__}",
            "Accept": "application/json",
            "Authorization": f"Bearer {token_a}",
            "X-Tenant-ID": tenant_b_id,
            "Cookie": f"session={token_a}; auth_token={token_a}",
        }
        try:
            req_a = urllib.request.Request(full_url, headers=headers_a)
            with opener.open(req_a, timeout=3) as resp_a:
                body = resp_a.read().decode("utf-8", errors="ignore")
                ct_a = resp_a.headers.get("Content-Type", "")
                if resp_a.status == 200 and _is_meaningful_api_payload(ct_a, body):
                    stripped_body = body.strip()
                    is_actually_tenant_a_only = (
                        self_a_body is not None
                        and stripped_body == self_a_body
                        and tenant_a_id in stripped_body
                        and tenant_b_id not in stripped_body
                    )
                    if stripped_body != unauth_baseline and not is_actually_tenant_a_only:
                        findings.append(
                            BolaFinding(
                                rule_id="BOLA-CROSS-TENANT-ACCESS",
                                severity="P0",
                                message=f"BOLA / IDOR: Tenant A token accessed Tenant B private resource at {path}",
                                endpoint_or_file=path,
                                curl_poc=f"curl -s -i -H \"Authorization: Bearer $PRUFGATE_TOKEN_A\" -H 'X-Tenant-ID: {tenant_b_id}' '{full_url}'",
                                details=f"Expected 403 Forbidden or 404 Not Found, received HTTP 200 with response payload: {stripped_body[:120]}...",
                            )
                        )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

        headers_b = {
            "User-Agent": f"PrufGate-BOLA-Probe/{__version__}",
            "Accept": "application/json",
            "Authorization": f"Bearer {token_b}",
            "X-Tenant-ID": tenant_a_id,
            "Cookie": f"session={token_b}; auth_token={token_b}",
        }
        try:
            req_b = urllib.request.Request(url_for_a, headers=headers_b)
            with opener.open(req_b, timeout=3) as resp_b:
                body_b = resp_b.read().decode("utf-8", errors="ignore")
                ct_b = resp_b.headers.get("Content-Type", "")
                if resp_b.status == 200 and _is_meaningful_api_payload(ct_b, body_b):
                    stripped_b = body_b.strip()
                    if stripped_b != unauth_baseline:
                        findings.append(
                            BolaFinding(
                                rule_id="BOLA-CROSS-TENANT-ACCESS",
                                severity="P0",
                                message=f"BOLA / IDOR: Tenant B token accessed Tenant A private resource at {path.replace(tenant_b_id, tenant_a_id)}",
                                endpoint_or_file=path.replace(tenant_b_id, tenant_a_id),
                                curl_poc=f"curl -s -i -H \"Authorization: Bearer $PRUFGATE_TOKEN_B\" -H 'X-Tenant-ID: {tenant_a_id}' '{url_for_a}'",
                                details=f"Expected 403 Forbidden or 404 Not Found, received HTTP 200 with response payload: {stripped_b[:120]}...",
                            )
                        )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return _with_refused_redirects(findings, refused, target_url)


def run_self_check() -> int:
    """Validate universal route discovery and static BOLA scoping across Next.js, FastAPI, Express, Go, and Spring Boot."""
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        # 1. Vulnerable FastAPI route (unscoped DB lookup by id)
        (ws / "api_vulnerable.py").write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(prefix='/api/v1')\n"
            "@router.get('/invoices/{invoice_id}')\n"
            "def get_invoice(invoice_id: str, user=Depends(get_current_user)):\n"
            "    return db.query(Invoice).filter_by(id=invoice_id).first()\n",
            encoding="utf-8",
        )
        # 2. Safe FastAPI route (scoped by tenant_id + auth guard)
        (ws / "api_safe.py").write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(prefix='/api/v1')\n"
            "@router.get('/orders/{order_id}')\n"
            "def get_order(order_id: str, user=Depends(get_current_user)):\n"
            "    return db.query(Order).filter_by(id=order_id, tenant_id=user.tenant_id).first()\n",
            encoding="utf-8",
        )
        # 3. Vulnerable Express route
        (ws / "routes.ts").write_text(
            "app.get('/api/projects/:id', async (req, res) => {\n"
            "  const proj = await prisma.project.findUnique({ where: { id: req.params.id } });\n"
            "  return res.json(proj);\n"
            "});\n",
            encoding="utf-8",
        )
        # 4. Vulnerable Go Gin route
        (ws / "handler.go").write_text(
            "package api\n"
            "func Register(r *gin.Engine) {\n"
            '    r.GET("/api/documents/:id", func(c *gin.Context) {\n'
            "        var doc Document\n"
            '        db.First(&doc, c.Param("id"))\n'
            "    })\n"
            "}\n",
            encoding="utf-8",
        )
        # 5. Vulnerable Spring Boot route
        (ws / "DocumentController.java").write_text(
            '@RestController\n@RequestMapping("/api/v1/docs")\n'
            "public class DocumentController {\n"
            '    @GetMapping("/{id}")\n'
            "    public Doc getDoc(@PathVariable String id) {\n"
            "        return docRepository.findById(id);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        routes = discover_all_routes(ws)
        if len(routes) < 5:
            print(f"bola_engine self-check FAILED: expected >= 5 routes, found {len(routes)}", file=sys.stderr)
            return 1

        findings = run_static_matrix_audit(ws)
        flagged_files = {f.endpoint_or_file for f in findings if f.rule_id == "static-bola-unscoped-access"}
        expected_files = {"api_vulnerable.py", "routes.ts", "handler.go", "DocumentController.java"}
        if flagged_files != expected_files:
            print(
                f"bola_engine self-check FAILED: expected {sorted(expected_files)}, got {sorted(flagged_files)}",
                file=sys.stderr,
            )
            return 1

    print("bola_engine self-check: 5 framework case(s) ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Exit 0: no P0/P1 finding. 1: a P0/P1 finding. 2: the engine could not run."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in raw_args:
        return run_self_check()

    ws_env = os.environ.get(
        "WORKSPACE",
        "/workspace" if Path("/workspace").exists() and os.access("/workspace", os.W_OK) else str(Path.cwd()),
    )
    parser = argparse.ArgumentParser(description="PrufGate Universal BOLA / Cross-Tenant Matrix Engine")
    parser.add_argument(
        "--target",
        "--target-url",
        "--url",
        dest="target",
        default=os.environ.get("TARGET_URL") or None,
        help="Live target for the two-token probe (default: $TARGET_URL; no live probe without one)",
    )
    parser.add_argument("--workspace", default=ws_env)
    parser.add_argument("--config", default=None, help="Path to .prufgate/config.yaml")
    parser.add_argument("--output", "--json-out", dest="output", default=None)
    parser.add_argument("--static-only", action="store_true", help="Run only static route & query scoping checks")
    parser.add_argument("--token-a", default=None, help="Bearer token for tenant A (or PRUFGATE_TEST_PROBE_TOKEN_A)")
    parser.add_argument("--token-b", default=None, help="Bearer token for tenant B (or PRUFGATE_TEST_PROBE_TOKEN_B)")
    parser.add_argument("--tenant-a", "--id-a", dest="tenant_a", default=None, help="Resource/tenant ID owned by tenant A")
    parser.add_argument("--tenant-b", "--id-b", dest="tenant_b", default=None, help="Resource/tenant ID owned by tenant B")
    args = parser.parse_args(raw_args)

    for env_key, val in (
        ("PRUFGATE_TEST_PROBE_TOKEN_A", args.token_a),
        ("PRUFGATE_TEST_PROBE_TOKEN_B", args.token_b),
        ("PRUFGATE_TEST_PROBE_TENANT_A_ID", args.tenant_a),
        ("PRUFGATE_TEST_PROBE_TENANT_B_ID", args.tenant_b),
    ):
        if val:
            os.environ[env_key] = val

    workspace = Path(args.workspace)
    if not workspace.is_dir():
        print(f"bola_engine: workspace not found: {workspace}", file=sys.stderr)
        return 2
    output_path = Path(args.output or f"{workspace}/reports/raw/bola_matrix.json")

    try:
        cfg = PrufGateConfig.load(workspace, args.config)
        findings: list[BolaFinding] = []
        if args.target and not args.static_only:
            if check_server_active(args.target):
                findings.extend(run_dynamic_matrix(args.target, workspace=workspace, config=cfg))
            else:
                print(f"  [BOLA Dynamic Matrix] Target {args.target} not reachable. Skipping dynamic network probes.")
        findings.extend(run_static_matrix_audit(workspace, config=cfg))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    except ConfigError as e:
        print(f"bola_engine: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # fail closed: a crash is never a pass
        print(f"bola_engine: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    print(f"✔ BOLA / Cross-Tenant Matrix complete: {len(findings)} finding(s) written to {output_path}")
    return 1 if any(f.severity in ("P0", "P1") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
