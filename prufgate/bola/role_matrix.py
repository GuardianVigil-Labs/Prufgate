"""Function-level authorisation check (`prufgate bola --url URL --roles FILE`, OWASP API5).

The developer lists their own test roles and which of them may call each of
their own routes. One GET or HEAD per route per role goes to `--url` plus the
route path, through the same origin-pinned opener and target check as the BOLA
probe. Tokens are read only from the environment variables the file names and
never appear in output: PoCs carry `$ENV_NAME` placeholders.

    roles:
      admin: { token_env: PRUFGATE_ROLE_ADMIN }
      anonymous: {}
    routes:
      - { path: /api/admin/users, allow: [admin] }
      - { path: /api/admin/health, method: HEAD, allow: [admin] }
"""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.parse
import urllib.request

import yaml

from prufgate import __version__
from prufgate.bola.bola_engine import BolaFinding, _probe_url
from prufgate.bola.route_sources import MAX_FILE_BYTES, RouteSourceError, _NoAliasLoader
from prufgate.netguard import target_url_error

_METHODS = {"GET", "HEAD"}
_PATH_RE = re.compile(r"^/[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]*$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TOKEN_RE = re.compile(r"^[\x21-\x7e]+$")


class RoleMatrixError(RouteSourceError):
    """The role file or its environment is unusable: the run exits 2."""


def _path_error(path: object) -> str | None:
    if not isinstance(path, str) or not _PATH_RE.match(path):
        return "must be a string starting with / and holding only URL path characters"
    decoded = urllib.parse.unquote(path.split("?", 1)[0])
    if "//" in decoded or "\\" in decoded or "://" in path:
        return "must not contain //, a backslash or a scheme"
    if any(seg in (".", "..") for seg in decoded.split("/")):
        return "must not contain . or .. segments"
    return None


Roles = dict[str, tuple[str, str]]  # role -> (token_env, token); both empty for an anonymous role
Routes = list[tuple[str, str, set[str]]]  # (method, path, allow)


def load_role_matrix(file_path: str) -> tuple[Roles, Routes]:
    """Read and validate the role file; read each role's token from its environment variable."""
    try:
        if not os.path.isfile(file_path):
            raise RoleMatrixError(f"{file_path} is not a regular file")
        with open(file_path, encoding="utf-8") as fh:
            text = fh.read(MAX_FILE_BYTES + 1)
        if len(text.encode("utf-8")) > MAX_FILE_BYTES:
            raise RoleMatrixError(f"{file_path} is over the 5 MB limit for --roles")
        doc = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 (a SafeLoader)
    except (OSError, UnicodeDecodeError) as exc:
        raise RoleMatrixError(f"cannot read {file_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RoleMatrixError(f"cannot parse {file_path}: {getattr(exc, 'problem', None) or 'invalid YAML'}") from exc

    def bad(msg: str) -> RoleMatrixError:
        return RoleMatrixError(f"{file_path}: {msg}")

    if not isinstance(doc, dict) or set(doc) != {"roles", "routes"}:
        raise bad("needs exactly the keys `roles` and `routes`")
    if not isinstance(doc["roles"], dict) or not doc["roles"]:
        raise bad("`roles` must be a non-empty mapping")
    roles: Roles = {}
    for name, spec in doc["roles"].items():
        spec = {} if spec is None else spec
        if not isinstance(name, str) or not isinstance(spec, dict) or not set(spec) <= {"token_env"}:
            raise bad(f"role {name!r} may only have `token_env` (tokens are never read from the file)")
        env = spec.get("token_env")
        if env is None:
            roles[name] = ("", "")
            continue
        if not isinstance(env, str) or not _ENV_RE.match(env):
            raise bad(f"role {name!r}: token_env must be an environment variable name")
        token = os.environ.get(env, "").strip()
        if not token:
            raise bad(f"role {name!r}: environment variable {env} is not set")
        if not _TOKEN_RE.match(token):  # a header-breaking character would print the token in the error
            raise bad(f"role {name!r}: environment variable {env} holds characters a bearer token cannot have")
        roles[name] = (env, token)
    if not isinstance(doc["routes"], list) or not doc["routes"]:
        raise bad("`routes` must be a non-empty list")
    routes: Routes = []
    for i, route in enumerate(doc["routes"], 1):
        if not isinstance(route, dict) or not set(route) <= {"path", "allow", "method"} or "path" not in route:
            raise bad(f"route {i} may only have `path`, `allow` and `method`")
        method = route.get("method", "GET")
        if not isinstance(method, str) or method.upper() not in _METHODS:
            raise bad(f"route {i}: method {method!r} is not allowed; only GET and HEAD are sent")
        err = _path_error(route["path"])
        if err:
            raise bad(f"route {i}: path {err}")
        allow = route.get("allow", [])
        if not isinstance(allow, list) or not all(isinstance(r, str) and r in roles for r in allow):
            raise bad(f"route {i}: `allow` must list roles defined under `roles`")
        routes.append((method.upper(), route["path"], set(allow)))
    return roles, routes


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: a denied role is often sent to a login page that answers 200, which
    must not read as access. The 3xx comes back as an HTTPError and counts as a denial."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def run_role_matrix(target_url: str, roles: Roles, routes: Routes) -> list[BolaFinding]:
    """Send one request per route per role; report a 2xx to a role outside `allow` and a 3xx/401/403 to one inside."""
    url_error = target_url_error(target_url)
    if url_error:
        raise RoleMatrixError(url_error)
    opener = urllib.request.build_opener(_NoRedirects())
    findings: list[BolaFinding] = []
    for method, path, allow in routes:
        full_url = _probe_url(target_url, path)
        for role, (env, token) in roles.items():
            headers = {"User-Agent": f"PrufGate-BOLA-Probe/{__version__}", "Accept": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(full_url, headers=headers, method=method)
            try:
                with opener.open(req, timeout=3) as resp:
                    status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            except (urllib.error.URLError, OSError) as e:
                raise RoleMatrixError(f"{method} {path} as {role} failed: {getattr(e, 'reason', e)}") from e
            auth = f'-H "Authorization: Bearer ${env}" ' if token else ""
            poc = f"curl -s -i {'-I ' if method == 'HEAD' else ''}{auth}'{full_url}'"
            if 200 <= status < 300 and role not in allow:
                findings.append(BolaFinding(
                    rule_id="bfla-role-allowed",
                    severity="P0",
                    message=f"Role {role} is not allowed on {method} {path} but got HTTP {status}",
                    endpoint_or_file=path,
                    curl_poc=poc,
                    details="Function-level authorisation: the role matrix denies this role, the server answered with success.",
                ))
            elif (300 <= status < 400 or status in (401, 403)) and role in allow:
                findings.append(BolaFinding(
                    rule_id="bfla-allow-denied",
                    severity="P3",
                    message=f"Role {role} is allowed on {method} {path} in the role matrix but got HTTP {status}; the matrix may be stale",
                    endpoint_or_file=path,
                    curl_poc=poc,
                ))
    return findings
