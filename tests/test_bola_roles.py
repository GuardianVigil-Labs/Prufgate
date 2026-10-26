"""Issue #63: `prufgate bola --url URL --roles FILE`, a function-level authorisation
check against a role matrix of the developer's own test accounts."""

import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate import cli

ADMIN = "role_token_admin_7f3a9c"
MEMBER = "role_token_member_2b8d1e"
ENV = {"PRUFGATE_ROLE_ADMIN": ADMIN, "PRUFGATE_ROLE_MEMBER": MEMBER}

# What the invented server lets through: /api/admin/users is (wrongly) open to members.
SERVER_ALLOWS = {
    "/api/admin/users": {ADMIN, MEMBER},
    "/api/reports/export": {ADMIN, MEMBER},
    "/api/admin/health": {ADMIN},
}

ROLES = """roles:
  admin: { token_env: PRUFGATE_ROLE_ADMIN }
  member: { token_env: PRUFGATE_ROLE_MEMBER }
  anonymous: {}
routes:
"""


class Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a: object) -> None:
        pass

    def _reply(self) -> None:
        if self.path != "/":  # the liveness check
            Handler.seen.append((self.command, self.path, self.headers.get("Authorization", "")))
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        if self.path == "/login":
            code = 200
        elif self.path == "/api/billing" and token != ADMIN:
            code = 302  # a denied role is sent to the login page, which answers 200
        else:
            allowed = SERVER_ALLOWS.get(self.path, {ADMIN} if self.path == "/api/billing" else None)
            code = 404 if allowed is None else 200 if token in allowed else 401 if not token else 403
        self.send_response(code)
        if code == 302:
            self.send_header("Location", "/login")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(b"{}")

    do_GET = _reply
    do_HEAD = _reply


class BolaRoles(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self) -> None:
        Handler.seen = []
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_roles(self, routes: str, env: dict = ENV, fmt: str = "json") -> tuple[int, str, str]:
        roles = Path(self.tmp.name) / "roles.yaml"
        roles.write_text(ROLES + routes, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        argv = ["bola", self.tmp.name, "--url", self.url, "--roles", str(roles), "--format", fmt]
        with patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_over_permissive_route_is_flagged(self) -> None:
        rc, out, _ = self.run_roles("  - { path: /api/admin/users, allow: [admin] }\n")
        self.assertEqual(rc, 1)
        findings = json.loads(out)
        self.assertEqual([(f["rule_id"], f["severity"]) for f in findings], [("bfla-role-allowed", "P0")])
        self.assertIn("member", findings[0]["message"])
        self.assertIn("$PRUFGATE_ROLE_MEMBER", findings[0]["curl_poc"])
        self.assertEqual(len(Handler.seen), 3)  # one request per role
        self.assertTrue(all(m == "GET" for m, _, _ in Handler.seen))

    def test_correct_matrix_has_no_findings(self) -> None:
        rc, out, _ = self.run_roles(
            "  - { path: /api/admin/users, allow: [admin, member] }\n"
            "  - { path: /api/reports/export, allow: [admin, member] }\n"
            "  - { path: /api/admin/health, method: HEAD, allow: [admin] }\n"
        )
        self.assertEqual((rc, json.loads(out)), (0, []))
        self.assertIn(("HEAD", "/api/admin/health", "Bearer " + ADMIN), Handler.seen)
        self.assertIn(("GET", "/api/admin/users", ""), Handler.seen)  # anonymous: no token

    def test_stale_allow_is_a_p3_note(self) -> None:
        rc, out, _ = self.run_roles("  - { path: /api/admin/health, method: HEAD, allow: [admin, member] }\n")
        self.assertEqual(rc, 0)
        self.assertEqual([(f["rule_id"], f["severity"]) for f in json.loads(out)], [("bfla-allow-denied", "P3")])

    def test_login_redirect_is_a_denial_not_access(self) -> None:
        rc, out, _ = self.run_roles("  - { path: /api/billing, allow: [admin] }\n")
        self.assertEqual((rc, json.loads(out)), (0, []))
        self.assertNotIn("/login", [p for _, p, _ in Handler.seen])  # never followed
        rc, out, _ = self.run_roles("  - { path: /api/billing, allow: [admin, member] }\n")
        self.assertEqual(rc, 0)
        findings = json.loads(out)
        self.assertEqual([f["rule_id"] for f in findings], ["bfla-allow-denied"])
        self.assertIn("member", findings[0]["message"])
        self.assertIn("HTTP 302", findings[0]["message"])

    def test_non_get_methods_are_rejected(self) -> None:
        for method in ("POST", "DELETE", "PUT", "OPTIONS"):
            rc, _, err = self.run_roles(f"  - {{ path: /api/admin/users, method: {method}, allow: [admin] }}\n")
            self.assertEqual(rc, 2, method)
            self.assertIn("only GET and HEAD", err)
        self.assertEqual(Handler.seen, [])

    def test_bad_paths_are_rejected(self) -> None:
        for path in ("api/x", "//evil.example/x", "/a//b", "http://evil.example/x", "/a/../admin", "/a/%2e%2e/b", "/a\\\\b", "/a b"):
            rc, _, err = self.run_roles(f"  - {{ path: {json.dumps(path)}, allow: [admin] }}\n")
            self.assertEqual(rc, 2, path)
            self.assertIn("path", err)
        self.assertEqual(Handler.seen, [])

    def test_malformed_file_and_aliases_exit_2(self) -> None:
        for routes in ("  - [\n", "  - &r { path: /a, allow: [admin] }\n  - *r\n", "  - { path: /a, allow: [root] }\n"):
            rc, _, _ = self.run_roles(routes)
            self.assertEqual(rc, 2, routes)

    def test_tokens_never_in_output(self) -> None:
        for fmt in ("json", "text"):
            rc, out, err = self.run_roles(
                "  - { path: /api/admin/users, allow: [admin] }\n  - { path: /api/admin/health, method: HEAD, allow: [admin, member] }\n",
                fmt=fmt,
            )
            self.assertEqual(rc, 1)
            for token in (ADMIN, MEMBER):
                self.assertNotIn(token, out + err)

    def test_missing_env_var_exits_2(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PRUFGATE_ROLE_MEMBER", None)
            rc, _, err = self.run_roles("  - { path: /api/admin/users, allow: [admin] }\n", env={"PRUFGATE_ROLE_ADMIN": ADMIN})
        self.assertEqual(rc, 2)
        self.assertIn("PRUFGATE_ROLE_MEMBER is not set", err)
        self.assertEqual(Handler.seen, [])

    def test_bad_token_exits_2_without_printing_it(self) -> None:
        rc, out, err = self.run_roles("  - { path: /api/admin/users, allow: [admin, member] }\n",
                                      env={**ENV, "PRUFGATE_ROLE_MEMBER": MEMBER + "\n"})
        self.assertEqual((rc, json.loads(out)), (0, []))  # a trailing newline is stripped
        for bad in (MEMBER + "\r\nX-Injected: 1", MEMBER + " x", MEMBER + "\u00e9"):
            rc, out, err = self.run_roles("  - { path: /api/admin/users, allow: [admin] }\n",
                                          env={**ENV, "PRUFGATE_ROLE_MEMBER": bad})
            self.assertEqual(rc, 2, bad)
            self.assertIn("PRUFGATE_ROLE_MEMBER", err)
            self.assertNotIn(MEMBER, out + err)

    def test_bad_target_is_a_role_matrix_error(self) -> None:
        from prufgate.bola.role_matrix import RoleMatrixError, run_role_matrix

        with self.assertRaises(RoleMatrixError):
            run_role_matrix("ftp://203.0.113.5/", {}, [])

    def test_route_cap(self) -> None:
        roles = Path(self.tmp.name) / "roles.yaml"
        roles.write_text(ROLES + "  - { path: /a, allow: [] }\n  - { path: /b, allow: [] }\n", encoding="utf-8")
        with patch.dict(os.environ, ENV), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["bola", self.tmp.name, "--url", self.url, "--roles", str(roles), "--max-routes", "1"])
        self.assertEqual(rc, 2)
        self.assertEqual(Handler.seen, [])


if __name__ == "__main__":
    unittest.main()
