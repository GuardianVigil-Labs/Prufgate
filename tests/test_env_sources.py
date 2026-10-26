"""Env drift against config schemas and deploy manifests (`env_sources.py`)."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from prufgate.config import PrufGateConfig
from prufgate.contract_guard import scan_contract_guard
from prufgate.contract_guard.env_sources import load_env_sources


def _write(ws: Path, rel: str, text: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class EnvSourcesTest(unittest.TestCase):
    def _names(self, files: dict[str, str], config: PrufGateConfig | None = None) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for rel, text in files.items():
                _write(ws, rel, text)
            return load_env_sources(ws, config)

    def test_zod_object(self) -> None:
        names = self._names({"src/env.ts": (
            "import { z } from 'zod';\n"
            "export const env = z.object({\n  DATABASE_URL: z.string().url(),\n  'QUOTED_KEY': z.string(),\n"
            "  // COMMENTED_KEY: z.string(),\n  /* BLOCK_KEY: z.string() */\n  camelKey: z.string(),\n"
            "}).parse(process.env);\n"
        )})
        self.assertIn("DATABASE_URL", names)
        self.assertIn("QUOTED_KEY", names)
        self.assertNotIn("COMMENTED_KEY", names)
        self.assertNotIn("BLOCK_KEY", names)

    def test_t3_create_env(self) -> None:
        names = self._names({"src/env.mjs": (
            "export const env = createEnv({\n"
            "  server: { AUTH_SECRET: z.string() },\n"
            "  client: { NEXT_PUBLIC_SITE_URL: z.string().url() },\n"
            "  runtimeEnv: { RUNTIME_ONLY: process.env.RUNTIME_ONLY },\n"
            "});\n"
        )})
        self.assertTrue({"AUTH_SECRET", "NEXT_PUBLIC_SITE_URL"} <= names)
        self.assertNotIn("RUNTIME_ONLY", names)

    def test_zod_outside_env_file_is_ignored(self) -> None:
        self.assertEqual(self._names({"src/forms.ts": "z.object({ FORM_FIELD: z.string() })\n"}), set())

    def test_pydantic_settings(self) -> None:
        names = self._names({"app/settings.py": (
            "from pydantic import Field, AliasChoices\n"
            "from pydantic_settings import BaseSettings, SettingsConfigDict\n"
            "class Settings(BaseSettings):\n"
            "    model_config = SettingsConfigDict(env_prefix='APP_')\n"
            "    db_url: str\n"
            "    token: str = Field(alias='SERVICE_TOKEN')\n"
            "    region: str = Field(validation_alias=AliasChoices('CLOUD_REGION', 'REGION_NAME'))\n"
            "class Extra(Settings):\n"
            "    feature: bool = False\n"
            "class Legacy(BaseSettings):\n"
            "    class Config:\n"
            "        env_prefix = 'OLD_'\n"
            "    host: str\n"
            "class NotSettings:\n"
            "    plain_field: str\n"
            "# class Ghost(BaseSettings): ghost_field: str\n"
        )})
        self.assertTrue({"APP_DB_URL", "SERVICE_TOKEN", "CLOUD_REGION", "REGION_NAME", "FEATURE", "OLD_HOST"} <= names)
        self.assertNotIn("APP_TOKEN", names)
        self.assertNotIn("PLAIN_FIELD", names)
        self.assertNotIn("GHOST_FIELD", names)

    def test_docker_compose(self) -> None:
        names = self._names({
            "docker-compose.yml": (
                "services:\n  api:\n    environment:\n      - LIST_VAR=1\n      - BARE_VAR\n"
                "    env_file: [./api.env]\n  worker:\n    environment:\n      MAP_VAR: x\n"
                "    # COMMENT_VAR: y\n"
            ),
            "api.env": "FROM_ENV_FILE=1\n",
        })
        self.assertTrue({"LIST_VAR", "BARE_VAR", "MAP_VAR", "FROM_ENV_FILE"} <= names)
        self.assertNotIn("COMMENT_VAR", names)

    def test_compose_env_file_outside_workspace_is_ignored(self) -> None:
        names = self._names({"compose.yaml": "services:\n  a:\n    env_file: ../../etc/outside.env\n"})
        self.assertEqual(names, set())

    def test_kubernetes_env_and_env_from(self) -> None:
        names = self._names({"k8s/app.yaml": (
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: app-config}\ndata: {CM_KEY: '1'}\n---\n"
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: app}\nspec:\n  template:\n    spec:\n"
            "      containers:\n      - name: app\n        env:\n        - name: K8S_VAR\n          value: x\n"
            "        envFrom:\n        - configMapRef: {name: app-config}\n          prefix: P_\n"
            "        - secretRef: {name: external-secret}\n"
        )})
        self.assertIn("K8S_VAR", names)
        self.assertIn("P_CM_KEY", names)
        self.assertNotIn("CM_KEY", names)  # only through envFrom, with its prefix

    def test_yaml_outside_conventional_paths_is_ignored(self) -> None:
        self.assertEqual(self._names({"data/random.yaml": "env: {NOT_A_MANIFEST: 1}\n"}), set())

    def test_helm_values_and_templates(self) -> None:
        names = self._names({
            "charts/app/values.yaml": "env:\n  - name: HELM_VALUE_VAR\n    value: x\n",
            "charts/app/templates/deployment.yaml": (
                "spec:\n  containers:\n    - name: {{ .Chart.Name }}\n      env:\n"
                "        - name: HELM_TEMPLATE_VAR\n          value: {{ .Values.x | quote }}\n"
                "        - name: lower-case-container\n"
                "        # - name: COMMENTED_TEMPLATE_VAR\n"
            ),
        })
        self.assertTrue({"HELM_VALUE_VAR", "HELM_TEMPLATE_VAR"} <= names)
        self.assertNotIn("COMMENTED_TEMPLATE_VAR", names)

    def test_github_actions_env(self) -> None:
        names = self._names({".github/workflows/ci.yml": "env:\n  WORKFLOW_VAR: x\njobs:\n  t:\n    env: {JOB_VAR: y}\n"})
        self.assertTrue({"WORKFLOW_VAR", "JOB_VAR"} <= names)

    def test_malformed_yaml_is_skipped_with_a_warning(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            names = self._names({
                "docker-compose.yml": "services: [unclosed\n  environment: {BROKEN_VAR: 1\n",
                "k8s/ok.yaml": "env:\n- name: GOOD_VAR\n",
            })
        self.assertIn("GOOD_VAR", names)
        self.assertNotIn("BROKEN_VAR", names)
        self.assertIn("invalid YAML", err.getvalue())

    def test_alias_bomb_and_cyclic_alias_do_not_hang_or_crash(self) -> None:
        bomb = "a0: &a0 [x]\n" + "".join(
            f"a{i}: &a{i} [{','.join([f'*a{i - 1}'] * 9)}]\n" for i in range(1, 12)
        ) + "env:\n- name: BOMB_VAR\n"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            names = self._names({
                "deploy/bomb.yaml": bomb,
                "k8s/cycle.yaml": "r: &r [*r]\nm: &m {b: *m}\nenv:\n- name: CYCLE_VAR\n",
            })
        self.assertTrue({"BOMB_VAR", "CYCLE_VAR"} <= names)

    def test_node_budget_stops_the_walk_with_a_warning(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                unittest.mock.patch("prufgate.contract_guard.env_sources._MAX_YAML_NODES", 3):
            self._names({"k8s/big.yaml": "a: [[1], [2], [3], [4]]\n"})
        self.assertIn("partly read", err.getvalue())

    def test_symlink_outside_the_workspace_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as tmp:
            _write(Path(outside), "app.yaml", "env:\n- name: OUTSIDE_VAR\n")
            ws = Path(tmp)
            (ws / "k8s").mkdir()
            (ws / "k8s/app.yaml").symlink_to(Path(outside) / "app.yaml")
            _write(ws, "k8s/own.yaml", "env:\n- name: OWN_VAR\n")
            names = load_env_sources(ws)
        self.assertIn("OWN_VAR", names)
        self.assertNotIn("OUTSIDE_VAR", names)

    def test_exclude_config_is_respected(self) -> None:
        cfg = PrufGateConfig()
        cfg.exclude = ["deploy/legacy"]
        names = self._names({"deploy/legacy/app.yaml": "env:\n- name: EXCLUDED_VAR\n"}, cfg)
        self.assertNotIn("EXCLUDED_VAR", names)

    def test_oversized_file_is_skipped(self) -> None:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            names = self._names({"k8s/big.yaml": "env:\n- name: BIG_VAR\n" + "# pad\n" * 200_000})
        self.assertNotIn("BIG_VAR", names)

    def test_engine_counts_manifest_vars_as_documented(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, ".env.example", "DATABASE_URL=\n")
            _write(ws, "docker-compose.yml", "services:\n  api:\n    environment: [COMPOSE_ONLY_VAR=1]\n")
            _write(ws, "src/env.ts", "export const e = z.object({ SCHEMA_ONLY_VAR: z.string() });\n")
            _write(ws, "src/app.ts", (
                "export const a = process.env.COMPOSE_ONLY_VAR;\n"
                "export const b = process.env.SCHEMA_ONLY_VAR;\n"
                "export const c = process.env.TRULY_UNDOCUMENTED_VAR;\n"
            ))
            findings = [f for f in scan_contract_guard(ws) if f.rule == "undocumented-env-var-drift"]
            self.assertEqual([f.line for f in findings], [3])
            self.assertIn("TRULY_UNDOCUMENTED_VAR", findings[0].message)

    def test_manifests_alone_do_not_switch_the_rule_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "docker-compose.yml", "services:\n  db:\n    environment: [POSTGRES_PASSWORD=x]\n")
            _write(ws, "src/app.ts", "export const c = process.env.SOME_UNDOCUMENTED_VAR;\n")
            self.assertEqual([f for f in scan_contract_guard(ws) if f.rule == "undocumented-env-var-drift"], [])


if __name__ == "__main__":
    unittest.main()
