import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate.config import ConfigError, PrufGateConfig
from prufgate.contract_guard import ghost_symbols, scan_contract_guard
from prufgate.contract_guard.ghost_symbols import scan_file_ghost_symbols


def _write(root: Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _ghosts(root: Path, rel: str, third_party: bool = False, added=None) -> list:
    path = root / rel
    found = scan_file_ghost_symbols(path, rel, path.read_text(encoding="utf-8"), root, added, third_party)
    return sorted(f.message.split("`")[1] for f in found)


class PythonInRepo(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _write(
            self.ws,
            {
                "shop/__init__.py": "from .billing import charge\n__all__ = ['charge', 'lazy_name']\n",
                "shop/billing.py": (
                    "import os\nfrom shop.models import Order as Order\n"
                    "def charge(amount):\n    return amount\n"
                    "if os.name == 'nt':\n    def refund(x):\n        return x\nelse:\n    def refund(x):\n        return -x\n"
                    "try:\n    from json import dumps as fast_dumps\nexcept ImportError:\n    fast_dumps = None\n"
                    "class Invoice:\n    def total(self):\n        return 0\n"
                    "RATE: float = 1.0\n"
                ),
                "shop/models.py": "class Order:\n    pass\n",
                "shop/starry.py": "from shop.models import *\n",
                "shop/lazy.py": "def __getattr__(name):\n    return name\n",
            },
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_missing_name_is_flagged_and_existing_names_pass(self) -> None:
        _write(self.ws, {"app.py": "from shop.billing import charge, refund, Invoice, RATE, fast_dumps, charge_card\n"})
        self.assertEqual(_ghosts(self.ws, "app.py"), ["charge_card"])

    def test_deeply_nested_or_huge_module_is_unknown_not_a_crash(self) -> None:
        _write(self.ws, {
            "shop/deep.py": "x = 1\n",
            "shop/huge.py": "x = 1\n" + "#" * (3 * 1024 * 1024) + "\n",
            "app.py": "from shop.deep import missing\nfrom shop.huge import gone\nfrom shop.billing import charge_card\n",
        })
        real_parse = ghost_symbols.ast.parse

        def parse(source, *args, **kwargs):
            # Python 3.12 raises RecursionError on deeply nested expressions; 3.9 parses deeper.
            if source.startswith("x = 1\n") and len(source) < 10:
                raise RecursionError("maximum recursion depth exceeded")
            return real_parse(source, *args, **kwargs)

        with patch.object(ghost_symbols.ast, "parse", parse):
            self.assertEqual(_ghosts(self.ws, "app.py"), ["charge_card"])
            _write(self.ws, {"deep_app.py": "x = 1\n"})
            self.assertEqual(_ghosts(self.ws, "deep_app.py"), [])

    def test_name_added_inside_a_multiline_import_is_checked(self) -> None:
        _write(self.ws, {"app.py": "from shop.billing import (\n    charge,\n    charge_card,\n)\n"})
        path = self.ws / "app.py"
        found = scan_file_ghost_symbols(path, "app.py", path.read_text(), self.ws, {3})
        self.assertEqual([f.message.split("`")[1] for f in found], ["charge_card"])
        if sys.version_info >= (3, 10):  # older versions have no line numbers on import names
            self.assertEqual(found[0].line, 3)

    def test_parameter_elsewhere_does_not_hide_module_calls(self) -> None:
        _write(self.ws, {"app.py": (
            "import shop.billing as bill\n"
            "def helper(bill):\n    return bill.anything()\n"
            "bill.void(1)\n"
        )})
        self.assertEqual(_ghosts(self.ws, "app.py"), ["void"])

    def test_symlinked_submodule_outside_the_package_is_not_read(self) -> None:
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        _write(Path(outside.name), {"ext/__init__.py": "def real():\n    pass\n"})
        (self.ws / "shop" / "ext").symlink_to(Path(outside.name) / "ext", target_is_directory=True)
        _write(self.ws, {"app.py": "from shop import ext\next.missing()\n"})
        self.assertEqual(_ghosts(self.ws, "app.py"), [])

    def test_top_level_relative_import_does_not_search_the_parent(self) -> None:
        _write(self.ws, {"__init__.py": "x = 1\n", "app.py": "from . import ghost\n"})
        self.assertEqual(_ghosts(self.ws, "app.py"), [])

    def test_edited_module_is_read_again(self) -> None:
        _write(self.ws, {"app.py": "from shop.models import Customer\n"})
        self.assertEqual(_ghosts(self.ws, "app.py"), ["Customer"])
        _write(self.ws, {"shop/models.py": "class Order:\n    pass\nclass Customer:\n    pass\n"})
        self.assertEqual(_ghosts(self.ws, "app.py"), [])

    def test_reexports_package_init_and_all(self) -> None:
        _write(
            self.ws,
            {"app.py": "from shop import charge, lazy_name, billing\nfrom shop.billing import Order\nfrom shop import ghost\n"},
        )
        self.assertEqual(_ghosts(self.ws, "app.py"), ["ghost"])

    def test_relative_imports(self) -> None:
        _write(self.ws, {"shop/api.py": "from .billing import charge, invented\nfrom . import models, nothing_here\n"})
        self.assertEqual(_ghosts(self.ws, "shop/api.py"), ["invented", "nothing_here"])

    def test_star_import_and_module_getattr_are_skipped(self) -> None:
        _write(self.ws, {"app.py": "from shop.starry import anything\nfrom shop.lazy import whatever\n"})
        self.assertEqual(_ghosts(self.ws, "app.py"), [])

    def test_module_attribute_calls(self) -> None:
        _write(
            self.ws,
            {
                "app.py": (
                    "import shop.billing\nimport shop.models as m\nfrom shop import billing as b\n"
                    "shop.billing.charge(1)\nshop.billing.Invoice().total()\nm.Order()\nb.refund(2)\n"
                    "shop.billing.charge_now(1)\nm.Customer()\nb.void(3)\n"
                )
            },
        )
        self.assertEqual(_ghosts(self.ws, "app.py"), ["Customer", "charge_now", "void"])

    def test_rebound_alias_and_unknown_modules_are_skipped(self) -> None:
        _write(
            self.ws,
            {
                "app.py": (
                    "import shop.models as m\nimport not_in_repo\nfrom not_in_repo import thing\n"
                    "def f(m):\n    return m.anything()\nnot_in_repo.call()\n"
                )
            },
        )
        self.assertEqual(_ghosts(self.ws, "app.py"), [])

    def test_only_added_lines_are_checked(self) -> None:
        _write(self.ws, {"app.py": "from shop.billing import old_ghost\nfrom shop.billing import new_ghost\n"})
        self.assertEqual(_ghosts(self.ws, "app.py", added={2}), ["new_ghost"])


class TypeScriptInRepo(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        _write(
            self.ws,
            {
                "src/lib/math.ts": (
                    "export function add(a: number, b: number) { return a + b }\n"
                    "export const PI = 3.14, TAU = 6.28;\nexport class Vec {}\nexport interface Shape {}\n"
                    "const hidden = 1;\nexport { hidden as visible };\n"
                ),
                "src/lib/index.ts": "export * from './math';\nexport { default as Chart } from './chart';\n",
                "src/lib/chart.tsx": "export default function Chart() { return null }\n",
                "src/lib/opaque.ts": "export * from 'some-package';\n",
                "src/lib/broken.ts": "export * from './missing';\n",
            },
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_missing_export_is_flagged_existing_pass(self) -> None:
        _write(
            self.ws,
            {"src/page.ts": "import { add, PI, TAU, Vec, type Shape, visible as v } from './lib/math';\nimport { subtract } from './lib/math';\n"},
        )
        self.assertEqual(_ghosts(self.ws, "src/page.ts"), ["subtract"])

    def test_very_long_reexport_chain_is_unknown(self) -> None:
        files = {f"lib/a{i}.ts": f"export * from './a{i + 1}';\n" for i in range(100)}
        files["lib/a100.ts"] = "export const x = 1;\n"
        files["app.ts"] = "import { nope } from './lib/a0';\n"
        _write(self.ws, files)
        self.assertEqual(_ghosts(self.ws, "app.ts"), [])

    def test_barrel_index_and_js_extension(self) -> None:
        _write(
            self.ws,
            {"src/page.ts": "import {\n  add,\n  Chart,\n  multiply,\n} from './lib';\nimport { Vec } from './lib/math.js';\n"},
        )
        self.assertEqual(_ghosts(self.ws, "src/page.ts"), ["multiply"])

    def test_unresolved_export_star_and_unknown_targets_are_skipped(self) -> None:
        _write(
            self.ws,
            {
                "src/page.ts": (
                    "import { anything } from './lib/opaque';\nimport { other } from './lib/broken';\n"
                    "import { nope } from './does/not/exist';\nimport { ext } from 'external-package';\n"
                    "// import { commented } from './lib/math';\n"
                )
            },
        )
        self.assertEqual(_ghosts(self.ws, "src/page.ts"), [])


class ThirdParty(unittest.TestCase):
    def test_installed_package_is_read_never_imported(self) -> None:
        with tempfile.TemporaryDirectory() as site, tempfile.TemporaryDirectory() as tmp:
            _write(
                Path(site),
                {
                    "fakevendorpkg/__init__.py": "raise SystemExit('imported')\ndef real_api():\n    pass\n",
                    "fakevendorpkg/client.py": "raise SystemExit('imported')\nclass Client:\n    pass\n",
                    "fakevendorpkg/typed.py": "raise SystemExit('imported')\n",
                    "fakevendorpkg/typed.pyi": "def typed_api() -> None: ...\n",
                },
            )
            ws = Path(tmp)
            _write(
                ws,
                {
                    "app.py": (
                        "import fakevendorpkg.client as c\n"
                        "from fakevendorpkg import real_api, client, ghost_api\n"
                        "from fakevendorpkg.typed import typed_api, untyped_api\n"
                        "c.Client()\nc.Server()\n"
                    )
                },
            )
            sys.path.insert(0, site)
            try:
                self.assertEqual(_ghosts(ws, "app.py"), [])  # off by default
                self.assertEqual(_ghosts(ws, "app.py", third_party=True), ["Server", "ghost_api", "untyped_api"])
            finally:
                sys.path.remove(site)
            self.assertFalse([m for m in sys.modules if m.startswith("fakevendorpkg")])

    def test_config_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _write(Path(tmp), {".prufgate/config.yaml": "ghost_symbols: {third_party: true}\n"})
            self.assertTrue(PrufGateConfig.load(Path(tmp)).ghost_third_party)
            _write(Path(tmp), {".prufgate/config.yaml": "ghost_symbols: {third_party: 1}\n"})
            with self.assertRaises(ConfigError):
                PrufGateConfig.load(Path(tmp))


class ChangedScan(unittest.TestCase):
    def test_contract_guard_flags_ghosts_on_added_lines_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)

            def git(*args: str) -> None:
                subprocess.run(["git", *args], cwd=ws, check=True, capture_output=True)

            git("init", "-q", "-b", "main")
            _write(ws, {"lib.py": "def real():\n    pass\n", "app.py": "from lib import old_ghost\n"})
            git("add", ".")
            git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base")
            _write(ws, {"app.py": "from lib import old_ghost\nfrom lib import real, new_ghost\n"})
            found = [f for f in scan_contract_guard(ws, changed_only=True) if f.rule == "ghost-symbol"]
            self.assertEqual([(f.line, f.severity) for f in found], [(2, "P1")])
            self.assertIn("new_ghost", found[0].message)

    def _repo(self, ws: Path) -> None:
        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=ws, check=True, capture_output=True)

        git("init", "-q", "-b", "main")
        git("config", "core.fileMode", "true")
        _write(ws, {"lib.py": "def real():\n    pass\n", "app.py": "from lib import old_ghost\n"})
        git("add", ".")
        git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base")

    def test_mode_only_change_adds_no_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._repo(ws)
            (ws / "app.py").chmod(0o755)
            self.assertEqual([f for f in scan_contract_guard(ws, changed_only=True) if f.rule == "ghost-symbol"], [])

    def test_git_diff_failure_fails_closed(self) -> None:
        import prufgate.contract_guard as cg
        from prufgate.config import GitDiffError

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._repo(ws)
            _write(ws, {"app.py": "from lib import old_ghost\nfrom lib import new_ghost\n"})
            with patch.object(cg, "_git", side_effect=GitDiffError("git diff failed")):
                with self.assertRaises(GitDiffError):
                    scan_contract_guard(ws, changed_only=True)


if __name__ == "__main__":
    unittest.main()
