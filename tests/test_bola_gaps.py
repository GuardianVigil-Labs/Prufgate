"""Issue #22: static BOLA gaps after the Engine 5 fixes. Each gap has a sample that
must be flagged and a near miss that must not; GAP_CASES are also the self-check cases."""

from __future__ import annotations

import contextlib
import io
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from prufgate.bola.bola_engine import GAP_CASES, run_gap_case, run_static_matrix_audit
from prufgate.config import ConfigError, PrufGateConfig
from prufgate.diff_guard import tamper_detector as dg

U = "static-bola-unscoped-access"


def flagged(files: dict[str, str], **config) -> set[tuple[str, int]]:
    return {(f, line) for rule, f, line in run_gap_case(files, config) if rule == U}


def _audit(files: dict[str, str]) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        for rel, text in files.items():
            (ws / rel).parent.mkdir(parents=True, exist_ok=True)
            (ws / rel).write_text(text)
        with contextlib.redirect_stdout(io.StringIO()):
            return run_static_matrix_audit(ws)


EXPRESS_HEAD = "app.get('/api/invoices/:id', requireAuth, async (req, res) => {\n"
EXPRESS_LOOKUP = "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, orgId: org } }));\n});\n"


class GapCases(unittest.TestCase):
    def test_every_gap_case(self) -> None:
        for name, files, config, expected in GAP_CASES:
            with self.subTest(name):
                self.assertEqual(run_gap_case(files, config), expected)


class TracedLocals(unittest.TestCase):
    def test_javascript_one_and_two_hops(self) -> None:
        cases = {
            "const org = req.query.orgId;\n": True,
            "const q = req.query;\n  const org = q.orgId;\n": True,
            "const org: string = req.headers['x-org'] as string;\n": True,
            "const u = req.user;\n  const org = u.orgId;\n": False,
            "const org = ctx.state.user.orgId;\n": False,
            "const org = req.session.orgId;\n": False,
        }
        for assign, bad in cases.items():
            with self.subTest(assign):
                files = {"r.ts": EXPRESS_HEAD + "  " + assign + EXPRESS_LOOKUP}
                self.assertEqual(bool(flagged(files)), bad)

    def test_destructured_shorthand(self) -> None:
        body = "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, orgId } }));\n});\n"
        self.assertTrue(flagged({"r.ts": EXPRESS_HEAD + "  const { orgId } = req.body;\n" + body}))
        self.assertFalse(flagged({"r.ts": EXPRESS_HEAD + "  const { orgId } = req.user;\n" + body}))

    def test_python(self) -> None:
        def view(assign: str) -> dict[str, str]:
            return {
                "api.py": "@app.get('/invoices/{invoice_id}')\n"
                "def get(invoice_id: str, user=Depends(get_current_user)):\n"
                f"    {assign}\n"
                "    return db.query(Invoice).filter_by(id=invoice_id, org_id=org).first()\n"
            }

        self.assertTrue(flagged(view("org = request.query_params['org']")))
        self.assertTrue(flagged(view("org = request.headers.get('x-org')")))
        self.assertFalse(flagged(view("org = user.org_id")))
        self.assertFalse(flagged(view("org = current_user.org_id")))

    def test_php(self) -> None:
        def ctrl(assign: str) -> dict[str, str]:
            return {
                "app/Http/Controllers/BillController.php": "<?php\nclass BillController extends Controller\n{\n"
                "    public function __construct() { $this->middleware('auth'); }\n"
                "    public function show($id)\n    {\n"
                f"        {assign}\n"
                "        return Bill::where('org_id', $org)->findOrFail($id);\n    }\n}\n"
            }

        self.assertTrue(flagged(ctrl("$org = $request->input('org_id');")))
        self.assertFalse(flagged(ctrl("$org = auth()->user()->org_id;")))


class LaravelBinding(unittest.TestCase):
    def files(self, ctrl_body: str, route_tail: str = "") -> dict[str, str]:
        return {
            "routes/web.php": "<?php\nRoute::get('/invoices/{invoice}', [InvoiceController::class, 'update'])"
            f"->middleware('auth'){route_tail};\n",
            "app/Http/Controllers/InvoiceController.php": "<?php\nclass InvoiceController extends Controller\n{\n"
            + ctrl_body
            + "    public function update(UpdateInvoiceRequest $request, Invoice $invoice)\n    {\n"
            "        $invoice->update($request->validated());\n    }\n}\n",
        }

    def test_form_request_is_not_the_bound_model(self) -> None:
        self.assertTrue(flagged(self.files("")))

    def test_authorize_resource_and_route_can(self) -> None:
        ctor = "    public function __construct() { $this->authorizeResource(Invoice::class, 'invoice'); }\n"
        self.assertFalse(flagged(self.files(ctor)))
        self.assertFalse(flagged(self.files("", "->can('update', 'invoice')")))
        self.assertFalse(flagged(self.files("", "->scopeBindings()")))


class DjangoViews(unittest.TestCase):
    def test_generic_detail_view_and_object_permission(self) -> None:
        detail = "class InvoiceDetail(LoginRequiredMixin, DetailView):\n    model = Invoice\n"
        self.assertEqual(flagged({"views.py": detail}), {("views.py", 1)})
        scoped = {
            "perms.py": "class IsOwner(BasePermission):\n"
            "    def has_object_permission(self, request, view, obj):\n        return obj.owner == request.user\n",
            "views.py": "class InvoiceView(RetrieveAPIView):\n"
            "    permission_classes = [IsAuthenticated, IsOwner]\n    queryset = Invoice.objects.all()\n",
        }
        self.assertFalse(flagged(scoped))

    def test_kwargs_filter_is_request_input(self) -> None:
        view = (
            "class InvoiceViewSet(ModelViewSet):\n    permission_classes = [IsAuthenticated]\n"
            "    def get_queryset(self):\n        return Invoice.objects.filter(org_id=self.kwargs['org_id'])\n"
        )
        self.assertTrue(flagged({"views.py": view}))

    def test_drf_default_permission_classes(self) -> None:
        view = "class NoteViewSet(ModelViewSet):\n    def get_queryset(self):\n        return Note.objects.filter(owner=self.request.user)\n"
        settings = "REST_FRAMEWORK = {\n    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],\n}\n"
        self.assertTrue(flagged({"views.py": view}))
        self.assertFalse(flagged({"views.py": view, "settings.py": settings}))


class GlobalAuth(unittest.TestCase):
    NEST = GAP_CASES[3][1]

    def test_nest_public_decorator_opts_out(self) -> None:
        files = dict(self.NEST)
        files["src/invoices.controller.ts"] = "@Public()\n" + files["src/invoices.controller.ts"]
        self.assertTrue(flagged(files))

    def test_spring_needs_method_security_and_respects_permit_all(self) -> None:
        files = dict(GAP_CASES[5][1])
        cfg = files["SecurityConfig.java"]
        files["SecurityConfig.java"] = cfg.replace("@EnableMethodSecurity\n", "")
        self.assertIn(("DocController.java", 5), flagged(files))
        # No @PreAuthorize: auth comes from anyRequest().authenticated(), unless the path is permitAll().
        files["SecurityConfig.java"] = cfg
        files["NoteController.java"] = files["NoteController.java"].replace("    @PreAuthorize(\"hasRole('USER')\")\n", "")
        messages = [f.message for f in _audit(files) if f.endpoint_or_file == "NoteController.java"]
        self.assertEqual(len(messages), 1)
        self.assertNotIn("authentication", messages[0])
        files["SecurityConfig.java"] = cfg.replace("a.anyRequest()", 'a.requestMatchers("/api/notes/**").permitAll().anyRequest()')
        self.assertIn("missing both", [f.message for f in _audit(files) if f.endpoint_or_file == "NoteController.java"][0])

    def test_express_prefixes_and_inline_auth(self) -> None:
        router = GAP_CASES[6][1]["src/routes/invoices.ts"]

        def app(*lines: str) -> dict[str, str]:
            entry = "const invoices = require('./routes/invoices');\n" + "".join(f"{ln}\n" for ln in lines)
            return {"src/app.js": entry, "src/routes/invoices.ts": router}

        self.assertFalse(flagged(app("app.use('/api', requireAuth);", "app.use('/api/invoices', invoices);")))
        self.assertTrue(flagged(app("app.use('/admin', requireAuth);", "app.use('/api/invoices', invoices);")))
        self.assertFalse(flagged(app("app.use('/api/invoices', passport.authenticate('jwt'), invoices);")))
        self.assertTrue(flagged(app("app.use('/api/invoices', invoices);", "app.use(requireAuth);")))

    def test_fastify_hook_before_register(self) -> None:
        plugin = (
            "export default async function (fastify) {\n"
            "  fastify.get('/invoices/:id', async (req) => {\n"
            "    return prisma.invoice.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });\n"
            "  });\n}\n"
        )
        entry = "import invoiceRoutes from './invoices';\n"
        hook = "fastify.addHook('onRequest', fastify.authenticate);\n"
        register = "fastify.register(invoiceRoutes);\n"
        self.assertFalse(flagged({"src/server.ts": entry + hook + register, "src/invoices.ts": plugin}))
        self.assertTrue(flagged({"src/server.ts": entry + register + hook, "src/invoices.ts": plugin}))


class GlobalAuthOnlyInCode(unittest.TestCase):
    """Application-wide auth counts only as code in an entry or config file: never in a
    comment, a string or an unrelated file, and never a middleware that authenticates no one."""

    ROUTER = GAP_CASES[6][1]["src/routes/invoices.ts"]
    NEST = GAP_CASES[3][1]["src/invoices.controller.ts"]
    DRF_VIEW = (
        "class InvoiceViewSet(viewsets.ModelViewSet):\n    queryset = Invoice.objects.all()\n"
        "    def get_queryset(self):\n        return Invoice.objects.filter(owner=self.request.user)\n"
    )
    DRF_SETTINGS = "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['IsAuthenticated']}\n"

    def express(self, *lines: str) -> dict[str, str]:
        entry = "import invoices from './routes/invoices';\nconst app = express();\n" + "".join(f"{ln}\n" for ln in lines)
        return {"src/app.ts": entry, "src/routes/invoices.ts": self.ROUTER}

    def test_express_non_auth_middleware(self) -> None:
        mount = "app.use('/api/invoices', invoices);"
        for mw in ("app.use(session({ secret: 'x' }));", "app.use(requestId());", "app.use(rateLimitGuard);",
                   "// app.use(requireAuth);", "const s = `\napp.use(requireAuth);\n`;"):
            with self.subTest(mw):
                self.assertTrue(flagged(self.express(mw, mount)))
        for mw in ("app.use(requireAuth);", "app.use(ensureAuthenticated);", "app.use(authMiddleware);",
                   "app.use(passport.authenticate('jwt'));", "app.use(requireLogin);"):
            with self.subTest(mw):
                self.assertFalse(flagged(self.express(mw, mount)))

    def test_nest_guard_in_comment_string_or_unrelated_file(self) -> None:
        guard = "app.useGlobalGuards(new JwtAuthGuard());\n"
        self.assertTrue(flagged({"src/invoices.controller.ts": self.NEST, "src/notes.ts": "// TODO: " + guard}))
        self.assertTrue(flagged({"src/invoices.controller.ts": self.NEST, "src/notes.ts": guard}))
        self.assertTrue(flagged({"src/invoices.controller.ts": self.NEST, "src/main.ts": "// " + guard}))
        self.assertTrue(flagged({"src/invoices.controller.ts": self.NEST, "src/main.ts": f"const doc = '{guard.strip()}';\n"}))
        self.assertFalse(flagged({"src/invoices.controller.ts": self.NEST, "src/main.ts": guard}))

    def test_spring_config_in_comment_or_non_config_class(self) -> None:
        files = {k: v for k, v in GAP_CASES[5][1].items() if k != "SecurityConfig.java"}
        text = "@EnableMethodSecurity with http.authorizeHttpRequests(a -> a.anyRequest().authenticated())\n"
        self.assertIn(("DocController.java", 5), flagged({**files, "Notes.java": "// see docs: " + text}))
        self.assertIn(("DocController.java", 5), flagged({**files, "Notes.java": "/* SecurityFilterChain\n" + text + "*/\n"}))
        self.assertNotIn(("DocController.java", 5), flagged({**files, "SecurityConfig.java": GAP_CASES[5][1]["SecurityConfig.java"]}))

    def test_drf_settings_in_comment_or_non_settings_file(self) -> None:
        self.assertTrue(flagged({"views.py": self.DRF_VIEW, "notes.py": "# " + self.DRF_SETTINGS}))
        self.assertTrue(flagged({"views.py": self.DRF_VIEW, "notes.py": self.DRF_SETTINGS}))
        self.assertTrue(flagged({"views.py": self.DRF_VIEW, "settings.py": "# " + self.DRF_SETTINGS}))
        self.assertTrue(flagged({"views.py": self.DRF_VIEW, "settings.py": f'DOC = "{self.DRF_SETTINGS.strip()}"\n'}))
        self.assertFalse(flagged({"views.py": self.DRF_VIEW, "settings.py": self.DRF_SETTINGS}))
        self.assertFalse(flagged({"views.py": self.DRF_VIEW, "config/settings/production.py": self.DRF_SETTINGS}))


class LaravelPolicyInCode(unittest.TestCase):
    def files(self, body: str, route_tail: str = "") -> dict[str, str]:
        return {
            "routes/web.php": f"<?php\nRoute::get('/invoices/{{invoice}}', [InvoiceController::class, 'show'])->middleware('auth'){route_tail};\n",
            "app/Http/Controllers/InvoiceController.php": "<?php\nclass InvoiceController extends Controller\n{\n"
            f"    public function show(Invoice $invoice)\n    {{\n{body}        return $invoice;\n    }}\n}}\n",
        }

    def test_commented_or_dead_authorize(self) -> None:
        for body in (
            "        // $this->authorize('view', $invoice);\n",
            "        /* $this->authorize('view', $invoice); */\n",
            "        # $this->authorize('view', $invoice);\n",
            "        if (false) { $this->authorize('view', $invoice); }\n",
            "        if (0) {\n            $this->authorize('view', $invoice);\n        }\n",
            "        return $invoice;\n        $this->authorize('view', $invoice);\n",
        ):
            with self.subTest(body):
                self.assertTrue(flagged(self.files(body)))
        self.assertFalse(flagged(self.files("        $this->authorize('view', $invoice);\n")))
        self.assertFalse(flagged(self.files("        if ($invoice->draft) { return abort(404); }\n        $this->authorize('view', $invoice);\n")))

    def test_commented_scope_bindings(self) -> None:
        self.assertTrue(flagged(self.files("", "; // ->scopeBindings()")))
        self.assertFalse(flagged(self.files("", "->scopeBindings()")))


class TracedBeforeNames(unittest.TestCase):
    def test_identity_named_local_holding_request_input(self) -> None:
        lookup = "  res.json(await prisma.invoice.findFirst({ where: { id: req.params.id, orgId: currentUser.orgId } }));\n});\n"
        self.assertTrue(flagged({"r.ts": EXPRESS_HEAD + "  const currentUser = req.query;\n" + lookup}))
        self.assertTrue(flagged({"r.ts": EXPRESS_HEAD + "  const { currentUser } = req.body;\n" + lookup}))
        self.assertFalse(flagged({"r.ts": EXPRESS_HEAD + "  const currentUser = req.user;\n" + lookup}))
        self.assertFalse(flagged({"r.ts": EXPRESS_HEAD + lookup}))

    def test_ownership_compare_against_request_input(self) -> None:
        body = (
            "  const doc = await prisma.doc.findUnique({ where: { id: req.params.id } });\n"
            "  if (doc.ownerId !== currentUser.id) return res.sendStatus(403);\n  res.json(doc);\n});\n"
        )
        self.assertTrue(flagged({"r.ts": EXPRESS_HEAD + "  const currentUser = req.query;\n" + body}))
        self.assertFalse(flagged({"r.ts": EXPRESS_HEAD + "  const currentUser = req.user;\n" + body}))


class RailsMembers(unittest.TestCase):
    def test_inline_member_block(self) -> None:
        files = dict(GAP_CASES[7][1])
        files["config/routes.rb"] = "Rails.application.routes.draw do\n  resources :invoices do\n    member { post :approve }\n  end\nend\n"
        files["app/controllers/invoices_controller.rb"] = (
            "class InvoicesController < ApplicationController\n  def approve\n    Invoice.find(params[:id]).approve!\n  end\nend\n"
        )
        self.assertEqual(flagged(files), {("app/controllers/invoices_controller.rb", 2)})

    def test_unrouted_method_is_not_a_member_action(self) -> None:
        files = dict(GAP_CASES[7][1])
        files["config/routes.rb"] = "Rails.application.routes.draw do\n  resources :invoices\nend\n"
        self.assertNotIn(("app/controllers/invoices_controller.rb", 2), flagged(files))


class GlobalTablesConfig(unittest.TestCase):
    def load(self, text: str) -> PrufGateConfig:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".prufgate.yml").write_text(text)
            return PrufGateConfig.load(tmp)

    def test_unlisted_lookup_table_is_still_flagged(self) -> None:
        files = GAP_CASES[8][1]
        self.assertEqual(len(run_gap_case(files, {})), 2)

    def test_parse_and_validate(self) -> None:
        self.assertEqual(self.load("bola:\n  global_tables: [countries, currencies]\n").bola_global_tables, ["countries", "currencies"])
        for bad in ("bola: [countries]\n", "bola:\n  other: 1\n", "bola:\n  global_tables: ['a b']\n", "bola:\n  global_tables: countries\n"):
            with self.subTest(bad), self.assertRaises(ConfigError):
                self.load(bad)

    def test_drift_detection(self) -> None:
        head = PrufGateConfig(bola_global_tables=["countries", "invoices"])
        base = PrufGateConfig(bola_global_tables=["countries"])
        texts = [f.message for f in dg._compare_configs(head, base, ".prufgate.yml", ignored=False)]
        self.assertTrue(any("bola.global_tables" in t and "invoices" in t for t in texts), texts)
        self.assertEqual(dg._compare_configs(base, head, ".prufgate.yml", ignored=False), [])
        diff = (
            "diff --git a/.prufgate.yml b/.prufgate.yml\n--- a/.prufgate.yml\n+++ b/.prufgate.yml\n"
            "@@ -1,2 +1,3 @@ bola:\n   global_tables:\n+    - invoices\n"
        )
        self.assertIn("prufgate-config-self-exemption", {f.rule for f in dg.scan_diff_for_tampering(diff)})

    def test_base_ref_reading(self) -> None:
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run([*git, "init", "-q", "-b", "main"], cwd=repo, check=True)
            (repo / ".prufgate.yml").write_text("bola:\n  global_tables: [countries]\n")
            subprocess.run([*git, "add", "-A"], cwd=repo, check=True)
            subprocess.run([*git, "commit", "-qm", "base"], cwd=repo, check=True)
            subprocess.run([*git, "checkout", "-qb", "feature"], cwd=repo, check=True)
            (repo / ".prufgate.yml").write_text("bola:\n  global_tables: [countries, invoices]\n")
            self.assertEqual(PrufGateConfig.load(repo, ref="main").bola_global_tables, ["countries"])
            self.assertEqual(PrufGateConfig.load(repo).bola_global_tables, ["countries", "invoices"])


class ReviewRoundTwo(unittest.TestCase):
    """Bypasses found in review: each sample must be flagged, each near miss must not."""

    ROUTER = GAP_CASES[6][1]["src/routes/invoices.ts"]

    def express(self, *lines: str) -> dict[str, str]:
        entry = "const invoices = require('./routes/invoices');\n" + "".join(f"{ln}\n" for ln in lines)
        return {"src/app.js": entry, "src/routes/invoices.ts": self.ROUTER}

    def test_require_cors_and_prefix_boundaries(self) -> None:
        self.assertTrue(flagged(self.express("app.use(require('cors')());", "app.use('/api/invoices', invoices);")))
        self.assertTrue(flagged(self.express("app.use('/api', requireAuth);", "app.use('/api-public/invoices', invoices);")))
        self.assertFalse(flagged(self.express("app.use('/api', requireAuth);", "app.use('/api/invoices', invoices);")))
        self.assertFalse(flagged(self.express("app.use('/api/', requireAuth);", "app.use('/api/invoices', invoices);")))

    def test_traced_local_bypasses(self) -> None:
        for assign in (
            "let org = req.query.orgId;\n  if (false) {\n    org = req.user.orgId;\n  }\n",
            "const a = req.query.orgId;\n  const b = a;\n  const c2 = b;\n  const org = c2;\n",
            "const [org] = [req.query.orgId];\n",
            "const raw = req.query.orgId;\n  const org = String(raw);\n",
            "const org = req.user.orgId || req.query.orgId;\n",
        ):
            with self.subTest(assign):
                self.assertTrue(flagged({"r.ts": EXPRESS_HEAD + "  " + assign + EXPRESS_LOOKUP}))
        for assign in ("const u = req.user;\n  const org = String(u.orgId);\n", "const org = req.user.orgId;\n"):
            with self.subTest(assign):
                self.assertFalse(flagged({"r.ts": EXPRESS_HEAD + "  " + assign + EXPRESS_LOOKUP}))

    def test_ownership_call_must_be_live_and_checked(self) -> None:
        lookup = "  const doc = await prisma.doc.findUnique({ where: { id: req.params.id } });\n  res.json(doc);\n});\n"
        for check in (
            "  // authorize(req.user, doc);\n",
            "  const note = 'call authorize(user) first';\n",
            "  checkAccess();\n",
            "  canAccess(req.user, req.params.id);\n",
        ):
            with self.subTest(check):
                self.assertTrue(flagged({"r.ts": EXPRESS_HEAD + check + lookup}))
        for check in (
            "  await authorize(req.user, 'doc:read', req.params.id);\n",
            "  if (!(await canAccess(req.user, req.params.id))) return res.sendStatus(403);\n",
        ):
            with self.subTest(check):
                self.assertFalse(flagged({"r.ts": EXPRESS_HEAD + check + lookup}))

    def laravel(self, sig: str, body: str = "", routes: str = "") -> dict[str, str]:
        return {
            "routes/web.php": "<?php\nRoute::get('/invoices/{invoice}', [InvoiceController::class, 'show'])->middleware('auth');\n"
            "Route::get('/invoices/{invoice}/edit', [InvoiceController::class, 'edit'])->middleware('auth');\n" + routes,
            "app/Http/Controllers/InvoiceController.php": "<?php\nclass InvoiceController extends Controller\n{\n"
            f"    public function show({sig})\n    {{\n{body}        return $invoice;\n    }}\n}}\n",
        }

    def test_laravel_binding_bypasses(self) -> None:
        self.assertTrue(flagged(self.laravel("Invoice $invoice, string $traceId = ''")))
        self.assertTrue(flagged(self.laravel("Invoice $invoice", "        Gate::allows('view', $invoice);\n")))
        self.assertTrue(flagged(self.laravel("Invoice $invoice", "        $request->user()->can('view', $invoice);\n")))
        self.assertTrue(flagged(self.laravel(
            "Invoice $invoice", routes="Route::get('/invoices/{invoice}/pdf', [InvoiceController::class, 'pdf'])->can('view', 'invoice');\n"
        )))
        self.assertFalse(flagged(self.laravel("Invoice $invoice", "        abort_unless(Gate::allows('view', $invoice), 403);\n")))
        self.assertFalse(flagged(self.laravel("Invoice $invoice", "        if (! $request->user()->can('view', $invoice)) { abort(403); }\n")))
        self.assertFalse(flagged(self.laravel(
            "Invoice $invoice", routes="Route::get('/x/{invoice}', [InvoiceController::class, 'show'])->can('view', 'invoice');\n"
        )))
        self.assertFalse(flagged(self.laravel("Invoice $invoice", routes="Route::resource('invoices', InvoiceController::class)->scoped();\n")))

    def test_django_object_permission_and_queryset(self) -> None:
        stub = "class IsOwner(BasePermission):\n    def has_object_permission(self, request, view, obj):\n        return True\n"
        real = "class IsOwner(BasePermission):\n    def has_object_permission(self, request, view, obj):\n        return obj.owner == request.user\n"
        listed = "class InvoiceView(RetrieveAPIView):\n    permission_classes = [IsAuthenticated, IsOwner]\n    queryset = Invoice.objects.all()\n"
        mention = "class InvoiceView(RetrieveAPIView):\n    # IsOwner is applied upstream\n    queryset = Invoice.objects.all()\n"
        self.assertTrue(flagged({"perms.py": stub, "views.py": listed}))
        self.assertTrue(flagged({"perms.py": real, "views.py": mention}))
        self.assertFalse(flagged({"perms.py": real, "views.py": listed}))
        qs = "class InvoiceViewSet(ModelViewSet):\n    permission_classes = [IsAuthenticated]\n    def get_queryset(self):\n"
        for body in (
            "        if self.request.user.is_authenticated:\n            return super().get_queryset()\n",
            "        u = self.request.user\n        return Invoice.objects.all()\n",
        ):
            with self.subTest(body):
                self.assertTrue(flagged({"views.py": qs + body}))
        for body in (
            "        return Invoice.objects.filter(owner=self.request.user)\n",
            "        return self.request.user.invoices.all()\n",
        ):
            with self.subTest(body):
                self.assertFalse(flagged({"views.py": qs + body}))

    def test_spring_bean_check_needs_the_object(self) -> None:
        files = dict(GAP_CASES[5][1])
        ctrl = files["DocController.java"]
        exprs = re.findall(r'@PreAuthorize\("([^"]*)"\)', ctrl)
        self.assertTrue(exprs, ctrl)
        files["DocController.java"] = ctrl.replace(exprs[0], "@guard.check()")
        self.assertIn(("DocController.java", 5), flagged(files))
        files["DocController.java"] = ctrl.replace(exprs[0], "@guard.canRead(#id, authentication)")
        self.assertNotIn(("DocController.java", 5), flagged(files))


if __name__ == "__main__":
    unittest.main()
