"""Contract tests for gate.py verdict classification (no network). Run: python test_gate.py"""
import os
import sys

os.environ.setdefault("GITHUB_REPOSITORY", "example/repo")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate  # noqa: E402

fails = []


def check(name, cond):
    print(("  OK   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


quota = {"valid": False, "score": 0, "validation_type": "quota", "provider": "quota-gate",
         "issues": ["[quota] You've used all 25 free validations."], "suggestions": ["Start a free trial at https://verificate.ai/auth/signup"],
         "quota": {"tier": "free", "used": 25, "limit": 25, "reason": "free_limit"}}
badkey = dict(quota, quota={"tier": "key", "reason": "invalid_key"})
unreviewed = {"valid": False, "score": 100.0, "review_unavailable": True, "protection": {"vetoed": False}, "issues": ["[gate] high|review_unavailable|..."]}
veto = {"valid": False, "score": 0, "protection": {"vetoed": True, "vetoed_by": ["code_reality_gate"]}, "issues": ["[code_reality_gate] Mock implementation detected"]}
rejected = {"valid": False, "score": 41.0, "protection": {"vetoed": False}, "issues": ["[llm] critical|L2|SQL injection"]}
approved = {"valid": True, "score": 92.0, "protection": {"vetoed": False}, "issues": []}

for name, obj, kind in (("exhausted free tier", quota, "access"), ("invalid / expired key", badkey, "access"),
                        ("gate-side review timeout", unreviewed, "review")):
    m = gate._not_a_verdict(obj)
    check(f"{name} is NOT a verdict on the code (never blocks a merge)", bool(m) and m["_unavailable"] and m["kind"] == kind)
check("an invalid key is distinguished from an exhausted quota", gate._not_a_verdict(badkey)["reason"] == "invalid_key")
for name, obj in (("a deterministic veto", veto), ("a model rejection", rejected), ("an approval", approved)):
    check(f"{name} IS a verdict and is passed through untouched", gate._not_a_verdict(obj) is None)
check("junk input never crashes the classifier", gate._not_a_verdict(None) is None and gate._not_a_verdict([1]) is None)

# ---- cross-file guard context (ported from PR #2): suppress-only, bounded, never breaks a review ----
import importlib  # noqa: E402
import json  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

import vcg  # noqa: E402

NL = chr(10)
FILES = {
    "src/utils.ts": NL.join([
        "export const unsafeObjectProperties = new Set(['__proto__', 'prototype', 'constructor']);",
        "export function isSafeObjectProperty(p: string) { return !unsafeObjectProperties.has(p); }", ""]),
    "src/expression-sandboxing.ts": NL.join([
        "import { isSafeObjectProperty } from './utils';",
        "export class PrototypeSanitizer { visit(n: any) { if (!isSafeObjectProperty(n.name)) throw new Error('blocked'); } }", ""]),
    "src/expression.ts": NL.join([
        "import { PrototypeSanitizer } from './expression-sandboxing';",
        "export function evaluate(expr: string, data: any) { new PrototypeSanitizer().visit(expr); return data[expr]; }", ""]),
    "src/unrelated.ts": "export function add(a: number, b: number) { return a + b; }" + NL,
    "py/guards.py": NL.join(["BLOCKED_ATTRS = {'__class__', '__globals__'}", "", "def is_safe_attr(name):",
                             "    return name not in BLOCKED_ATTRS", ""]),
    "py/render.py": NL.join(["from .guards import is_safe_attr", "", "def render(obj, name):",
                             "    return getattr(obj, name) if is_safe_attr(name) else None", ""]),
    "node_modules/evil/index.js": "export const blocklistEverything = new Set(['x']);" + NL,
}
with tempfile.TemporaryDirectory() as d:
    for rel, body in FILES.items():
        f = Path(d) / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
    g = vcg.build(d)
    check("the checked-out repo is indexed, vendored directories are not", g is not None and g.files_indexed == 6)
    sub = g.subgraph("src/expression.ts")
    check("a guard chain is followed ACROSS files (expression -> PrototypeSanitizer -> isSafeObjectProperty)",
          any("PrototypeSanitizer" in x for x in sub["guards"]) and any("isSafeObjectProperty" in x for x in sub["guards"]))
    check("...down to the blocklist those guards enforce, with its values",
          sorted(sub["blocklists"].get("unsafeObjectProperties", [])) == ["__proto__", "constructor", "prototype"])
    check("a file with no guards gets no context",
          g.subgraph("src/unrelated.ts") == {"file": "src/unrelated.ts", "guards": [], "blocklists": {}})
    psub = g.subgraph("py/render.py")
    check("Python relative imports and set-literal blocklists are understood too",
          any("is_safe_attr" in x for x in psub["guards"]) and "__globals__" in psub["blocklists"].get("BLOCKED_ATTRS", []))
    # What actually goes on the wire: record every request the Action makes, answer like the gate would.
    seen = []
    real_open = gate._open

    class _Resp:
        def __init__(self, obj): self._b = json.dumps(obj).encode()
        def read(self): return self._b

    def recorder(req, *a, **k):
        body = json.loads(req.data.decode())
        seen.append(body)
        if body["method"] == "tools/call":
            return _Resp({"jsonrpc": "2.0", "id": body["id"], "result": {"content": [{"type": "text", "text": json.dumps({"valid": True, "score": 90})}]}})
        return _Resp({"jsonrpc": "2.0", "id": body["id"], "result": {}})

    gate._open = recorder
    try:
        gate.mcp_validate("x = 1", "typescript", rel="src/expression.ts", graph=g)
        guarded_ctx = [b for b in seen if b["method"] == "tools/call"][-1]["params"]["arguments"]["context"]
        seen.clear()
        gate.mcp_validate("x = 1", "typescript", rel="src/unrelated.ts", graph=g)
        plain_ctx = [b for b in seen if b["method"] == "tools/call"][-1]["params"]["arguments"]["context"]
        seen.clear()
        gate.mcp_validate("x = 1", "typescript")
        legacy_ctx = [b for b in seen if b["method"] == "tools/call"][-1]["params"]["arguments"]["context"]
    finally:
        gate._open = real_open
    sg = guarded_ctx.get("security_graph", {})
    check("the guard graph is SENT to the gate for a guarded file, alongside the existing per-file taint facts",
          "unsafeObjectProperties" in sg.get("blocklists", {}) and "injection_reachable" in sg)
    check("an unguarded file's request is unchanged (no empty graph noise)",
          "blocklists" not in plain_ctx.get("security_graph", {}))
    check("callers that pass no graph behave exactly as before", legacy_ctx == plain_ctx)
    check("the graph never adds a 'taint' key — nothing can be RAISED from it, only suppressed", "taint" not in sg)

# A wrong edge could SUPPRESS a real finding, so ambiguity must link to nothing.
AMBIG = {
    "a/safe.ts": NL.join(["export const blockedProps = new Set(['__proto__', 'constructor', 'prototype']);",
                          "export function sanitizeKey(k: string) { return !blockedProps.has(k); }", ""]),
    "b/other.ts": NL.join(["export function sanitizeKey(k: string) { return k.trim(); }   // same NAME, enforces nothing", ""]),
    "app/uses_pkg.ts": NL.join(["import { sanitizeKey } from '@acme/shared';   // bare package import: which sanitizeKey?",
                                "export function get(o: any, k: string) { return sanitizeKey(k) ? o[k] : undefined; }", ""]),
    "app/uses_rel.ts": NL.join(["import { sanitizeKey } from '../a/safe';      // names its module: unambiguous",
                                "export function get(o: any, k: string) { return sanitizeKey(k) ? o[k] : undefined; }", ""]),
    # guard reached THROUGH an ordinary module that is not itself a guard
    "svc/evaluator.ts": NL.join(["import { sanitizeKey } from '../a/safe';",
                                 "export function evaluate(o: any, k: string) { return sanitizeKey(k) ? o[k] : undefined; }", ""]),
    "svc/expression.ts": NL.join(["import { evaluate } from './evaluator';",
                                  "export function run(o: any, k: string) { return evaluate(o, k); }", ""]),
}
with tempfile.TemporaryDirectory() as d:
    for rel, body in AMBIG.items():
        f = Path(d) / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
    g2 = vcg.build(d)
    check("an AMBIGUOUS guard name (defined in two modules, imported by bare package) links to NOTHING",
          g2.subgraph("app/uses_pkg.ts") == {"file": "app/uses_pkg.ts", "guards": [], "blocklists": {}})
    rel_sub = g2.subgraph("app/uses_rel.ts")
    check("...while an import that names its module links to exactly that module's guard",
          rel_sub["guards"] == ["a/safe#sanitizeKey"] and "blockedProps" in rel_sub["blocklists"])
    via = g2.subgraph("svc/expression.ts")
    check("a guard reached THROUGH an ordinary intermediate module is found (expression -> evaluator -> sanitizeKey)",
          via["guards"] == ["a/safe#sanitizeKey"] and "blockedProps" in via["blocklists"])
hinted = "BLOCKED_ATTRS: frozenset[str] = frozenset({" + NL + "    '__class__'," + NL + "    '__globals__'," + NL + "})" + NL
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "g.py").write_text(hinted + NL + "def is_safe_attr(n):" + NL + "    return n not in BLOCKED_ATTRS" + NL, encoding="utf-8")
    (Path(d) / "use.py").write_text("from g import is_safe_attr" + NL, encoding="utf-8")
    check("type-hinted, multi-line Python blocklists with trailing commas are read",
          sorted(vcg.build(d).subgraph("use.py")["blocklists"].get("BLOCKED_ATTRS", [])) == ["__class__", "__globals__"])
cyc = {"x.ts": "import { b } from './y';" + NL + "export const a = 1;" + NL, "y.ts": "import { a } from './x';" + NL + "export const b = 2;" + NL}
with tempfile.TemporaryDirectory() as d:
    for rel, body in cyc.items():
        (Path(d) / rel).write_text(body, encoding="utf-8")
    check("import cycles terminate", vcg.build(d).subgraph("x.ts") == {"file": "x.ts", "guards": [], "blocklists": {}})
check("missing workspace / unreadable input never raises and yields no graph",
      vcg.build("") is None and vcg.build("/definitely/not/a/real/path") is None)
os.environ["CROSS_FILE"] = "off"
try:
    check("cross-file: off is respected", importlib.reload(gate).build_context_graph() is None)
finally:
    os.environ.pop("CROSS_FILE", None)
    importlib.reload(gate)

print("\nGATE ACTION CONTRACT: " + ("FAILED %d" % len(fails) if fails else "PASSED"))
sys.exit(1 if fails else 0)
