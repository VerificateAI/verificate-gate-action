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


# ---- fail-on modes, driven through main() and entry() with the network stubbed ----
import base64  # noqa: E402
import json  # noqa: E402
import tempfile  # noqa: E402

_event = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
json.dump({"pull_request": {"number": 7, "head": {"sha": "abc"}}}, _event)
_event.close()
os.environ["GITHUB_EVENT_PATH"] = _event.name
os.environ.pop("GITHUB_OUTPUT", None)


def run(mode, files, verdicts, *, list_error=None, crash=False, max_files=25, via_entry=False):
    """Run the gate once. verdicts maps filename -> verdict dict, or an Exception to raise."""
    gate.FAIL_ON, gate.MAX_FILES = mode, max_files
    reviewed = []

    def gh_all(path):
        if list_error:
            raise list_error
        return [dict(f) for f in files]

    def gh(path, method="GET", data=None):
        if "/contents/.verificate/" in path:
            raise RuntimeError("no rebuttals")
        return {"encoding": "base64", "content": base64.b64encode(b"x = 1\n").decode()}

    def mcp(code, lang, rebuttal=""):
        name = reviewed_names[len(reviewed)]
        reviewed.append(name)
        v = verdicts.get(name, approved)
        if isinstance(v, Exception):
            raise v
        return gate._not_a_verdict(v) or v

    reviewed_names = [f["filename"] for f in gate.to_review(files, mode)]
    def comment(pr, body):
        if crash:  # raised outside every per-file handler, so only the global handler sees it
            raise KeyError("unexpected")

    gate.gh_all, gate.gh, gate.mcp_validate, gate.upsert_comment = gh_all, gh, mcp, comment
    return (gate.entry() if via_entry else gate.main()), reviewed


one = [{"filename": "a.py", "status": "modified"}]

# test_strict_blocks_on_error
rc, _ = run("strict", one, {"a.py": ConnectionError("mcp down")})
check("strict: an MCP connection error fails the check", rc == 1)
rc, _ = run("reject", one, {"a.py": ConnectionError("mcp down")})
check("reject: an MCP connection error still passes (unchanged)", rc == 0)
rc, _ = run("strict", one, {}, list_error=ConnectionError("github down"))
check("strict: a failed file listing fails the check", rc == 1)
rc, _ = run("reject", one, {}, list_error=ConnectionError("github down"))
check("reject: a failed file listing still passes (unchanged)", rc == 0)

# test_strict_blocks_on_skipped
for label, v in (("review did not complete", unreviewed), ("API key not accepted", badkey), ("free limit reached", quota)):
    rc, _ = run("strict", one, {"a.py": v})
    check(f"strict: '{label}' fails the check", rc == 1)
    rc, _ = run("reject", one, {"a.py": v})
    check(f"reject: '{label}' still passes (unchanged)", rc == 0)
rc, _ = run("strict", one, {"a.py": {"score": 90}})
check("strict: a response with no verdict is not an approval", rc == 1)
big = {"encoding": "none", "content": ""}
try:
    gate.read_file(big)
    check("a file the contents API cannot return is an error, never an empty approval", False)
except ValueError:
    check("a file the contents API cannot return is an error, never an empty approval", True)

# test_strict_blocks_on_cap
many = [{"filename": f"m{i}.py", "status": "modified"} for i in range(4)]
rc, reviewed = run("strict", many, {}, max_files=3)
check("strict: changed code files above max-files fail the check", rc == 1 and len(reviewed) == 3)
rc, _ = run("reject", many, {}, max_files=3)
check("reject: files above max-files still pass (unchanged)", rc == 0)
rc, _ = run("strict", [{"filename": f"d{i}.md", "status": "modified"} for i in range(gate.GH_FILES_LIMIT)], {})
check("strict: a file list at GitHub's 3000-file maximum fails the check", rc == 1)

# test_strict_blocks_on_unexpected_exception
rc, _ = run("strict", one, {}, crash=True, via_entry=True)
check("strict: the global handler fails the check on an unexpected exception", rc == 1)
rc, _ = run("reject", one, {}, crash=True, via_entry=True)
check("reject: the global handler still fails open (unchanged)", rc == 0)

# test_strict_reviews_every_code_file
for name in ("a.py", "q.sql", "e.cpp", "e.h", "w.ts", "w.tsx", "w.js", "w.jsx", "s.css", "p.html",
             "db/migrations/0042_add_index.up.sql", "db/migrations/0042_add_index.down.sql",
             "Makefile", "Dockerfile", "conf.yml", "x.json", "weird.zzz", "dir.v2/noext"):
    check(f"strict: {name} is code", gate.is_code(name, "strict"))
for name in ("README.md", "docs/guide.rst", "notes.txt", "logo.png", "font.woff2"):
    check(f"strict: {name} is not code", not gate.is_code(name, "strict"))
check("reject keeps the published allow-list: weird.zzz is skipped", not gate.is_code("weird.zzz", "reject"))
check("file_ext uses the base name, not a dotted directory", gate.file_ext("dir.v2/noext") == "" and gate.file_ext("A.PY") == ".py")
renamed = [{"filename": "moved.py", "status": "renamed"}, {"filename": "gone.py", "status": "removed"}]
check("strict reviews renamed files and skips removed ones", [f["filename"] for f in gate.to_review(renamed, "strict")] == ["moved.py"])

# approvals and rejections
rc, _ = run("strict", many, {})
check("strict: every file reviewed and approved passes", rc == 0)
rc, _ = run("strict", one, {"a.py": rejected})
check("strict: a model rejection fails the check", rc == 1)
rc, _ = run("reject", one, {"a.py": veto})
check("reject: a veto fails the check", rc == 1)
rc, _ = run("off", one, {"a.py": veto})
check("off: a veto only comments", rc == 0)
os.unlink(_event.name)

print("\nGATE ACTION CONTRACT: " + ("FAILED %d" % len(fails) if fails else "PASSED"))
sys.exit(1 if fails else 0)
