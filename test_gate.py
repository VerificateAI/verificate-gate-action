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


posted = []
mcp_kwargs = []


def run(mode, files, verdicts, *, list_error=None, crash=False, max_files=25, via_entry=False, spy=None,
        live_head=None):
    """Run the gate once. verdicts maps filename -> verdict dict, or an Exception to raise."""
    gate.FAIL_ON, gate.MAX_FILES = mode, max_files
    reviewed = []

    def gh_all(path):
        if list_error:
            raise list_error
        return [dict(f) for f in files]

    def gh(path, method="GET", data=None):
        if spy is not None:
            spy.append(path)
        if "/contents/.verificate/" in path:
            raise RuntimeError("no rebuttals")
        if path.rstrip("/").split("/")[-2:-1] == ["pulls"]:  # GET /repos/o/r/pulls/{n}
            with open(_event.name, encoding="utf-8") as fh:
                ev_head = ((json.load(fh).get("pull_request") or {}).get("head") or {}).get("sha")
            return {"head": {"sha": ev_head if live_head is None else live_head}}
        return {"encoding": "base64", "content": base64.b64encode(b"x = 1\n").decode()}

    def mcp(code, lang, rebuttal="", **kw):
        name = reviewed_names[len(reviewed)]
        reviewed.append(name)
        mcp_kwargs.append(kw)
        v = verdicts.get(name, approved)
        if isinstance(v, Exception):
            raise v
        return gate._not_a_verdict(v) or v

    reviewed_names = [f["filename"] for f in gate.to_review(files, mode)
                      if not (mode == "strict" and gate.file_ext(f["filename"]) in gate.BINARY_EXEC_EXT)]
    def comment(pr, body):
        posted.append(body)
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
# revision 2: encoding, binaries, config parsing
b64 = lambda raw: {"encoding": "base64", "content": base64.b64encode(raw).decode()}
utf16 = "SELECT 1;".encode("utf-16")
try:
    gate.read_file(b64(utf16), "strict")
    check("strict: a UTF-16 file is unreviewable, never reviewed as replacement characters", False)
except ValueError:
    check("strict: a UTF-16 file is unreviewable, never reviewed as replacement characters", True)
try:
    gate.read_file(b64(b"\x7fELF\x00\x01"), "strict")
    check("strict: NUL-containing content is unreviewable", False)
except ValueError:
    check("strict: NUL-containing content is unreviewable", True)
check("strict: a UTF-8 BOM is accepted", gate.read_file(b64(b"\xef\xbb\xbfx = 1\n"), "strict") == "x = 1\n")
check("reject: decoding stays lenient (unchanged)", "�" in gate.read_file(b64(b"\xff\xfe"), "reject"))
rc, reviewed = run("strict", [{"filename": "lib/native.so", "status": "added"}], {})
check("strict: a compiled binary blocks without being sent for review", rc == 1 and reviewed == [])
rc, reviewed = run("strict", [{"filename": "payload.tgz", "status": "added"}, {"filename": "bundle.zip", "status": "added"}], {})
check("strict: archives block without being sent for review", rc == 1 and reviewed == [])
check("parse_fail_on: typo falls back to reject with a warning", gate.parse_fail_on("strct")[0] == "reject" and gate.parse_fail_on("strct")[1])
check("parse_fail_on: ' Strict ' is strict", gate.parse_fail_on(" Strict ") == ("strict", ""))
check("parse_max_files: 500 clamps to 300 with a warning", gate.parse_max_files("500")[0] == 300 and gate.parse_max_files("500")[1])
check("parse_max_files: junk falls back to 25 with a warning", gate.parse_max_files("lots")[0] == 25 and gate.parse_max_files("lots")[1])
check("parse_max_files: 40 is accepted silently", gate.parse_max_files("40") == (40, ""))
check("importing gate made no OIDC request", gate.net._OIDC_CACHE == [])


# revision 3: non-PR events, rebuttal source, malformed responses, cell, Retry-After
def set_event(ev):
    with open(_event.name, "w", encoding="utf-8") as fh:
        json.dump(ev, fh)


set_event({"ref": "refs/heads/main"})
rc, _ = run("strict", one, {})
check("strict: a non-pull_request event fails the check", rc == 1)
rc, _ = run("reject", one, {})
check("reject: a non-pull_request event passes (unchanged)", rc == 0)

set_event({"pull_request": {"number": 7, "head": {"sha": "HEADSHA"}, "base": {"sha": "BASESHA"}}})
seen = []


def run_capturing(mode):
    return run(mode, one, {}, spy=seen)


seen.clear(); run_capturing("strict")
rb = [p for p in seen if "rebuttals.md" in p]
check("strict: rebuttals are read from the base commit, never the PR head", rb == ["/repos/example/repo/contents/.verificate/rebuttals.md?ref=BASESHA"])
check("strict: the reviewed code is still read from the PR head", any(p.endswith("a.py?ref=HEADSHA") for p in seen))
seen.clear(); run_capturing("reject")
check("reject: rebuttals still come from the PR head (unchanged)", [p for p in seen if "rebuttals.md" in p] == ["/repos/example/repo/contents/.verificate/rebuttals.md?ref=HEADSHA"])

two = [{"filename": "bad.py", "status": "modified"}, {"filename": "good.py", "status": "modified"}]
rc, reviewed = run("strict", two, {"bad.py": {"valid": True, "protection": "oops"}})
check("strict: a malformed response blocks and the remaining files are still reviewed", rc == 1 and reviewed == ["bad.py", "good.py"])
rc, reviewed = run("reject", two, {"bad.py": {"valid": True, "protection": None}})
check("reject: a malformed response no longer aborts the run", rc == 0 and reviewed == ["bad.py", "good.py"])

check("cell never ends in a lone backslash after truncation", not gate.cell("a" * 179 + "|tail").endswith("\\"))

import urllib.error  # noqa: E402
calls = []


def _urlopen_date(req, timeout):
    calls.append(1)
    if len(calls) == 1:
        raise urllib.error.HTTPError("u", 429, "slow", {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, None)
    return "ok"


gate.net._urlopen, _sleep = _urlopen_date, gate.net.time.sleep
gate.net.time.sleep = lambda s: None
try:
    out = gate.net._open(object(), 5, tries=2)
    check("an HTTP-date Retry-After waits and retries instead of crashing", out == "ok" and len(calls) == 2)
except ValueError:
    check("an HTTP-date Retry-After waits and retries instead of crashing", False)
finally:
    gate.net.time.sleep = _sleep

# revision 4: response shapes, labelling, taint loading, Retry-After range, MCP body shape
rc, reviewed = run("strict", two, {"bad.py": {"valid": True, "issues": "not a list", "protection": {"vetoed": False, "vetoed_by": [1]}}})
check("strict: non-list issues are normalised, the file is approved and the run continues", rc == 0 and reviewed == ["bad.py", "good.py"])
rc, reviewed = run("reject", two, {"bad.py": {"valid": False, "fix_plan": "x", "suggestions": 3, "protection": {"vetoed": True, "vetoed_by": "gate"}}})
check("reject: malformed fix_plan/suggestions/vetoed_by do not abort; the veto still blocks", rc == 1 and reviewed == ["bad.py", "good.py"])
check("normalize_response rejects a non-dict", gate.normalize_response("x") is None and gate.normalize_response({"valid": True, "protection": 5}) is None)

rc, _ = run("strict", one, {"a.py": {"_unavailable": True, "text": "upstream 502"}})
check("strict: a response with no verdict blocks", rc == 1)
posted.clear()
rc, _ = run("reject", one, {"a.py": {"_unavailable": True, "text": "upstream 502"}})
check("an untyped unavailable response is not labelled as quota exhaustion",
      rc == 0 and posted and "free trial" not in posted[-1] and "gate returned no verdict" in posted[-1])

sys.modules["taint"] = type(sys)("taint")  # a planted module must never be the one used
check("taint is loaded from the action's own file, not a module named 'taint' on sys.path",
      os.path.abspath(gate.net._load_taint().__file__) == os.path.join(os.path.dirname(os.path.abspath(gate.__file__)), "taint.py"))
del sys.modules["taint"]

calls.clear()


def _urlopen_neg(req, timeout):
    calls.append(1)
    if len(calls) == 1:
        raise urllib.error.HTTPError("u", 429, "slow", {"Retry-After": "-5"}, None)
    return "ok"


slept = []
gate.net._urlopen, gate.net.time.sleep = _urlopen_neg, lambda s: slept.append(s)
try:
    out = gate.net._open(object(), 5, tries=2)
    check("a negative Retry-After backs off a sane positive time and retries", out == "ok" and slept and slept[0] >= 30)
except ValueError:
    check("a negative Retry-After backs off a sane positive time and retries", False)
finally:
    gate.net.time.sleep = _sleep


class _Resp:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=-1): return self.body


import importlib  # noqa: E402
g2 = importlib.reload(gate.net)
g2._OIDC_CACHE.append("")
g2._open = lambda req, timeout, tries=3, label="": _Resp(b'{"jsonrpc":"2.0","id":2,"result":null}')
check("mcp_validate: a null JSON-RPC result is 'unavailable', never an AttributeError", g2.mcp_validate("x=1", "python").get("_unavailable") is True)
g2._open = lambda req, timeout, tries=3, label="": _Resp(b"x" * (g2.MCP_MAX_RESPONSE + 1))
try:
    g2.mcp_validate("x=1", "python")
    check("mcp_validate: an oversized response is refused", False)
except ValueError:
    check("mcp_validate: an oversized response is refused", True)

# revision 5: agent instructions, head pinning, reachability hint
sent = []
g2._open = lambda req, timeout, tries=3, label="": (sent.append(json.loads(req.data)), _Resp(b'{"result":null}'))[1]
g2.mcp_validate("os.system(x)", "python", reachability_hint=False)
call = [s for s in sent if s.get("method") == "tools/call"][-1]["params"]["arguments"]
check("mcp_validate: reachability_hint=False sends no security_graph", "security_graph" not in call["context"])
g2.mcp_validate("# guide", "text", validation_type="documentation")
call = [s for s in sent if s.get("method") == "tools/call"][-1]["params"]["arguments"]
check("mcp_validate: validation_type is forwarded", call["validation_type"] == "documentation")

for name in ("AGENTS.md", "docs/CLAUDE.md", ".github/copilot-instructions.md", ".cursorrules",
             ".claude/commands/deploy.md", ".github/instructions/py.instructions.md", ".verificate/rebuttals.md"):
    check(f"strict: agent instructions {name} are reviewed", gate.is_code(name, "strict"))
check("agent-instruction Markdown is reviewed as documentation", gate.review_type("AGENTS.md") == "documentation")
check("ordinary Markdown is still exempt in strict", not gate.is_code("docs/guide.md", "strict"))
check("code under .claude/ is reviewed as code", gate.review_type(".claude/hooks/pre.py") == "code_generation")

set_event({"pull_request": {"number": 7, "head": {"sha": "HEADSHA"}, "base": {"sha": "BASESHA"}}})
rc, reviewed = run("strict", one, {}, live_head="NEWERSHA")
check("strict: a PR head that moved since the event blocks without reviewing", rc == 1 and reviewed == [])
rc, _ = run("strict", one, {})
check("strict: a matching head passes", rc == 0)
rc, _ = run("reject", one, {}, live_head="NEWERSHA")
check("reject: head pinning is strict-only (unchanged)", rc == 0)
mcp_kwargs.clear()
run("strict", [{"filename": "AGENTS.md", "status": "modified"}, {"filename": "a.py", "status": "modified"}], {})
check("strict: main sends no reachability hint and types agent docs as documentation",
      [k.get("reachability_hint") for k in mcp_kwargs] == [False, False]
      and [k.get("validation_type") for k in mcp_kwargs] == ["documentation", "code_generation"])
mcp_kwargs.clear()
run("reject", one, {})
check("reject: main keeps the reachability hint (unchanged)", [k.get("reachability_hint") for k in mcp_kwargs] == [True])
os.unlink(_event.name)

print("\nGATE ACTION CONTRACT: " + ("FAILED %d" % len(fails) if fails else "PASSED"))
sys.exit(1 if fails else 0)
