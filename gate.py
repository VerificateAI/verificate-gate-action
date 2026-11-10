"""Verificate Gate — GitHub Action entrypoint.

Runs the Verificate merge gate on the changed code files of a pull request, posts an inline
summary comment, and exits non-zero if the gate VETOES (so it can be a required status check
that blocks merge). Modes (FAIL_ON):
  reject (default) - fail CLOSED only on a real veto or rejection; fail OPEN on any infrastructure
                     error (MCP unreachable, timeouts, quota) so gate outages never block merges.
  off              - comment only, never fail the check.
  strict           - fail CLOSED unless every changed file was reviewed and approved: gate errors,
                     skipped reviews, files over max-files, an incomplete file list and unexpected
                     exceptions all fail the check. Files with an unrecognised extension are
                     reviewed, never silently skipped. For required checks that must not fail open.

Env: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH, optional VERIFICATE_MCP_URL,
VERIFICATE_API_KEY, FAIL_ON (reject|off|strict), MAX_FILES.
"""
from __future__ import annotations
import base64, html, json, os, random, ssl, sys, time, urllib.parse, urllib.request, urllib.error

COMMENT_MAX = 60000  # keep under GitHub's 65536-char comment limit

def _s(v):
    """Coerce a finding (str or dict) to a clean one-line string."""
    if isinstance(v, dict):
        v = v.get("description") or v.get("message") or v.get("step") or json.dumps(v)
    return " ".join(str(v).split())

def cell(v):
    """Safe for a markdown table cell: no pipes or newlines break the table."""
    # Truncate BEFORE escaping so a cut can never leave a lone trailing backslash.
    return _s(v)[:180].replace("|", "\\|")

def md(v):
    """Safe for markdown/HTML body text: escape angle brackets so AI text can't
    close our <details> block or inject HTML. Slice BEFORE escaping so we never
    split an HTML entity (e.g. '&lt;')."""
    return html.escape(_s(v)[:220], quote=False)

REPO = os.environ.get("GITHUB_REPOSITORY", "")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
# GitHub Actions OIDC: present only if the caller's workflow grants `permissions: id-token: write`.
OIDC_REQ_URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
OIDC_REQ_TOKEN = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
MCP_URL = os.environ.get("VERIFICATE_MCP_URL", "https://mcp.verificate.ai/mcp")
VKEY = os.environ.get("VERIFICATE_API_KEY", "").strip()
FAIL_MODES = ("reject", "off", "strict")


def parse_fail_on(raw):
    """(mode, warning or ''). A typo must never silently turn a blocking check into a
    comment-only one, so an unrecognised value falls back to 'reject'."""
    mode = (raw or "").strip().lower() or "reject"
    if mode not in FAIL_MODES:
        return "reject", f"fail-on '{mode}' is not one of {', '.join(FAIL_MODES)}; using 'reject'."
    return mode, ""


def parse_max_files(raw):
    """(n, warning or ''), n clamped to 1..300; a clamp or a bad value is reported, never silent."""
    try:
        n = int(raw if raw not in (None, "") else "25")
    except ValueError:
        return 25, f"max-files '{raw}' is not an integer; using 25."
    if n < 1 or n > 300:
        c = max(1, min(n, 300))
        return c, f"max-files {n} is outside 1-300; using {c}."
    return n, ""


# Pure parsing at import; the warnings are printed by main(), not as an import side effect.
FAIL_ON, _FAIL_ON_WARNING = parse_fail_on(os.environ.get("FAIL_ON", "reject"))
MAX_FILES, _MAX_FILES_WARNING = parse_max_files(os.environ.get("MAX_FILES", "25"))
MARK = "<!-- verificate-gate -->"
CODE_EXT = {".py",".js",".ts",".tsx",".jsx",".go",".java",".rb",".rs",".c",".cc",".cpp",
            ".cs",".php",".sql",".sh",".kt",".swift",".scala",
            ".h",".hh",".hpp",".cxx",".css",".html",".htm",".mjs",".cjs",".ps1",".psql"}
# Strict mode reviews every changed file EXCEPT these: prose and binary assets that carry no
# executable behaviour. Everything else, including an unknown or missing extension, is code.
NON_CODE_EXT = {".md",".markdown",".rst",".txt",".png",".jpg",".jpeg",".gif",".webp",".ico",
                ".bmp",".pdf",".woff",".woff2",".ttf",".otf",".eot",".mp4",".mov",".mp3",".wav",
                }
# Compiled binaries and archives cannot be reviewed as text, and either can carry executable
# code. Strict mode does not skip them (that would pass bytes nobody read); it reports them as
# unreviewable and blocks.
BINARY_EXEC_EXT = {".pyc",".pyo",".so",".dll",".dylib",".exe",".jar",".class",".bin",".o",
                   ".a",".lib",".wasm",".whl",".node",
                   ".zip",".gz",".tgz",".7z",".xz",".bz2",".tar",".rar",".war"}
LANG = {".py":"python",".js":"javascript",".ts":"typescript",".tsx":"typescript",".jsx":"javascript",
        ".mjs":"javascript",".cjs":"javascript",".go":"go",".java":"java",".rb":"ruby",".rs":"rust",
        ".c":"c",".h":"cpp",".hh":"cpp",".hpp":"cpp",".cc":"cpp",".cxx":"cpp",".cpp":"cpp",
        ".cs":"csharp",".php":"php",".sql":"sql",".psql":"sql",".sh":"bash",".ps1":"powershell",
        ".css":"css",".html":"html",".htm":"html"}
# The GitHub "list pull request files" API returns at most 3000 files; at that size the list
# may be incomplete, so strict mode treats it as unreviewed.
GH_FILES_LIMIT = 3000
# File statuses whose head content is reviewed. "removed" has nothing to read.
REVIEW_STATUS = {"added", "modified"}
STRICT_REVIEW_STATUS = {"added", "modified", "renamed", "copied", "changed"}
_ctx = ssl.create_default_context()


def file_ext(filename):
    """Lower-cased extension of the file's base name ('' if none). The previous
    '"." + rsplit(".")' turned 'Makefile' into '.Makefile' and 'a.b/c' into '.b/c'."""
    return os.path.splitext(filename.rsplit("/", 1)[-1])[1].lower()


def is_code(filename, mode):
    """Whether a changed file must be reviewed. reject/off keep the published allow-list;
    strict reviews everything that is not explicitly prose or a binary asset."""
    ext = file_ext(filename)
    if mode == "strict":
        return ext not in NON_CODE_EXT
    return ext in CODE_EXT


def to_review(files, mode):
    statuses = STRICT_REVIEW_STATUS if mode == "strict" else REVIEW_STATUS
    return [f for f in files if f.get("status") in statuses and is_code(f.get("filename", ""), mode)]


def exit_code(mode, vetoed, rejected, errors, dropped, incomplete_list):
    """The one place the check's pass/fail is decided."""
    if mode == "off":
        return 0
    if vetoed or rejected:
        return 1
    if mode == "strict" and (errors or dropped or incomplete_list):
        return 1
    return 0


def read_file(meta, mode="reject"):
    """Decode a contents-API object. Files over 1 MB come back with encoding 'none' and no
    content; reviewing that as an empty file would be a false approval, so it is an error.
    In strict mode the bytes must be valid UTF-8 (a BOM is allowed): a UTF-16 or binary file
    decoded with 'replace' would be reviewed as replacement characters, not as the committed
    code, so it raises instead and the file counts as unreviewed."""
    if not isinstance(meta, dict) or meta.get("encoding") != "base64" or "content" not in meta:
        raise ValueError("file content not available from the contents API (too large or not a file)")
    raw = base64.b64decode(meta["content"])
    if mode == "strict":
        if b"\x00" in raw:
            raise ValueError("binary content cannot be reviewed as text")
        return raw.decode("utf-8-sig")  # UnicodeDecodeError is a ValueError
    return raw.decode("utf-8", "replace")

_OIDC_CACHE = []


def oidc_token():
    """The OIDC token, fetched once on first use (never at import)."""
    if not _OIDC_CACHE:
        _OIDC_CACHE.append(github_oidc_token())
    return _OIDC_CACHE[0]

def github_oidc_token():
    """Fetch a GitHub Actions OIDC JWT (audience=verificate-gate) so the gate's free tier
    can meter per-repository instead of per shared-runner IP. Returns '' if the workflow
    didn't grant `permissions: id-token: write` — the gate then falls back to the IP tier."""
    if not OIDC_REQ_URL or not OIDC_REQ_TOKEN:
        return ""
    try:
        req = urllib.request.Request(OIDC_REQ_URL + "&audience=verificate-gate",
            headers={"Authorization": f"Bearer {OIDC_REQ_TOKEN}", "User-Agent": "verificate-gate"})
        with urllib.request.urlopen(req, context=_ctx, timeout=15) as r:
            return (json.loads(r.read() or b"{}").get("value") or "").strip()
    except Exception as e:
        print(f"::warning::could not obtain OIDC token ({type(e).__name__}); using IP free tier.")
        return ""

def _open(req, timeout, tries=3, label="request"):
    """Transient-fault retry: 5xx / network blips get backoff; 4xx raises at once, except
    secondary rate limits (403/429 with Retry-After), which wait the header's duration."""
    last = None
    for attempt in range(1, tries + 1):
        try:
            return _urlopen(req, timeout)
        except urllib.error.HTTPError as e:
            last = e
            retry_after = e.headers.get("Retry-After") if e.headers else None
            try:
                ra_secs = float(retry_after) if retry_after else None
            except ValueError:  # RFC 9110 also allows an HTTP-date; back off a fixed amount
                ra_secs = 30.0
            if ra_secs is not None and not (0 <= ra_secs < float("inf")):  # negative, NaN, inf
                ra_secs = 30.0
            if e.code in (403, 429) and ra_secs is not None and attempt < tries:
                wait = min(ra_secs, 60) + random.uniform(0, 1)
                print(f"::warning::{label} rate-limited; waiting {wait:.1f}s per Retry-After")
                time.sleep(wait)
                continue
            if e.code in (401, 403, 404, 422, 429) or attempt == tries:
                raise
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError) as e:
            last = e
            if attempt == tries:
                raise
        wait = (2 ** attempt) + random.uniform(0, 1)
        print(f"::warning::{label} failed (attempt {attempt}/{tries}); retrying in {wait:.1f}s")
        time.sleep(wait)
    raise last

def _urlopen(req, timeout):
    return urllib.request.urlopen(req, context=_ctx, timeout=timeout)

def gh(path, method="GET", data=None):
    req = urllib.request.Request("https://api.github.com" + path, method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
                 "User-Agent": "verificate-gate"})
    if data is not None:
        req.data = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    with _open(req, 30, label=f"github {method} {path[:60]}") as r:
        return json.loads(r.read() or b"{}")

def gh_all(path):
    """Follow per_page pagination so large PRs are fully enumerated."""
    out, page = [], 1
    while True:
        chunk = gh(("&" if "?" in path else "?").join([path, f"per_page=100&page={page}"]))
        if not isinstance(chunk, list):
            return chunk
        out += chunk
        if len(chunk) < 100:
            return out
        page += 1
        if page > 30:
            return out

def set_output(**kv):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        for k, v in kv.items():
            f.write(f"{k}={str(v).replace(chr(13), ' ').replace(chr(10), ' ')}\n")

MCP_MAX_RESPONSE = 4 * 1024 * 1024  # a verdict is a few KB; cap what a bad upstream can make us buffer


def _load_taint():
    """Load the action's own taint.py by absolute path. A bare 'import taint' could resolve a
    PR-supplied taint.py from the workspace or PYTHONPATH inside a job holding GITHUB_TOKEN."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taint.py")
    spec = importlib.util.spec_from_file_location("verificate_gate_taint", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def mcp_validate(code, lang, rebuttal=""):
    # A rebuttal (from .verificate/rebuttals.md) lets the gate adjudicate a prior finding the
    # agent contests with proof — the gate overturns findings whose methodology it accepts.
    ctx = {"language": lang}
    # Injection-reachability: suppress false "injection/RCE" findings whose sink is fed only by an
    # operator-controlled source (a CLI arg, local config, a trusted literal) rather than untrusted input.
    try:
        taint = _load_taint()
        _t = taint.analyze(code)
        ctx["security_graph"] = {"injection_reachable": _t["injection_reachable"], "taint_flows": _t["flows"]}
    except Exception as e:
        # Optional hint only: the review still runs, just without the reachability graph.
        print(f"::warning::taint analysis skipped ({type(e).__name__}); reviewing without the reachability hint.")
    if rebuttal:
        ctx["rebuttal"] = rebuttal[:6000]
    def rpc(method, params, rid):
        body = json.dumps({"jsonrpc":"2.0","id":rid,"method":method,"params":params}).encode()
        h = {"Content-Type":"application/json","Accept":"application/json, text/event-stream",
             "User-Agent":"verificate-gate/1.0 (+https://verificate.ai)"}
        # Signed OIDC token → the portal meters the free tier per-repository (not per
        # shared runner IP) with the repo identity proven, not merely claimed.
        tok = oidc_token()
        if tok: h["X-Verificate-OIDC"] = tok
        if VKEY: h["Authorization"] = f"Bearer {VKEY}"
        req = urllib.request.Request(MCP_URL, data=body, method="POST", headers=h)
        with _open(req, 120, tries=2, label=f"mcp {method}") as r:
            raw_b = r.read(MCP_MAX_RESPONSE + 1)
        if len(raw_b) > MCP_MAX_RESPONSE:
            raise ValueError(f"gate response exceeds {MCP_MAX_RESPONSE} bytes")
        raw = raw_b.decode("utf-8", "replace")
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"): line = line[5:].strip()
            if line.startswith("{"):
                try: return json.loads(line)
                except json.JSONDecodeError: continue
        return {}
    rpc("initialize", {"protocolVersion":"2024-11-05","capabilities":{},
                       "clientInfo":{"name":"verificate-gate-action","version":"1"}}, 0)
    resp = rpc("tools/call", {"name":"validate_ai_output",
               "arguments":{"ai_output":code,"validation_type":"code_generation","context":ctx}}, 2)
    result = resp.get("result") if isinstance(resp, dict) else None
    parts = result.get("content") if isinstance(result, dict) else None
    parts = parts if isinstance(parts, list) else []
    text = "\n".join(str(p.get("text", "")) for p in parts
                     if isinstance(p, dict) and p.get("type") == "text").strip()
    if text.startswith("{"):
        try:
            obj, _ = json.JSONDecoder().raw_decode(text)  # first JSON object; ignore trailing trial note
            return _not_a_verdict(obj) or obj
        except json.JSONDecodeError:
            pass
    # Not a verdict (e.g. free-tier upsell / trial note) — the gate could not score this.
    return {"_unavailable": True, "text": text[:200]}

def _not_a_verdict(obj):
    """The gate answers quota/key refusals and "could not review" as JSON with valid:false. Those say
    NOTHING about the code, so they must not be read as a rejection: until v1.2.1 an exhausted free
    tier, an expired/invalid key, or a gate-side review timeout marked every file "REJECTED" and
    blocked the merge — the opposite of what the README promises. Returns an _unavailable marker
    (with the reason, so the PR comment can say what to do), or None for a real verdict."""
    if not isinstance(obj, dict):
        return None
    if obj.get("validation_type") == "quota" or obj.get("provider") == "quota-gate":
        reason = str((obj.get("quota") or {}).get("reason") or "free_limit")
        msg = (obj.get("suggestions") or obj.get("issues") or [""])[0]
        return {"_unavailable": True, "kind": "access", "reason": reason, "text": str(msg)[:300]}
    if obj.get("review_unavailable"):
        return {"_unavailable": True, "kind": "review", "reason": "review_unavailable",
                "text": "The gate's model review did not complete for this file (timeout or transient error)."}
    return None


def normalize_response(res):
    """Return the gate response with every field main() reads coerced to its expected shape,
    or None if it is not a response at all. One malformed field must not abort the run."""
    if not isinstance(res, dict):
        return None
    if res.get("_unavailable"):
        return res
    prot, assess = res.get("protection") or {}, res.get("assessment") or {}
    if not isinstance(prot, dict) or not isinstance(assess, dict):
        return None
    lst = lambda v: v if isinstance(v, list) else []
    out = dict(res)
    out["protection"] = dict(prot, vetoed_by=[_s(x) for x in lst(prot.get("vetoed_by"))])
    out["assessment"] = assess
    out["issues"] = lst(res.get("issues"))
    out["fix_plan"] = lst(res.get("fix_plan"))
    out["suggestions"] = lst(res.get("suggestions"))
    return out


def upsert_comment(pr, body):
    try:
        comments = gh(f"/repos/{REPO}/issues/{pr}/comments?per_page=100")
        existing = next((c for c in comments if MARK in (c.get("body") or "")), None)
        if existing:
            gh(f"/repos/{REPO}/issues/comments/{existing['id']}", "PATCH", {"body": body})
        else:
            gh(f"/repos/{REPO}/issues/{pr}/comments", "POST", {"body": body})
    except Exception as e:
        print(f"::warning::could not post comment: {e}")

def main():
    mode = FAIL_ON
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        ev = json.load(fh)
    pr = (ev.get("pull_request") or {}).get("number") or ev.get("number")
    head = ((ev.get("pull_request") or {}).get("head") or {}).get("sha") or ""
    base = ((ev.get("pull_request") or {}).get("base") or {}).get("sha") or ""
    ref_qs = f"?ref={head}" if head else ""
    if not pr:
        if mode == "strict":
            # A required check must not go green on an event that carries no pull request
            # (merge_group, push, ...): nothing was reviewed.
            print("::error::Not a pull_request event; strict mode reviews pull requests only and blocks here.")
            return 1
        print("Not a pull_request event; nothing to gate."); return 0
    for w in (_FAIL_ON_WARNING, _MAX_FILES_WARNING):
        if w:
            print(f"::warning::{w}")
    try:
        files = gh_all(f"/repos/{REPO}/pulls/{pr}/files")
        if not isinstance(files, list):
            raise ValueError("pull request file list is not a list")
    except Exception as e:
        if mode == "strict":
            print(f"::error::could not list files ({type(e).__name__}); strict mode blocks the merge.")
            set_output(verdict="error", files_reviewed=0, files_errored=0, files_dropped=0)
            return 1
        print(f"::warning::could not list files ({e}); failing open."); return 0
    incomplete_list = len(files) >= GH_FILES_LIMIT
    if incomplete_list:
        print(f"::warning::the pull request lists {len(files)} files, GitHub's maximum; the list may be incomplete.")
    eligible = to_review(files, mode)
    targets = eligible[:MAX_FILES]
    dropped = len(eligible) - len(targets)
    if dropped:
        print(f"::warning::Verificate Gate reviewed the first {MAX_FILES} of {len(eligible)} changed code files; "
              f"{dropped} were left unreviewed. Raise max-files to cover the whole PR.")
    if not targets:
        upsert_comment(pr, f"{MARK}\n### ✅ Verificate Gate — no code changes to review.")
        print("No code files changed.")
        return exit_code(mode, False, False, 0, 0, incomplete_list)

    # Appeal channel: if the author (or their agent) contested prior findings with a proof in
    # .verificate/rebuttals.md, feed it to the gate so it can adjudicate and overturn sound rebuttals.
    # In strict mode the rebuttals come from the PR's BASE commit, never its head: the PR being
    # gated must not be able to overrule its own findings. A rebuttal takes effect once it has
    # itself been reviewed and merged.
    rebuttal = ""
    rb_ref = (f"?ref={base}" if base else None) if mode == "strict" else ref_qs
    if rb_ref is None:
        print("::warning::strict mode: no base commit in the event, so no rebuttals are read.")
    else:
        try:
            rb = gh(f"/repos/{REPO}/contents/.verificate/rebuttals.md{rb_ref}")
            rebuttal = base64.b64decode(rb["content"]).decode("utf-8", "replace")
            if rebuttal.strip():
                print("Verificate: rebuttals.md found — the gate will adjudicate contested findings.")
        except urllib.error.HTTPError as e:
            if e.code != 404:  # 404 = no rebuttals file, the normal case
                print(f"::warning::could not read .verificate/rebuttals.md (HTTP {e.code}); reviewing without rebuttals.")
        except Exception as e:
            print(f"::warning::could not read .verificate/rebuttals.md ({type(e).__name__}); reviewing without rebuttals.")

    rows, vetoed_any, rejected_any, errors, capped, fixes = [], False, False, 0, False, []
    for f in targets:
        ext = file_ext(f["filename"])
        if mode == "strict" and ext in BINARY_EXEC_EXT:
            errors += 1
            print(f"::warning::{f['filename']} is a compiled binary and cannot be reviewed; strict mode blocks it.")
            rows.append((f["filename"], "⚠️ binary executable — cannot be reviewed", "")); continue
        try:
            meta = gh(f"/repos/{REPO}/contents/{urllib.parse.quote(f['filename'])}{ref_qs}")
            code = read_file(meta, mode)
            res = mcp_validate(code, LANG.get(ext, "text"), rebuttal=rebuttal)
        except Exception as e:
            errors += 1
            print(f"::warning::Verificate gate error on {f['filename']}: {type(e).__name__}: {str(e)[:160]}")
            rows.append((f["filename"], "⚠️ gate error (skipped)", "")); continue
        res = normalize_response(res)
        if res is None:
            # A malformed response costs this one file, never the remaining reviews.
            errors += 1
            print(f"::warning::malformed gate response for {f['filename']}; treated as unreviewed.")
            rows.append((f["filename"], "⚠️ malformed gate response", "")); continue
        if res.get("_unavailable"):
            errors += 1
            reason = res.get("reason", "")
            if res.get("kind") not in ("review", "access"):
                print(f"::warning::Verificate gate returned no verdict for {f['filename']}: {_s(res.get('text', ''))[:160]}")
                rows.append((f["filename"], "⚠️ skipped — gate returned no verdict", "")); continue
            if res.get("kind") == "review":
                print(f"::warning::Verificate could not review {f['filename']} (gate-side timeout/transient error) — "
                      f"not blocking. Re-run the check; very large files review more reliably when split.")
                rows.append((f["filename"], "⚠️ skipped — review did not complete", "")); continue
            if reason in ("invalid_key", "no_active_subscription"):
                print(f"::warning::Verificate gate refused the VERIFICATE_API_KEY for {f['filename']} ({reason}) — not blocking. "
                      f"Check the secret's value, or get a fresh free key: https://verificate.ai/auth/signup")
                rows.append((f["filename"], "⚠️ skipped — API key not accepted", reason)); continue
            capped = True
            print(f"::warning::Verificate gate unavailable for {f['filename']} — free-tier limit reached. "
                  f"Add a VERIFICATE_API_KEY secret (free, no card: https://verificate.ai/auth/signup) to get your own quota.")
            rows.append((f["filename"], "⚠️ skipped — free limit reached", "")); continue
        prot = res.get("protection", {})
        vetoed = bool(prot.get("vetoed"))
        rejected = vetoed or res.get("valid") is False or str(res.get("assessment",{}).get("verdict","")).lower() in ("reject","rejected")
        score = res.get("score")
        issues = res.get("issues") or []
        if vetoed: vetoed_any = True
        if rejected: rejected_any = True
        status = "❌ REJECTED" if rejected else "✅ approved"
        detail = ("vetoed by " + ", ".join(prot.get("vetoed_by") or [])) if vetoed else (f"score {score}" if score is not None else "")
        if mode == "strict" and not rejected and res.get("valid") is not True:
            # Strict requires a positive approval; a response with no verdict is not one.
            errors += 1
            rows.append((f["filename"], "⚠️ no verdict returned", detail))
            continue
        rows.append((f["filename"], status, detail))
        for iss in issues[:4]:
            rows.append(("　↳", cell(iss), ""))
        # Keep the full remediation for rejected files — this is the "how to fix" guidance,
        # which the review generates but the summary table alone would drop.
        if rejected:
            plan = [s for s in (res.get("fix_plan") or []) if isinstance(s, dict) and s.get("step")]
            steps = [s.get("step") for s in plan]
            fixes.append({"file": f["filename"], "issues": issues[:8],
                          "steps": steps[:8], "plan": plan[:8],
                          "suggestions": (res.get("suggestions") or [])[:6]})

    lines = [MARK, "### 🛡️ Verificate Gate",
             f"Reviewed **{len(targets)}** changed code file(s)"
             + (f" · {errors} skipped (gate error)" if errors else "") + ".", "",
             "| File | Verdict | Detail |", "|---|---|---|"]
    for name, status, detail in rows:
        lines.append(f"| {cell(name)} | {status} | {cell(detail)} |")
    # Per-file remediation — the actionable "how to fix", collapsed so the comment stays tidy.
    # Budget the total length (running counter) so a big PR can't exceed GitHub's comment limit;
    # reserve headroom for the truncation footer.
    truncated = False
    used = sum(len(x) + 1 for x in lines)
    for fx in fixes:
        block = ["", f"<details><summary>🔧 How to fix <code>{md(fx['file'])}</code></summary>", ""]
        if fx["issues"]:
            block.append("**What was caught:**")
            block += [f"- {md(i)}" for i in fx["issues"]]
        guidance = fx["steps"] or fx["suggestions"]
        if guidance:
            block += ["", "**How to fix:**"]
            block += [f"{n}. {md(g)}" for n, g in enumerate(guidance, 1)]
        block += ["", "</details>"]
        blen = sum(len(x) + 1 for x in block)
        if used + blen > COMMENT_MAX - 200:  # reserve 200 chars for the footer
            truncated = True
            break
        lines += block
        used += blen
    if truncated:
        lines += ["", "> _Some fix guidance was omitted to fit GitHub's comment size limit — "
                  "run the gate locally or in your IDE for the full detail._"]

    # ---- Auto-fix prompt: hand the remediation to a coding agent for a zero-effort green commit ----
    # A developer (or the GitHub coding agent / Copilot / Cursor / Claude Code) can act on this to fix
    # exactly the flagged issues and turn the check green — no manual back-to-dev round trip.
    if fixes:
        p = ["You are resolving a pull request that failed the Verificate quality gate. For EACH finding "
             "below, do ONE of two things:",
             "  (A) FIX it — apply exactly the change described, nothing else; do not touch unrelated code; "
             "preserve existing behaviour and performance (a fix that regresses either is not acceptable); or",
             "  (B) OVERRULE it — ONLY if, after investigating, you are confident the finding is a false "
             "positive. Do not change the code. Instead append an entry to `.verificate/rebuttals.md` with: "
             "the file, the finding, and a rigorous methodology PROVING the code is correct (name the "
             "reference pattern, cite the spec/line, or give the exact input showing no failure). The gate "
             "re-reads this on the next run and, like a senior reviewer, overturns findings whose rebuttal "
             "is sound — the check then passes without a code change.",
             "Then commit and push; the gate re-runs automatically.", ""]
        pused = 0
        for fx in fixes:
            seg = [f"File `{fx['file']}`:"]
            if fx["plan"]:
                for i, s in enumerate(fx["plan"], 1):
                    line = f"  {i}. Fix: {_s(s.get('step'))}"
                    if s.get("root_cause"):
                        line += f"  (root cause: {_s(s.get('root_cause'))})"
                    if s.get("risk_if_wrong"):
                        line += f"  DO NOT: {_s(s.get('risk_if_wrong'))}"
                    seg.append(line)
            else:
                for i, g in enumerate((fx["steps"] or fx["suggestions"]), 1):
                    seg.append(f"  {i}. Fix: {_s(g)}")
            seg.append("")
            slen = sum(len(x) + 1 for x in seg)
            if pused + slen > 8000:  # keep the prompt block itself bounded
                p.append("(further files omitted — re-run the gate after these land)")
                break
            p += seg
            pused += slen
        prompt_text = "\n".join(p)
        lines += ["", "### 🤖 Auto-fix this PR (zero-effort green commit)",
                  "Hand this to your coding agent — the GitHub coding agent, Copilot, Cursor or Claude Code "
                  "— or paste it into your editor. It fixes exactly what the gate flagged, preserves "
                  "behaviour, and the check goes green on the next push.", "",
                  "```text", prompt_text, "```"]
    if vetoed_any:
        lines += ["", "**A deterministic reality gate vetoed a change — fix the findings above and push again.** "
                  "A veto is authoritative and cannot be overridden."]
    elif rejected_any:
        lines += ["", "**A change was REJECTED — fix the findings above and push again.** "
                  "The check stays red until every reviewed file passes."]
    else:
        lines += ["", "No blocking findings. " + ("Warnings noted above." if errors else "Changes cleared the gate.")]
    if mode == "strict" and (errors or dropped or incomplete_list):
        lines += ["", "**Strict mode: not every changed file was reviewed and approved, so the check is red.** "
                  "Re-run the check once the gate is reachable, or split the PR so it is within `max-files`."]
    if capped:
        lines += ["", "> ⚠️ **Some files were skipped — the shared free trial on this runner is used up, so the gate couldn't score them.** "
                  + ("Strict mode blocks the merge until they are reviewed. " if mode == "strict" else
                     "The gate failed **open**, so this did **not** block your merge. ") +
                  "To get your own quota (free, no card, 30 days), sign up at "
                  "[verificate.ai/auth/signup](https://verificate.ai/auth/signup) and add the key as a repo secret named "
                  "**`VERIFICATE_API_KEY`** — validations resume on the next push."]
    if dropped:
        lines += ["", f"> ⚠️ **This PR changed {len(eligible)} code files; the gate reviewed the first "
                  f"{MAX_FILES} and left {dropped} unreviewed.** Raise `max-files` to cover the whole PR."]
    lines += ["", "_Verificate — the merge gate for AI-written code. [Why](https://github.com/VerificateAI/verificate-mcp-quickstart/blob/master/COMPARISON.md)_"]
    upsert_comment(pr, "\n".join(lines))

    set_output(
        verdict="vetoed" if vetoed_any else ("rejected" if rejected_any else ("error" if errors else "approved")),
        files_reviewed=len(targets),
        files_errored=errors,
        files_dropped=dropped,
    )

    rc = exit_code(mode, vetoed_any, rejected_any, errors, dropped, incomplete_list)
    if rc and (vetoed_any or rejected_any):
        why = "VETOED by a deterministic reality gate" if vetoed_any else "REJECTED"
        print(f"::error::Verificate Gate: a change was {why} — blocking merge until fixed.")
    elif rc:
        print(f"::error::Verificate Gate (strict): {errors} file(s) not reviewed, {dropped} over max-files"
              + (", file list may be incomplete" if incomplete_list else "") + " — blocking merge.")
    else:
        print("Verificate Gate: passed.")
    return rc


def entry():
    """Process entry point. reject/off fail open on an unexpected error; strict fails closed."""
    try:
        return main()
    except Exception as e:
        if FAIL_ON == "strict":
            print(f"::error::Verificate Gate errored ({type(e).__name__}); strict mode blocks the merge.")
            return 1
        print(f"::warning::Verificate Gate errored, failing open: {e}")
        return 0


if __name__ == "__main__":
    sys.exit(entry())
