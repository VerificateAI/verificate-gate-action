"""Verificate Gate — GitHub Action entrypoint.

Runs the Verificate merge gate on the changed code files of a pull request, posts an inline
summary comment, and exits non-zero if the gate VETOES (so it can be a required status check
that blocks merge). Design principle: fail CLOSED only on a real veto; fail OPEN on any
infrastructure error (MCP unreachable, timeouts) so gate outages never block your merges.

Env: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH, optional VERIFICATE_MCP_URL,
VERIFICATE_API_KEY, FAIL_ON (reject|off), MAX_FILES.
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
    return _s(v).replace("|", "\\|")[:180]

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
FAIL_ON = os.environ.get("FAIL_ON", "reject").strip().lower()
try:
    MAX_FILES = int(os.environ.get("MAX_FILES", "25"))
except ValueError:
    print(f"::warning::max-files '{os.environ.get('MAX_FILES')}' is not an integer; using 25.")
    MAX_FILES = 25
MAX_FILES = max(1, min(MAX_FILES, 300))
MARK = "<!-- verificate-gate -->"
CODE_EXT = {".py",".js",".ts",".tsx",".jsx",".go",".java",".rb",".rs",".c",".cc",".cpp",
            ".cs",".php",".sql",".sh",".kt",".swift",".scala"}
LANG = {".py":"python",".js":"javascript",".ts":"typescript",".tsx":"typescript",".jsx":"javascript",
        ".go":"go",".java":"java",".rb":"ruby",".rs":"rust",".cpp":"cpp",".cs":"csharp",".php":"php",".sql":"sql"}
_ctx = ssl.create_default_context()

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

_OIDC = github_oidc_token()

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
            if e.code in (403, 429) and retry_after and attempt < tries:
                wait = min(float(retry_after), 60) + random.uniform(0, 1)
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
            f.write(f"{k}={str(v).replace(chr(10), ' ')}\n")

CROSS_FILE = os.environ.get("CROSS_FILE", "auto").strip().lower()      # auto | off


def build_context_graph():
    """Cross-file guard graph of the checked-out repo, or None. The Action reads changed files through
    the GitHub API and does not need actions/checkout — so this is available exactly when the caller's
    workflow checked the repo out, and silently absent otherwise. Never raises."""
    if CROSS_FILE == "off":
        return None
    try:
        import vcg
        return vcg.build(os.environ.get("GITHUB_WORKSPACE", ""))
    except Exception as e:
        print(f"::warning::cross-file context skipped: {type(e).__name__}: {str(e)[:120]}")
        return None


def mcp_validate(code, lang, rebuttal="", rel=None, graph=None):
    # A rebuttal (from .verificate/rebuttals.md) lets the gate adjudicate a prior finding the
    # agent contests with proof — the gate overturns findings whose methodology it accepts.
    ctx = {"language": lang}
    # Injection-reachability: suppress false "injection/RCE" findings whose sink is fed only by an
    # operator-controlled source (a CLI arg, local config, a trusted literal) rather than untrusted input.
    try:
        import taint
        _t = taint.analyze(code)
        ctx["security_graph"] = {"injection_reachable": _t["injection_reachable"], "taint_flows": _t["flows"]}
    except Exception:
        pass
    # Cross-file GUARD context: the guards this file reaches through its imports and the blocklists they
    # enforce, so the gate can drop a finding it can PROVE is blocked in another file. Suppress-only —
    # nothing is ever raised from the graph, so a wrong edge can at worst change nothing.
    if graph is not None and rel:
        try:
            sub = graph.subgraph(rel)
            if sub["guards"] or sub["blocklists"]:
                ctx.setdefault("security_graph", {}).update({"guards": sub["guards"], "blocklists": sub["blocklists"]})
        except Exception:
            pass
    if rebuttal:
        ctx["rebuttal"] = rebuttal[:6000]
    def rpc(method, params, rid):
        body = json.dumps({"jsonrpc":"2.0","id":rid,"method":method,"params":params}).encode()
        h = {"Content-Type":"application/json","Accept":"application/json, text/event-stream",
             "User-Agent":"verificate-gate/1.0 (+https://verificate.ai)"}
        # Signed OIDC token → the portal meters the free tier per-repository (not per
        # shared runner IP) with the repo identity proven, not merely claimed.
        if _OIDC: h["X-Verificate-OIDC"] = _OIDC
        if VKEY: h["Authorization"] = f"Bearer {VKEY}"
        req = urllib.request.Request(MCP_URL, data=body, method="POST", headers=h)
        raw = _open(req, 120, tries=2, label=f"mcp {method}").read().decode()
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
    parts = resp.get("result", {}).get("content", [])
    text = "\n".join(p.get("text","") for p in parts if p.get("type")=="text").strip()
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
    ev = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    pr = (ev.get("pull_request") or {}).get("number") or ev.get("number")
    head = ((ev.get("pull_request") or {}).get("head") or {}).get("sha") or ""
    ref_qs = f"?ref={head}" if head else ""
    if not pr:
        print("Not a pull_request event; nothing to gate."); return 0
    try:
        files = gh_all(f"/repos/{REPO}/pulls/{pr}/files")
    except Exception as e:
        print(f"::warning::could not list files ({e}); failing open."); return 0
    eligible = [f for f in files if f.get("status") in ("added","modified")
                and any(f["filename"].endswith(e) for e in CODE_EXT)]
    targets = eligible[:MAX_FILES]
    dropped = len(eligible) - len(targets)
    if dropped:
        print(f"::warning::Verificate Gate reviewed the first {MAX_FILES} of {len(eligible)} changed code files; "
              f"{dropped} were left unreviewed. Raise max-files to cover the whole PR.")
    if not targets:
        upsert_comment(pr, f"{MARK}\n### ✅ Verificate Gate — no code changes to review.")
        print("No code files changed."); return 0

    # Appeal channel: if the author (or their agent) contested prior findings with a proof in
    # .verificate/rebuttals.md, feed it to the gate so it can adjudicate and overturn sound rebuttals.
    rebuttal = ""
    try:
        rb = gh(f"/repos/{REPO}/contents/.verificate/rebuttals.md{ref_qs}")
        rebuttal = base64.b64decode(rb["content"]).decode("utf-8", "replace")
        if rebuttal.strip():
            print("Verificate: rebuttals.md found — the gate will adjudicate contested findings.")
    except Exception:
        pass  # no rebuttals file is the normal case

    rows, vetoed_any, rejected_any, errors, capped, fixes = [], False, False, 0, False, []
    vcg_metas = []
    graph = build_context_graph()
    if graph is not None:
        print(f"Cross-file context: {graph.files_indexed} files indexed"
              + (" (time budget reached — partial graph)" if graph.truncated else ""))
    for f in targets:
        ext = "." + f["filename"].rsplit(".",1)[-1]
        try:
            meta = gh(f"/repos/{REPO}/contents/{urllib.parse.quote(f['filename'])}{ref_qs}")
            code = base64.b64decode(meta["content"]).decode("utf-8","replace")
            res = mcp_validate(code, LANG.get(ext, "text"), rebuttal=rebuttal, rel=f["filename"], graph=graph)
        except Exception as e:
            errors += 1
            print(f"::warning::Verificate gate error on {f['filename']}: {type(e).__name__}: {str(e)[:160]}")
            rows.append((f["filename"], "⚠️ gate error (skipped)", "")); continue
        if res.get("_unavailable"):
            errors += 1
            reason = res.get("reason", "")
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
        vcg_metas.append(res)
        prot = res.get("protection", {})
        vetoed = bool(prot.get("vetoed"))
        rejected = vetoed or res.get("valid") is False or str(res.get("assessment",{}).get("verdict","")).lower() in ("reject","rejected")
        score = res.get("score")
        issues = res.get("issues") or []
        if vetoed: vetoed_any = True
        if rejected: rejected_any = True
        status = "❌ REJECTED" if rejected else "✅ approved"
        detail = ("vetoed by " + ", ".join(prot.get("vetoed_by") or [])) if vetoed else (f"score {score}" if score is not None else "")
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
    if graph is not None:
        n_sup = sum(int(((r_ or {}).get("vcg") or {}).get("suppressed", 0) or 0) for r_ in vcg_metas)
        lines.insert(3, f"Cross-file context: {graph.files_indexed} files indexed"
                     + (f" · {n_sup} finding(s) dropped as proven-guarded in another file" if n_sup else "") + ".")
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
    if capped:
        lines += ["", "> ⚠️ **Some files were skipped — the shared free trial on this runner is used up, so the gate couldn't score them.** "
                  "The gate failed **open**, so this did **not** block your merge. "
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

    if (vetoed_any or rejected_any) and FAIL_ON == "reject":
        why = "VETOED by a deterministic reality gate" if vetoed_any else "REJECTED"
        print(f"::error::Verificate Gate: a change was {why} — blocking merge until fixed.")
        return 1
    print("Verificate Gate: passed.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        # Global fail-open: never block a merge on an unexpected gate error.
        print(f"::warning::Verificate Gate errored, failing open: {e}")
        sys.exit(0)
