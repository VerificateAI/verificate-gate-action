"""Verificate Gate Action - network I/O: GitHub REST, GitHub OIDC and the Verificate MCP endpoint."""
from __future__ import annotations
import json, os, random, ssl, time, urllib.parse, urllib.request, urllib.error

from vg_policy import _not_a_verdict

REPO = os.environ.get("GITHUB_REPOSITORY", "")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
# GitHub Actions OIDC: present only if the caller's workflow grants `permissions: id-token: write`.
OIDC_REQ_URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
OIDC_REQ_TOKEN = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
MCP_URL = os.environ.get("VERIFICATE_MCP_URL", "https://mcp.verificate.ai/mcp")
VKEY = os.environ.get("VERIFICATE_API_KEY", "").strip()
MARK = "<!-- verificate-gate -->"
_ctx = ssl.create_default_context()

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

GH_MAX_PAGES = 30  # 30 x 100 = 3000, GitHub's ceiling for the pull request files list


def gh_all(path):
    """Follow per_page pagination. Returns (items, complete): complete is False when the page
    cap was reached on a full page, so the caller knows the list may be truncated and never
    mistakes it for the whole set. A non-list page raises instead of being returned."""
    out, page = [], 1
    while True:
        chunk = gh(("&" if "?" in path else "?").join([path, f"per_page=100&page={page}"]))
        if not isinstance(chunk, list):
            raise ValueError(f"expected a list from {path[:60]}, got {type(chunk).__name__}")
        out += chunk
        if len(chunk) < 100:
            return out, True
        if page >= GH_MAX_PAGES:
            return out, False
        page += 1

def set_output(**kv):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        for k, v in kv.items():
            f.write(f"{k}={str(v).replace(chr(13), ' ').replace(chr(10), ' ')}\n")

MCP_MAX_RESPONSE = 4 * 1024 * 1024  # a verdict is a few KB; cap what a bad upstream can make us buffer
REBUTTAL_MAX = 6000  # characters of .verificate/rebuttals.md sent as review context


def _load_taint():
    """Load the action's own taint.py by absolute path. A bare 'import taint' could resolve a
    PR-supplied taint.py from the workspace or PYTHONPATH inside a job holding GITHUB_TOKEN."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "taint.py")
    spec = importlib.util.spec_from_file_location("verificate_gate_taint", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def mcp_validate(code, lang, rebuttal="", validation_type="code_generation", reachability_hint=True):
    # A rebuttal (from .verificate/rebuttals.md) lets the gate adjudicate a prior finding the
    # agent contests with proof — the gate overturns findings whose methodology it accepts.
    ctx = {"language": lang}
    # Injection-reachability: suppress false "injection/RCE" findings whose sink is fed only by an
    # operator-controlled source (a CLI arg, local config, a trusted literal) rather than untrusted input.
    # The hint is computed from the code under review, so the author can shape it; strict mode
    # turns it off (reachability_hint=False) and the reviewer judges injection on its own.
    if reachability_hint and validation_type == "code_generation":
        try:
            taint = _load_taint()
            _t = taint.analyze(code)
            ctx["security_graph"] = {"injection_reachable": _t["injection_reachable"], "taint_flows": _t["flows"]}
        except Exception as e:
            # Optional hint only: the review still runs, just without the reachability graph.
            print(f"::warning::taint analysis skipped ({type(e).__name__}); reviewing without the reachability hint.")
    if rebuttal:
        if len(rebuttal) > REBUTTAL_MAX:
            print(f"::warning::.verificate/rebuttals.md is {len(rebuttal)} characters; only the first "
                  f"{REBUTTAL_MAX} are sent. Put the methodology for each contested finding first.")
            rebuttal = rebuttal[:REBUTTAL_MAX] + f"\n[rebuttals truncated at {REBUTTAL_MAX} characters]"
        ctx["rebuttal"] = rebuttal
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
               "arguments":{"ai_output":code,"validation_type":validation_type,"context":ctx}}, 2)
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

