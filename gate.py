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
import base64, json, os, sys, urllib.parse, urllib.error

# Load the sibling modules from the action directory only. The action runs under python -I, so
# neither the PR workspace nor PYTHONPATH is on sys.path; this puts back exactly one trusted path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vg_net as net  # noqa: E402
from vg_net import MARK, REPO, gh, gh_all, mcp_validate, set_output, upsert_comment  # noqa: E402
from vg_policy import (BINARY_EXEC_EXT, GH_FILES_LIMIT, LANG, _s, cell, exit_code, file_ext,  # noqa: E402,F401
                       is_code, md, normalize_response, parse_fail_on, parse_max_files, read_file,
                       review_type, to_review, _not_a_verdict)

COMMENT_MAX = 60000  # keep under GitHub's 65536-char comment limit

# Pure parsing at import; the warnings are printed by main(), not as an import side effect.
FAIL_ON, _FAIL_ON_WARNING = parse_fail_on(os.environ.get("FAIL_ON", "reject"))
MAX_FILES, _MAX_FILES_WARNING = parse_max_files(os.environ.get("MAX_FILES", "25"))

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
    if mode == "strict" and not head:
        # Without the event's head SHA the contents would be read at the default branch.
        print("::error::the event carries no pull request head SHA; strict mode blocks this run.")
        set_output(verdict="error", files_reviewed=0, files_errored=0, files_dropped=0)
        return 1

    def head_moved():
        """The file list describes the PR's CURRENT head; the contents are read at the event's
        head. Checked before AND after listing, so a push in between cannot slip through."""
        live = ((gh(f"/repos/{REPO}/pulls/{pr}").get("head") or {}).get("sha") or "")
        if live != head:
            print(f"::error::the pull request head moved ({head[:12]} -> {live[:12]}) since this event; "
                  "strict mode blocks this run. The run for the new head gates it.")
            set_output(verdict="error", files_reviewed=0, files_errored=0, files_dropped=0)
            return True
        return False

    try:
        if mode == "strict" and head_moved():
            return 1
        files, complete = gh_all(f"/repos/{REPO}/pulls/{pr}/files")
        if mode == "strict" and head_moved():
            return 1
    except Exception as e:
        if mode == "strict":
            print(f"::error::could not list files ({type(e).__name__}); strict mode blocks the merge.")
            set_output(verdict="error", files_reviewed=0, files_errored=0, files_dropped=0)
            return 1
        print(f"::warning::could not list files ({e}); failing open."); return 0
    incomplete_list = (not complete) or len(files) >= GH_FILES_LIMIT
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
            res = mcp_validate(code, LANG.get(ext, "text"), rebuttal=rebuttal,
                               validation_type=review_type(f["filename"]),
                               reachability_hint=(mode != "strict"))
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
            # Best effort: leave downstream jobs a verdict. A failure here must not mask the block.
            try:
                set_output(verdict="error", files_reviewed=0, files_errored=0, files_dropped=0)
            except Exception as oe:
                print(f"::warning::could not write step outputs ({type(oe).__name__}).")
            return 1
        print(f"::warning::Verificate Gate errored, failing open: {e}")
        return 0


if __name__ == "__main__":
    sys.exit(entry())
