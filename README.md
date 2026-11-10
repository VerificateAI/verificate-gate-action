# 🛡️ Verificate Gate

**Verificate Gate is an AI-powered CI gate for GitHub.** It protects your repository from AI hallucination — code that looks right but isn't real — and performs automated checks for **security, reliability, performance efficiency and maintainability (ISO 5055)** on every pull request. If a change has a real problem, the pull request is blocked until it's fixed.

[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-Verificate%20Gate-2ea44f?logo=github)](https://github.com/marketplace/actions/verificate-gate)
[![gated by Verificate](https://img.shields.io/badge/gated%20by-Verificate-2ea44f?logo=shield)](https://github.com/VerificateAI/verificate-gate-action)
[![Benchmark](https://img.shields.io/badge/AI%20self--review%200%2F6%20%E2%86%92%20Gate%206%2F6-2ea44f)](https://github.com/VerificateAI/verificate-mcp-quickstart/blob/master/COMPARISON.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)

## What it is

Verificate Gate reviews the code in every pull request — automatically, before a human sees it. It looks for the mistakes AI coding tools make most:

- **Invented APIs** — calls to functions or libraries that don't exist.
- **Placeholder code presented as finished** — mocks, stubs, `FIXME`s and hardcoded results passed off as working.
- **Tests written to pass rather than to test** — a green tick that proves nothing.
- **Secrets written to logs** — a password, API key, access token or access code passed to a log or console call (CWE-532).
- **Quality problems** in the four ISO 5055 areas: security, reliability, performance efficiency and maintainability.

Nothing is executed — your code is read and checked, never run.

## New in November 2026

- **Stronger reviewer.** The model stage now runs on Claude Haiku 5.5. On our frozen benchmark (12 cases, each reviewed 3 times), unsafe approvals fell from **6 in 36 to 0 in 36**, and all 12 clean controls were still approved. [Method and numbers](https://github.com/VerificateAI/verificate-mcp-quickstart/blob/master/BENCHMARK_2026-11.md).
- **Two new deterministic vetoes:** secrets written to logs (Python, JS/TS, Java, Go, Rust, C#, PHP, Ruby, Swift, Kotlin) and invented Python standard-library calls. A veto fails the change whatever the model says.
- **One decision per file, with a receipt.** Each review returns a single decision (approved, approved with conditions, rejected or incomplete) plus what was and was not verified. A review that cannot cover the file says so; it is never counted as an approval.
- **Used hard in our own engineering:** 3,844 Gate reviews across 54 of our own projects between 7 October and 10 November 2026, 943 of them rejected and fixed.

## How it works

1. **Deterministic veto checks** run first — placeholders and mocks presented as done, tests that cannot fail, invented standard-library calls, secrets in logs, deceptive or evidence-free claims. Same input, same result, and no model output can override a veto.
2. **A Claude Haiku 5.5 review** then checks the rest against ISO/IEC 25010 and ISO/IEC 5055: security, reliability, performance efficiency and maintainability, including whether third-party API calls are real. Its high or critical security and API findings block the merge.

## How to use it

Add one file to your repository:

```yaml
# .github/workflows/verificate-gate.yml
name: Verificate Gate
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  pull-requests: write
  id-token: write      # lets the gate claim your repo's own free quota (see below)
jobs:
  verificate-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: VerificateAI/verificate-gate-action@v1
```

That's it. No signup, no API key, free to try — the next pull request gets checked. To remove it, delete the file.

> **The gate reviews pull requests.** Commits pushed straight to a branch (e.g. directly to `main`) are not reviewed — the check only runs on `pull_request` events. To gate everything, protect your default branch so changes arrive through PRs (**Settings → Branches → Require a pull request before merging**).

The `id-token: write` permission is what makes the free tier reliable in CI: GitHub-hosted runners share IP addresses across everyone, so an IP-based free quota gets used up by unrelated repos before your first run. With that permission, the gate proves your repository identity with a signed GitHub token and draws on **your repository's own free quota** instead — so your first run actually reviews your code. Leave the permission off and it still works, just falling back to the shared per-runner quota (which may already be used up).

## What you get

Every pull request gets a clear verdict, in plain English, right on the PR:

> ### 🛡️ Verificate Gate
> | File | Verdict | Detail |
> |---|---|---|
> | `payment.py` | ❌ **REJECTED** | |
> | ↳ | Placeholder detected: **FIXME** comment indicating broken code |
> | ↳ | `stripe.Refund.create_partial` **does not exist** in the Stripe SDK |
> | ↳ | Missing idempotency key in a financial transaction |
>
> **Fix the findings and push again.**

- **Broken AI code never reaches your application.** A rejected change turns the check red and GitHub blocks the merge until it's fixed.
- **A tireless first reviewer.** Humans skim; the gate reads every changed file, every time.
- **It catches what AI review misses.** In our September benchmark, a leading AI model asked to review code in a normal workflow caught **0 of 6** planted problems (a fake API and a self-passing test). Verificate Gate caught **6 of 6**, every run. [See the benchmark →](https://github.com/VerificateAI/verificate-mcp-quickstart/blob/master/COMPARISON.md)
- **Low noise, not just high recall.** The gate reasons about *reachability*: a `subprocess`/`exec`/`import` call fed by a CLI argument, a local config value, or a trusted literal is the intended behaviour of a dev tool or build script — not command injection — so it is not flagged. You get the real defects without a wall of false alarms that trains people to ignore the check.

Built for teams using **GitHub Copilot, Claude Code, Cursor, Windsurf, Cline, Aider, Codex** or any AI coding assistant — the gate catches what the assistant got wrong *before* the PR lands. It works on every pull request, including AI-generated ones, and pairs with the [Verificate MCP server](https://github.com/VerificateAI/verificate-mcp-quickstart) for in-editor gating as code is written.

## The problem: AI writes the code, humans carry the review

AI tools now write more and more of the code that lands in pull requests — far more than human reviewers can carefully read. AI-written code is fluent and confident even when it is wrong, so the worst mistakes are the hardest to spot: a function that doesn't exist, a test that can't fail, a stub that looks finished.

Verificate Gate supports the review process rather than replacing it. It applies **ISO 5055 protections** (automated checks for security, reliability, performance efficiency and maintainability) and adds **ISO 25010 recommendations** (suggestions aligned with the software-quality standard), so that only high-quality code ever reaches your application — and your human reviewers spend their time on design, not on spotting fakes.

## Adopting it safely

Start in watch mode, switch to blocking when you trust it:

1. **Watch mode** — set `fail-on: off`. The gate comments its verdict on every PR but never blocks anything. Run it for a week and see what it catches.
2. **Blocking mode** — set `fail-on: reject` (the default) and add the required check under **Settings → Branches → Require status checks**. In that list it appears as **`Verificate Gate / verificate-gate`** (job name / workflow). Now a rejected change can't merge until it's fixed.

Rejections come with the concrete problem they point to (a nonexistent API, a placeholder, a self-passing test, a secret in a log). In the November benchmark every clean control was approved, and the new secrets-in-logs check flagged only genuine credential logging when run on 34,849 real open-source files before launch.

If the Verificate service is ever unreachable, the check simply passes and says so. **In the default `reject` mode, an outage on our side never blocks your team's merges.**

3. **Strict mode** — set `fail-on: strict` when the check must never pass on code it did not review, for example a required org-wide check. The check fails unless every changed file was reviewed and approved. Gate errors, quota or key refusals, a review that did not complete, files over `max-files`, and unexpected errors all fail it. Every changed file is reviewed except prose and media (`.md`, `.rst`, `.txt`, images, fonts, audio and video), so a file with an unknown or missing extension is reviewed rather than skipped. Agent instruction files (`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.cursorrules`, anything under `.claude/`, `.cursor/` or `.github/instructions/`) are reviewed as documentation, because they steer generated code. Compiled binaries and archives cannot be reviewed as text, so they block. The check also blocks on a non-pull-request event, and when the PR head has moved since the event. It reads `.verificate/rebuttals.md` from the base branch, so a PR cannot overrule its own findings. It sends no reachability hint derived from the code under review. An outage blocks merges in this mode, by design.

> **Busy shared runners:** the free tier is shared per runner, so on a busy shared runner it can already be used up. A free key of your own (no card, 30 days — [verificate.ai/auth/signup](https://verificate.ai/auth/signup)) gives you a private quota: add it as a repository secret named `VERIFICATE_API_KEY` and pass it as shown below.

## Settings

All settings are optional.

| Setting | Default | What it does |
|---|---|---|
| `verificate-api-key` | — | Your own free key, for a private quota (the shared free tier works without one). |
| `fail-on` | `reject` | `reject` = block the merge on a rejected change; `off` = comment only (watch mode); `strict` = block unless every changed file was reviewed and approved (fails closed on gate errors and skipped files). An unrecognised value falls back to `reject`. |
| `max-files` | `25` | Most changed code files reviewed per pull request. If a PR changes more, the gate reviews the first `max-files`, flags the rest in the PR comment, and leaves them unreviewed — raise this for large PRs. |
| `mcp-url` | `https://mcp.verificate.ai/mcp` | Point at your own Verificate deployment if your code must not leave your infrastructure. |

```yaml
      - uses: VerificateAI/verificate-gate-action@v1
        with:
          verificate-api-key: ${{ secrets.VERIFICATE_API_KEY }}
          fail-on: reject
```

## Outputs

The step exposes outputs you can use in later steps — auto-label a rejected PR, notify, or build dashboards:

| Output | Value |
|---|---|
| `verdict` | `approved` / `rejected` / `vetoed` / `error` (transient gate failures block merges only with `fail-on: strict`) |
| `files_reviewed` | Changed code files reviewed |
| `files_errored` | Files skipped (transient error or quota) |
| `files_dropped` | Files beyond `max-files` that were left unreviewed |

```yaml
      - uses: VerificateAI/verificate-gate-action@v1
        id: gate
      - if: steps.gate.outputs.verdict == 'vetoed'
        run: echo "A deterministic reality gate vetoed this change."
```

## FAQ

- **Do PRs from forks get reviewed?** Yes — the free tier uses GitHub's signed OIDC token, not a repository secret, so fork PRs work with `id-token: write`. (GitHub never hands secrets to fork-originated PRs; OIDC is unaffected.)
- **What if the shared free tier is used up on a busy runner?** The gate fails open with a note on the PR and never blocks the merge (except with `fail-on: strict`). A free key ([verificate.ai/auth/signup](https://verificate.ai/auth/signup), no card) gives the repo its own quota as `VERIFICATE_API_KEY`.
- **What if Verificate is down or the network blips?** The gate retries transient failures and then fails open: an outage on the Verificate side never blocks your team's merges. With `fail-on: strict` it fails closed instead.
- **Big PRs?** The gate reviews up to `max-files` (default 25, up to 300) changed code files per PR and notes the remainder on the PR. Raise the cap or review locally for the full detail.
- **Must code leave our infrastructure?** No — point `mcp-url` at your own Verificate deployment and nothing leaves your environment.
- **Disagree with a finding?** Add a proof-backed entry to `.verificate/rebuttals.md` — the gate re-adjudicates on the next run and overturns findings whose methodology holds.

## Security & data handling

- **Permissions:** `contents: read` (to read the changed files), `pull-requests: write` (to post the comment) and, optionally, `id-token: write` (a signed GitHub token that proves the repository's identity for its own free quota). Nothing else.
- **What leaves your runner:** the text of the changed code files is sent over HTTPS to the Verificate endpoint for review, and the verdict comes back. Your `GITHUB_TOKEN` never leaves the runner.
- **No code execution.** Files are read and analysed, never run.
- **Keep code in-house:** point `mcp-url` at your own Verificate deployment.
- **Secrets:** the optional key is read from a repository secret; GitHub withholds secrets from fork-originated PRs.
- **Version pinning:** use `@v1` for automatic fixes, or pin a full commit SHA for byte-exact builds.

---
*Verificate — the merge gate for AI-written code. [verificate.ai](https://verificate.ai)*
