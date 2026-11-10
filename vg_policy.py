"""Verificate Gate Action - pure policy: modes, file classification, decoding, verdict shapes.

No I/O and no environment reads. gate.py decides; vg_net.py talks to GitHub and the gate."""
from __future__ import annotations
import base64, html, json, os


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

def file_ext(filename):
    """Lower-cased extension of the file's base name ('' if none). The previous
    '"." + rsplit(".")' turned 'Makefile' into '.Makefile' and 'a.b/c' into '.b/c'."""
    return os.path.splitext(filename.rsplit("/", 1)[-1])[1].lower()


def is_code(filename, mode):
    """Whether a changed file must be reviewed. reject/off keep the published allow-list;
    strict reviews everything that is not explicitly prose or a binary asset."""
    ext = file_ext(filename)
    if mode == "strict":
        return ext not in NON_CODE_EXT or is_agent_instructions(filename)
    return ext in CODE_EXT


# Prose that coding agents read and act on. It steers generated code, so strict reviews it
# (as documentation) even though other Markdown is exempt.
AGENT_DOC_NAMES = {"agents.md", "claude.md", "gemini.md", "copilot-instructions.md",
                   ".cursorrules", ".windsurfrules", ".clinerules"}
AGENT_DOC_DIRS = (".claude/", ".cursor/", ".github/instructions/", ".github/prompts/",
                  ".windsurf/", ".clinerules/", ".verificate/")


def is_agent_instructions(filename):
    path = "/" + filename.replace("\\", "/").lower()
    return path.rsplit("/", 1)[-1] in AGENT_DOC_NAMES or any("/" + d in path for d in AGENT_DOC_DIRS)


def review_type(filename):
    """validation_type sent to the gate: agent-instruction prose is documentation, all else code."""
    if is_agent_instructions(filename) and file_ext(filename) in NON_CODE_EXT:
        return "documentation"
    return "code_generation"


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


