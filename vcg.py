#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificate Context Graph (VCG) — cross-file GUARD context for the CI gate.

The gate reviews one file at a time, so it can flag an "escape" that a guard in ANOTHER file already
blocks (e.g. a prototype-pollution finding on expression.ts when PrototypeSanitizer -> isSafeObjectProperty
-> unsafeObjectProperties in other files rejects `__proto__`/`constructor`). This module builds a small
in-memory graph of the checked-out repo and returns, for a changed file, the guards it reaches through its
imports and the blocklists those guards enforce. The gate uses that ONLY to suppress a finding it can prove
is guarded — it never raises anything from this graph, so the worst a wrong edge can do is nothing.

Ported from PR #2 (2026-08-18) onto the current gate.py, with the properties a public Action needs:
  * bounded: caps on files, bytes per file and wall-clock; vendored/build dirs pruned; never raises
  * in-process only (no Redis lookup on a customer's runner)
  * the ENFORCES pass is O(files x blocklists), not O(files x every symbol)

Entities  E:<id>            dict: type, path, name, role, value
Edges     EDGE:<rel>:<src>  set of dst   (rel in IMPORTS, DEFINES, ENFORCES)
"""
import json
import os
import re
import time
from pathlib import Path

CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", ".venv", "venv", "env", "site-packages",
             "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", ".nuxt", "target", "coverage",
             ".terraform", "bower_components", "third_party"}
MAX_FILES = int(os.environ.get("VCG_MAX_FILES", "4000"))
MAX_BYTES = int(os.environ.get("VCG_MAX_FILE_BYTES", "400000"))
BUDGET_S = float(os.environ.get("VCG_BUDGET_SECONDS", "20"))

GUARD_NAME_RX = re.compile(r"saniti[sz]|validat|escape|is_?safe|is_?allowed|blocklist|denylist", re.I)   # camelCase and snake_case
BLOCK_RX = re.compile(r"(?:const|let|var)\s+(\w*(?:unsafe|blocked|forbidden|denied|reserved|blocklist|denylist)\w*)"
                      r"\s*=\s*new Set\(\[(.*?)\]\)", re.I | re.S)
BLOCK_PY_RX = re.compile(r"^(\w*(?:UNSAFE|BLOCKED|FORBIDDEN|DENIED|RESERVED|BLOCKLIST|DENYLIST)\w*)"
                         r"\s*=\s*(?:frozenset\(|set\()?[\[{(](.*?)[\]})]\)?\s*$", re.I | re.S | re.M)
IMPORT_TS = re.compile(r"import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+['\"]([^'\"]+)['\"]")
IMPORT_PY = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^\n)]+)", re.M)
DEF_TS = re.compile(r"export\s+(?:const|function|class|type|interface|abstract class)\s+(\w+)")
DEF_PY = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+(\w+)", re.M)


def repo_files(root):
    """First-party source files under root, sorted, pruned and capped. Never raises."""
    out = []
    try:
        for base, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
            for name in sorted(names):
                p = Path(base) / name
                if p.suffix in CODE_EXT and ".min." not in name:
                    out.append(p)
                    if len(out) >= MAX_FILES:
                        return out
    except OSError:
        pass
    return out


def _module_id(rel, imp, is_py):
    """Repo-relative file id (no extension) an import points at; bare package imports resolve by symbol."""
    if is_py:
        if imp.startswith("."):
            depth = len(imp) - len(imp.lstrip("."))
            base = Path(rel).parent
            for _ in range(depth - 1):
                base = base.parent
            tail = imp.lstrip(".").replace(".", "/")
            return (base / tail).as_posix() if tail else base.as_posix()
        return imp.replace(".", "/")
    return (Path(rel).parent / imp).as_posix() if imp.startswith(".") else imp


class VCG:
    def __init__(self, root):
        self.root = Path(root)
        self.ent, self.edges, self.defines = {}, {}, {}
        self.files_indexed, self.truncated = 0, False

    def _edge(self, kind, src, dst):
        self.edges.setdefault((kind, src), set()).add(dst)

    def build(self, files=None):
        t0 = time.monotonic()
        texts = {}
        for p in (files if files is not None else repo_files(self.root)):
            if time.monotonic() - t0 > BUDGET_S:
                self.truncated = True
                break
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                txt = p.read_text(encoding="utf-8", errors="replace")
                rel = p.relative_to(self.root).as_posix()
            except (OSError, ValueError):
                continue
            fid, is_py = rel.rsplit(".", 1)[0], rel.endswith(".py")
            texts[fid] = txt
            for rx in ((BLOCK_PY_RX,) if is_py else (BLOCK_RX,)):
                for m in rx.finditer(txt):
                    name = m.group(1)
                    vals = [v.strip().strip("'\"") for v in m.group(2).split(",") if v.strip().strip("'\"")]
                    if not vals:
                        continue
                    self.ent[f"{fid}#{name}"] = {"type": "const", "path": rel, "name": name, "role": "blocklist", "value": vals}
                    self._edge("DEFINES", fid, f"{fid}#{name}")
                    self.defines[name] = fid
            for m in (DEF_PY if is_py else DEF_TS).finditer(txt):
                name = m.group(1)
                if f"{fid}#{name}" in self.ent:
                    continue
                role = "guard" if GUARD_NAME_RX.search(name) else "symbol"
                self.ent[f"{fid}#{name}"] = {"type": "symbol", "path": rel, "name": name, "role": role}
                self._edge("DEFINES", fid, f"{fid}#{name}")
                self.defines.setdefault(name, fid)
            for m in (IMPORT_PY if is_py else IMPORT_TS).finditer(txt):
                mod, syms = (m.group(1), m.group(2)) if is_py else (m.group(2), m.group(1))
                for sym in (x.strip().split(" as ")[0].strip() for x in syms.split(",")):
                    if sym and sym != "*":
                        self._edge("IMPORTS", fid, f"{sym}@{_module_id(rel, mod, is_py)}")
            self.files_indexed += 1
        # ENFORCES: a file that references a blocklist symbol -> its guard symbols enforce that blocklist.
        blocklists = [(eid, e["name"]) for eid, e in self.ent.items() if e["role"] == "blocklist"]
        for fid, txt in texts.items():
            if time.monotonic() - t0 > BUDGET_S:
                self.truncated = True
                break
            guards = [g for g in self.edges.get(("DEFINES", fid), ()) if self.ent[g]["role"] == "guard"]
            if not guards:
                continue
            for eid, name in blocklists:
                if name in txt and re.search(rf"\b{re.escape(name)}\b", txt):
                    for g in guards:
                        self._edge("ENFORCES", g, eid)
        return self

    def _resolve(self, sym, tgt):
        if f"{tgt}#{sym}" in self.ent:
            return f"{tgt}#{sym}"
        for suffix in ("/index", "/__init__"):
            if f"{tgt}{suffix}#{sym}" in self.ent:
                return f"{tgt}{suffix}#{sym}"
        did = self.defines.get(sym)
        return f"{did}#{sym}" if did else None

    def subgraph(self, rel, max_depth=3):
        """Guards reachable from `rel` through its imports (transitively) and the blocklists they enforce."""
        guards, blocklists, seen = set(), {}, set()
        frontier = [rel.rsplit(".", 1)[0]]
        for _ in range(max_depth):
            nxt = []
            for cur in frontier:
                if cur in seen:
                    continue
                seen.add(cur)
                for edge in self.edges.get(("IMPORTS", cur), ()):
                    sym, tgt = edge.split("@", 1)
                    eid = self._resolve(sym, tgt)
                    if eid and self.ent[eid]["role"] == "guard":
                        guards.add(eid)
                        for b in self.edges.get(("ENFORCES", eid), ()):
                            blocklists[self.ent[b]["name"]] = self.ent[b]["value"]
                        nxt.append(eid.split("#")[0])
            frontier = nxt
            if not frontier:
                break
        return {"file": rel, "guards": sorted(guards)[:50], "blocklists": blocklists}    # bounded: this rides on every request


def build(workspace):
    """A built graph for a checked-out repo, or None (no checkout / nothing indexable / any error).
    The Action reads files through the GitHub API and does not require actions/checkout, so cross-file
    context is available exactly when the caller's workflow checked the repo out."""
    try:
        if not workspace or not os.path.isdir(workspace):
            return None
        g = VCG(workspace).build()
        return g if g.files_indexed else None
    except Exception as e:  # never let context-building break a review
        print(f"::warning::cross-file context skipped: {type(e).__name__}: {str(e)[:120]}")
        return None


if __name__ == "__main__":
    import sys
    g = build(sys.argv[1] if len(sys.argv) > 1 else ".")
    if not g:
        sys.exit("nothing indexed")
    print(f"indexed {g.files_indexed} files, {sum(1 for e in g.ent.values() if e['role'] == 'guard')} guards, "
          f"{sum(1 for e in g.ent.values() if e['role'] == 'blocklist')} blocklists")
    if len(sys.argv) > 2:
        print(json.dumps(g.subgraph(sys.argv[2]), indent=1))
