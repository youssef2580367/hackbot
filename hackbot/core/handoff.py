"""
HackBot → Claude Code validation handoff
========================================
Writes a self-contained, fact-only packet for one finding so the hunter's
existing Claude Code tooling can take over:

    validator agent  →  ywh:write (or report-writer)  →  ywh:triage

Layout::

    <out>/<target>/<NN>-<slug>/
        packet.md          human/agent-readable summary (facts only)
        finding.json       full finding + proof + pre-validation
        evidence/step-N.txt  full captured output of every cited step
        recorded/<file>      copies of attested recordings (hash-checked)

Nothing in the packet is generated prose: every field is copied from the
finding, the proof gate, the scope policy or captured output.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:60] or "finding"


def default_handoff_dir(configured: str = "") -> Path:
    return Path(configured).expanduser() if configured else Path.cwd() / "hackbot-findings"


def export_packet(
    finding: Dict[str, Any],
    index: int,
    target: str,
    step_outputs: Dict[int, Dict[str, str]],
    scope_summary: str = "",
    out_dir: Optional[Path] = None,
) -> Path:
    """Write the packet and return its directory.

    ``step_outputs`` maps step number → {"command", "output"} for the steps
    the finding's evidence cites.
    """
    name = f"{index:02d}-{_slug(finding.get('raw_title', ''))}"
    base = (out_dir or default_handoff_dir()) / _slug(target) / name
    (base / "evidence").mkdir(parents=True, exist_ok=True)

    proof = finding.get("proof") or {}
    validation = finding.get("validation") or {}
    refs: List[Dict[str, Any]] = proof.get("verified_refs") or []

    cited_steps = sorted({r["step"] for r in refs if r.get("step") is not None})
    for n in cited_steps:
        so = step_outputs.get(n)
        if so:
            (base / "evidence" / f"step-{n}.txt").write_text(
                f"$ {so['command']}\n\n{so['output']}"
            )

    copied: List[str] = []
    for rec in finding.get("recorded_evidence") or []:
        src = Path(rec["path"])
        if src.is_file():
            (base / "recorded").mkdir(exist_ok=True)
            dst = base / "recorded" / src.name
            shutil.copy2(src, dst)
            copied.append(f"recorded/{src.name} (sha256 {rec['sha256'][:16]}…)")

    (base / "finding.json").write_text(json.dumps(finding, indent=2, default=str))

    def line(label: str, value: Any) -> str:
        return f"- **{label}:** {value if value not in ('', None, []) else '_not provided_'}"

    md: List[str] = [
        f"# HackBot finding packet — {finding.get('raw_title', '')}",
        "",
        "> Facts only, copied from HackBot's proof gate. Anything marked _not provided_",
        "> is unknown — ask the hunter, do not fill it in.",
        "",
        "## Status",
        line("Proof gate", str(finding.get("verification", "lead")).upper()),
        line("HackBot pre-validation", validation.get("label", "not run")),
        line("Reason", validation.get("reason", "")),
        line("Claimed severity", finding.get("severity")),
        line("Suggested severity", validation.get("suggested_severity", "")),
        "",
        "## Finding",
        line("Target", target),
        line("Asset", finding.get("asset", "")),
        line("Class", finding.get("vuln_class", "")),
        line("Privileges required", finding.get("privileges_required", "")),
        line("Attacker identity", finding.get("attacker_identity", "")),
        line("Victim identity", finding.get("victim_identity", "")),
        line("Victim identifier", finding.get("victim_identifier", "")),
        line("Chained with", finding.get("chained_with", [])),
        "",
        "## Three pillars",
        line("Behavior", finding.get("behavior", "")),
        line("Boundary crossed", finding.get("boundary", "")),
        line("Demonstrated impact", finding.get("impact", "")),
        "",
        "## Verified evidence",
    ]
    if refs:
        for r in refs:
            if r.get("source") == "recorded":
                where = f"recorded `{r.get('path')}`"
            else:
                where = f"step {r.get('step')} — `{r.get('command', '')}`"
            md.append(f"- [{r.get('source')}] ({r.get('supports')}) {where}")
            md.append(f"  ```\n  {r.get('excerpt', '')}\n  ```")
    else:
        md.append("_none — this is an unverified lead_")
    md += ["", "## Reproduction", finding.get("reproduction") or "_not provided_", ""]
    if copied:
        md += ["## Attested recordings", *[f"- {c}" for c in copied], ""]
    if proof.get("missing"):
        md += ["## Proof gaps", *[f"- {m}" for m in proof["missing"]], ""]

    fp = finding.get("fp_triage") or {}
    if fp.get("signals") or fp.get("review"):
        md += [f"## False-positive screen: {fp.get('label', '')}"]
        for x in fp.get("signals", []):
            md.append(f"- {x['code']} ({x['confidence']}): {x['explanation']}")
        if fp.get("review"):
            r = fp["review"]
            md.append(f"- Hunter review: **{r['decision']}** — {r.get('note') or 'no note'}")
        md.append("")

    md += ["## 7-Question Gate (offline part)"]
    for q in validation.get("questions", []):
        md.append(f"- {q['q']} [{q['status']}] {q['detail']}")
    if validation.get("human_checks"):
        md += ["", "## Still needs the hunter / validator agent",
               *[f"- [ ] {h}" for h in validation["human_checks"]]]
    gotchas = validation.get("gotchas") or {}
    if gotchas:
        md += ["", "## ywh:gotchas for this class"]
        for key, label in (("common_na", "Common N/A"), ("overclaim", "Overclaim traps")):
            if gotchas.get(key):
                md += [f"**{label}**", *[f"- {x}" for x in gotchas[key]]]
    if scope_summary:
        md += ["", "## Enforced scope during the hunt", "```", scope_summary, "```"]
    md += ["", f"Rule sources: {json.dumps(validation.get('sources', {}))}", ""]

    (base / "packet.md").write_text("\n".join(md))
    return base
