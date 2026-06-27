"""Findings model and rendering.

A Finding is what Siege hands back: severity, the role it was found as, an exact
reproduction (tool + arguments a human can replay), the evidence (what actually
leaked), and remediation. Render to JSON for machines and Markdown for humans.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    probe_class: str         # "authz" | "inject" | "contract"
    severity: str            # critical | high | medium | low | info
    title: str
    identity: str            # the role it was found as
    repro: dict              # {"tool": ..., "arguments": {...}}
    evidence: dict
    remediation: str
    target: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)
    coverage: list = field(default_factory=list)   # probe classes that ran
    not_tested: list = field(default_factory=list)  # honest scope log

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "summary": self.summary(),
                "coverage": self.coverage,
                "not_tested": self.not_tested,
                "findings": [f.to_dict() for f in self.sorted_findings()],
            },
            indent=2,
        )

    def summary(self) -> dict:
        counts: dict = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(self.findings), "by_severity": counts}

    def to_markdown(self) -> str:
        lines = [f"# Siege report — {self.target}", ""]
        s = self.summary()
        if not self.findings:
            lines.append("**No findings.** The probed classes held.")
        else:
            sev = ", ".join(f"{n} {k}" for k, n in s["by_severity"].items())
            lines.append(f"**{s['total']} finding(s):** {sev}")
        lines += ["", f"_Coverage: {', '.join(self.coverage) or 'none'}._"]
        if self.not_tested:
            lines.append(f"_Not tested (out of scope this run): {', '.join(self.not_tested)}._")
        lines.append("")
        for i, f in enumerate(self.sorted_findings(), 1):
            lines += [
                f"## {i}. [{f.severity.upper()}] {f.title}",
                f"- **Class:** {f.probe_class}",
                f"- **Found as role:** `{f.identity}`",
                f"- **Reproduce:** `{f.repro['tool']}({json.dumps(f.repro.get('arguments', {}))})`",
            ]
            for k, v in f.evidence.items():
                lines.append(f"- **{k}:** {v}")
            lines += [f"- **Remediation:** {f.remediation}", ""]
        return "\n".join(lines)
