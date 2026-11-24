"""HTML and PDF assessment reports.

The report is a rendering of the stored assessment â€” it never recomputes scores, so it
cannot disagree with the API. Both renderers share one data structure built by
:func:`build_report_data`, which keeps the HTML and PDF outputs consistent.
"""

from __future__ import annotations

import html
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.services.scoring import SCORING_MODEL_VERSION

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
STATE_ORDER = {"non_compliant": 0, "error": 1, "unknown": 2, "compliant": 3, "not_applicable": 4}


def _json_text(value: Any) -> str:
    if value is None:
        return "not collected"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return str(value)


def _score(value: Any) -> str:
    return "not assessed" if value is None else str(value)


def build_report_data(
    *,
    scan: Any,
    findings: Sequence[Any],
    result: Any,
    device: Any,
    baseline: Any,
    risk_explanation: Mapping[str, Any] | None = None,
    documents: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble everything both renderers need."""
    controls = list((result.controls if result and result.controls else []) or [])
    assessment = dict((result.assessment if result and result.assessment else {}) or {})
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for finding in findings:
        severity = str(getattr(finding, "severity", "informational") or "informational").lower()
        counts[severity] = counts.get(severity, 0) + 1

    finding_rows = []
    for finding in sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(str(getattr(f, "severity", "")).lower(), 9),
            getattr(f, "title", "") or "",
        ),
    ):
        recommendation = finding.recommendations[0] if getattr(finding, "recommendations", None) else None
        finding_rows.append(
            {
                "id": str(finding.id),
                "control_id": finding.control_id or "-",
                "title": finding.title,
                "category": finding.category,
                "severity": str(finding.severity).lower(),
                "status": finding.status,
                "description": finding.description,
                "current_value": finding.current_value,
                "expected_value": finding.expected_value,
                "evidence": finding.evidence,
                "why_it_matters": (recommendation.why_it_matters if recommendation else ""),
                "recommendation": (
                    recommendation.what_should_be_done
                    if recommendation
                    else "Apply the baseline configuration for this control."
                ),
                "verify": (recommendation.verify_command if recommendation else None),
            }
        )

    controls_sorted = sorted(
        controls,
        key=lambda c: (STATE_ORDER.get(str(c.get("status")), 9), -int(c.get("weight", 0))),
    )

    return {
        "report_id": f"SCR-{str(scan.id)[:8].upper()}",
        "generated_at": datetime.now(UTC).isoformat(),
        "assessment": {
            "scan_id": str(scan.id),
            "source": scan.source,
            "status": scan.status,
            "stage": scan.stage,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_ms": scan.duration_ms,
            "scanner_version": scan.scanner_version,
            "scoring_model_version": scan.scoring_model_version or SCORING_MODEL_VERSION,
            "baseline_version": scan.baseline_version,
            "evidence_bytes": scan.evidence_bytes,
        },
        "device": {
            "hostname": getattr(device, "hostname", None) or "Unknown",
            "os_type": getattr(device, "os_type", None),
            "os_version": getattr(device, "os_version", None),
            "os_build": getattr(device, "os_build", None),
            "criticality": getattr(device, "criticality", 3),
            "criticality_label": _criticality_label(getattr(device, "criticality", 3)),
        },
        "scores": {
            "posture": result.security_score if result else None,
            "compliance": result.compliance_score if result else None,
            "coverage": result.assessment_coverage if result else 0,
            "risk": result.risk_score if result else 0,
            "risk_level": result.risk_level if result else "unknown",
            "evidence_quality": result.evidence_quality if result else "unavailable",
        },
        "assessment_meta": assessment,
        "baseline": {
            "id": getattr(baseline, "baseline_id", None),
            "version": getattr(baseline, "version", None),
            "title": getattr(baseline, "title", None),
            "references": list(getattr(baseline, "references", []) or []),
        },
        "findings_summary": counts,
        "finding_count": len(findings),
        "findings": finding_rows,
        "controls": controls_sorted,
        "risk": dict(risk_explanation or {}),
        "documents": dict(documents or {}),
    }


def _criticality_label(level: Any) -> str:
    try:
        value = int(level)
    except (TypeError, ValueError):
        value = 3
    return {1: "low", 2: "standard", 3: "standard", 4: "elevated", 5: "critical"}.get(value, "standard")


# --------------------------------------------------------------------------- HTML
HTML_CSS = """
:root{--ink:#0f1720;--muted:#5b6b7f;--line:#dfe5ec;--bg:#f5f7fa;--card:#fff;
--accent:#0b5cad;--crit:#a1121b;--high:#a34a00;--med:#7a5b00;--low:#0d6339;--info:#0b5cad}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:"Segoe UI",Inter,system-ui,Arial,sans-serif;line-height:1.55}
.page{max-width:1080px;margin:0 auto;padding:32px}
.cover{background:linear-gradient(135deg,#0d2136,#123c66);color:#fff;border-radius:18px;
padding:44px 48px}
.cover .kicker{letter-spacing:3px;text-transform:uppercase;font-size:12px;opacity:.85}
.cover h1{font-size:38px;margin:10px 0 6px;line-height:1.1}
.cover .meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;
margin-top:22px}
.cover .meta div{background:#ffffff14;border:1px solid #ffffff2b;border-radius:10px;
padding:10px 12px;font-size:13px}
section{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:22px 24px;margin-top:20px}
h2{font-size:19px;margin:0 0 14px}
h3{font-size:15px;margin:18px 0 6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top}
th{background:#123c66;color:#fff;font-size:11px;text-transform:uppercase;
letter-spacing:.6px}
tbody tr:nth-child(even){background:#fafbfd}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.metric{border:1px solid var(--line);border-radius:12px;padding:14px}
.metric .num{font-size:26px;font-weight:700}
.metric .label{font-size:12px;color:var(--muted)}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;
font-weight:600;border:1px solid transparent}
.s-compliant{background:#e9f7ef;color:var(--low);border-color:#bfe6cf}
.s-non_compliant{background:#fdeeee;color:var(--crit);border-color:#f3c9c9}
.s-unknown{background:#f2f4f7;color:var(--muted);border-color:#dde3ea}
.s-error{background:#fff4e5;color:var(--high);border-color:#f2d9b5}
.s-not_applicable{background:#eef2f7;color:#455a75;border-color:#d7e0ea}
.sev-critical{color:var(--crit);font-weight:700}
.sev-high{color:var(--high);font-weight:700}
.sev-medium{color:var(--med);font-weight:700}
.sev-low{color:var(--low);font-weight:700}
pre{background:#0f1720;color:#e8eef7;border-radius:10px;padding:12px 14px;
overflow-x:auto;font-size:12px;font-family:Consolas,"Cascadia Mono",monospace}
.muted{color:var(--muted);font-size:12px}
.finding{border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-top:14px}
.finding h3{margin-top:0}
.callout{border-left:4px solid var(--accent);background:#eef5fd;border-radius:8px;
padding:12px 14px;font-size:13px;margin-top:12px}
.footer{margin-top:22px;color:var(--muted);font-size:11px;text-align:center}
"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def render_html(data: Mapping[str, Any]) -> str:
    scores = data["scores"]
    device = data["device"]
    meta = data.get("assessment_meta") or {}
    findings = data["findings"]
    controls = data["controls"]

    finding_rows = (
        "".join(
            f"<tr><td><code>{_esc(f['control_id'])}</code></td><td>{_esc(f['title'])}</td>"
            f"<td>{_esc(f['category'])}</td>"
            f"<td class='sev-{_esc(f['severity'])}'>{_esc(f['severity'].upper())}</td></tr>"
            for f in findings
        )
        or "<tr><td colspan='4' class='muted'>No findings.</td></tr>"
    )

    control_rows = (
        "".join(
            f"<tr><td><code>{_esc(c.get('control_id'))}</code></td>"
            f"<td>{_esc(c.get('title'))}</td><td>{_esc(c.get('category'))}</td>"
            f"<td>{_esc(c.get('weight'))}</td>"
            f"<td><span class='badge s-{_esc(c.get('status'))}'>{_esc(c.get('status'))}</span></td>"
            f"<td class='muted'>{
                _esc(', '.join(r.get('standard', '') for r in (c.get('standard_refs') or [])))
            }</td></tr>"
            for c in controls
        )
        or "<tr><td colspan='6' class='muted'>No controls.</td></tr>"
    )

    reference_rows = "".join(
        f"<tr><td>{_esc(r.get('standard'))}</td><td>{_esc(r.get('control'))}</td>"
        f"<td class='muted'>{_esc(r.get('url'))}</td></tr>"
        for r in (data.get("baseline", {}).get("references") or [])
    )

    risk_rows = "".join(
        f"<tr><td><code>{_esc(c.get('control_id'))}</code></td><td>{_esc(c.get('severity'))}</td>"
        f"<td>{_esc(c.get('category'))}</td><td>{_esc(c.get('impact'))}</td>"
        f"<td>{_esc(c.get('contribution'))}%</td></tr>"
        for c in (data.get("risk", {}).get("contributions") or [])[:12]
    )

    detail_blocks = "".join(
        f"<div class='finding'><h3>{_esc(f['control_id'])} â€” {_esc(f['title'])}</h3>"
        f"<p class='muted'>{_esc(f['category'])} Â· {_esc(f['severity'].upper())} Â· "
        f"{_esc(f['status'])}</p>"
        f"<p>{_esc(f['description'] or '')}</p>"
        f"<h3>Observed</h3><pre>{_esc(_json_text(f['current_value']))}</pre>"
        f"<h3>Expected</h3><pre>{_esc(_json_text(f['expected_value']))}</pre>"
        f"<h3>Evidence</h3><pre>{_esc(_json_text(f['evidence']))}</pre>"
        f"<h3>Why it matters</h3><p>{_esc(f['why_it_matters'])}</p>"
        f"<h3>Recommended action</h3><p>{_esc(f['recommendation'])}</p>"
        + (f"<h3>Verify</h3><pre>{_esc(f['verify'])}</pre>" if f.get("verify") else "")
        + "</div>"
        for f in findings
    ) or ("<div class='callout'>No non-compliant controls were recorded in this assessment.</div>")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureConfigAI assessment {_esc(data["report_id"])}</title>
<style>{HTML_CSS}</style></head><body><main class="page">
<div class="cover"><div class="kicker">SecureConfigAI Â· endpoint security assessment</div>
<h1>{_esc(device["hostname"])}</h1>
<p class="muted" style="color:#cfe0f2">Deterministic control assessment rendered from
stored evidence. AI content is advisory and cannot change a score.</p>
<div class="meta">
<div><strong>Report</strong><br>{_esc(data["report_id"])}</div>
<div><strong>Assessed</strong><br>{_esc(data["assessment"]["completed_at"] or "in progress")}</div>
<div><strong>Baseline</strong><br>{_esc(data["baseline"]["title"])} v{_esc(data["baseline"]["version"])}</div>
<div><strong>Scoring model</strong><br>{_esc(data["assessment"]["scoring_model_version"])}</div>
<div><strong>Asset criticality</strong><br>{_esc(device["criticality"])}
  ({_esc(device["criticality_label"])})</div>
<div><strong>Duration</strong><br>{_esc(round((data["assessment"]["duration_ms"] or 0) / 1000, 1))} s</div>
</div></div>

<section><h2>Executive summary</h2>
<div class="metrics">
<div class="metric"><div class="num">{_esc(_score(scores["posture"]))}</div>
<div class="label">Security posture / 100</div></div>
<div class="metric"><div class="num">{_esc(scores["coverage"])}%</div>
<div class="label">Assessment coverage</div></div>
<div class="metric"><div class="num">{_esc(scores["risk"])}</div>
<div class="label">Risk score Â· {_esc(str(scores["risk_level"]).upper())}</div></div>
<div class="metric"><div class="num">{_esc(scores["evidence_quality"])}</div>
<div class="label">Evidence quality</div></div>
<div class="metric"><div class="num">{_esc(len(findings))}</div>
<div class="label">Non-compliant controls</div></div>
</div>
<div class="callout">Posture is computed only from controls that produced evidence:
<b>{_esc(meta.get("assessed_controls"))}</b> of <b>{_esc(meta.get("total_controls"))}</b>
controls were assessed, <b>{_esc(meta.get("unknown_or_error_controls"))}</b> could not be
determined from the collected evidence and are reported as unknown or error rather than
as failures. Coverage is shown separately for exactly this reason.</div></section>

<section><h2>Findings</h2>
<table><thead><tr><th>Control</th><th>Title</th><th>Category</th><th>Severity</th></tr></thead>
<tbody>{finding_rows}</tbody></table></section>

<section><h2>Control assessment</h2>
<table><thead><tr><th>ID</th><th>Control</th><th>Category</th><th>Weight</th><th>Status</th>
<th>Standards</th></tr></thead><tbody>{control_rows}</tbody></table></section>

<section><h2>Risk derivation</h2>
<p class="muted">{_esc((data.get("risk") or {}).get("formula", ""))}</p>
<p>Per-control impact = severity impact x category exposure x asset criticality / 125,
combined with a noisy-OR: <b>risk = 100 x (1 - product(1 - L x impact))</b> where
L = {_esc((data.get("risk") or {}).get("likelihood_factor"))}.
Asset criticality for this device is {_esc((data.get("risk") or {}).get("criticality"))}.</p>
<table><thead><tr><th>Control</th><th>Severity</th><th>Category</th><th>Impact</th>
<th>Contribution</th></tr></thead><tbody>{
        risk_rows or "<tr><td colspan='5' class='muted'>No non-compliant controls.</td></tr>"
    }</tbody></table></section>

<section><h2>Detailed findings</h2>{detail_blocks}</section>

<section><h2>Standards referenced by the baseline</h2>
<table><thead><tr><th>Standard</th><th>Control</th><th>Reference</th></tr></thead>
<tbody>{reference_rows}</tbody></table>
<p class="muted">{_esc(data["baseline"].get("id"))} v{_esc(data["baseline"].get("version"))}.
Benchmark recommendation numbering is intentionally not asserted because it changes
between benchmark revisions; the Windows setting name is the stable identifier.</p></section>

<div class="footer">Generated by SecureConfigAI {_esc(data["generated_at"])} Â·
Assessment artifact only â€” it does not execute remediation.</div>
</main></body></html>"""


# --------------------------------------------------------------------------- PDF
def render_pdf(data: Mapping[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    scores = data["scores"]
    device = data["device"]
    meta = data.get("assessment_meta") or {}
    findings = data["findings"]
    controls = data["controls"]

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "T", parent=styles["Title"], fontSize=23, leading=27, textColor=colors.HexColor("#0d2136")
    )
    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0b5cad"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body = ParagraphStyle(
        "B", parent=styles["BodyText"], fontSize=9.3, leading=13.4, textColor=colors.HexColor("#1f2b3a")
    )
    small = ParagraphStyle("S", parent=body, fontSize=8, leading=11, textColor=colors.HexColor("#5b6b7f"))
    mono = ParagraphStyle(
        "M",
        parent=body,
        fontName="Courier",
        fontSize=6.9,
        leading=8.8,
        backColor=colors.HexColor("#f2f4f7"),
        borderPadding=5,
    )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"SecureConfigAI assessment {data['report_id']}",
        author="SecureConfigAI",
    )
    story: list[Any] = []
    story += [
        Paragraph(
            "SECURECONFIGAI",
            ParagraphStyle("K", parent=body, fontSize=10, textColor=colors.HexColor("#0b5cad")),
        ),
        Paragraph(f"{device['hostname']} â€” endpoint security assessment", title),
        Paragraph(
            f"Report {data['report_id']} Â· baseline {data['baseline']['title']} "
            f"v{data['baseline']['version']} Â· scoring model "
            f"{data['assessment']['scoring_model_version']}<br/>"
            f"Assessed {data['assessment']['completed_at'] or 'in progress'} Â· "
            f"duration {round((data['assessment']['duration_ms'] or 0) / 1000, 1)} s Â· "
            f"asset criticality {device['criticality']} ({device['criticality_label']})",
            small,
        ),
        Spacer(1, 6 * mm),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dfe5ec")),
        Spacer(1, 4 * mm),
    ]

    metrics = [
        ["Security posture", "Assessment coverage", "Risk score", "Evidence quality"],
        [
            _score(scores["posture"]),
            f"{scores['coverage']}%",
            f"{scores['risk']} ({str(scores['risk_level']).upper()})",
            str(scores["evidence_quality"]),
        ],
    ]
    table = Table(metrics, colWidths=[45 * mm] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123c66")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dfe5ec")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dfe5ec")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story += [table, Spacer(1, 5 * mm)]
    story += [
        Paragraph(
            f"Posture is computed only from controls that produced evidence: "
            f"{meta.get('assessed_controls')} of {meta.get('total_controls')} controls were "
            f"assessed and {meta.get('unknown_or_error_controls')} could not be determined, so "
            f"they are reported as unknown or error rather than as failures. Coverage is "
            f"reported separately for exactly that reason.",
            body,
        )
    ]

    story += [Paragraph("Findings", h2)]
    rows = [["Control", "Finding", "Category", "Severity"]]
    rows += [[f["control_id"], f["title"][:58], f["category"], f["severity"].upper()] for f in findings] or [
        ["-", "No findings recorded", "-", "-"]
    ]
    ft = Table(rows, colWidths=[22 * mm, 88 * mm, 38 * mm, 22 * mm], repeatRows=1)
    ft.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123c66")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.6),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dfe5ec")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfd")]),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story += [ft, PageBreak()]

    story += [Paragraph("Control assessment", h2)]
    control_rows = [["ID", "Control", "Category", "W", "Status"]]
    control_rows += [
        [
            str(c.get("control_id")),
            str(c.get("title"))[:52],
            str(c.get("category")),
            str(c.get("weight")),
            str(c.get("status")),
        ]
        for c in controls
    ]
    ct = Table(control_rows, colWidths=[20 * mm, 78 * mm, 38 * mm, 9 * mm, 25 * mm], repeatRows=1)
    ct.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123c66")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#dfe5ec")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story += [ct]

    story += [
        Paragraph("Risk derivation", h2),
        Paragraph(
            f"Per-control impact = severity impact x category exposure x asset criticality / 125. "
            f"Impacts are combined with a noisy-OR: risk = 100 x (1 - product(1 - L x impact)), "
            f"L = {data.get('risk', {}).get('likelihood_factor')}, asset criticality "
            f"{data.get('risk', {}).get('criticality')}. This is a documented project "
            f"methodology, not an official NIST or CIS formula.",
            body,
        ),
    ]
    risk_rows = [["Control", "Severity", "Category", "Impact", "Contribution"]]
    risk_rows += [
        [
            str(c.get("control_id")),
            str(c.get("severity")),
            str(c.get("category")),
            str(c.get("impact")),
            f"{c.get('contribution')}%",
        ]
        for c in (data.get("risk", {}).get("contributions") or [])[:12]
    ]
    if len(risk_rows) > 1:
        rt = Table(risk_rows, colWidths=[24 * mm, 24 * mm, 44 * mm, 24 * mm, 30 * mm], repeatRows=1)
        rt.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123c66")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.4),
                    ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#dfe5ec")),
                    ("PADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story += [rt]
    story += [PageBreak(), Paragraph("Detailed findings", h2)]

    for finding in findings:
        block = [
            Paragraph(
                f"{_esc(finding['control_id'])} — {_esc(finding['title'])}",
                ParagraphStyle("FH", parent=h2, fontSize=11),
            ),
            Paragraph(
                f"<b>Severity:</b> {finding['severity'].upper()} &nbsp;&nbsp; "
                f"<b>Category:</b> {_esc(finding['category'])} &nbsp;&nbsp; "
                f"<b>Status:</b> {finding['status']}",
                small,
            ),
            # V4 fix (L-8): ReportLab paragraphs parse a mini-XML markup, so text that
            # originates from an uploaded snapshot must be escaped exactly like the
            # HTML path. Unescaped <, & or a malformed tag could abort the report
            # build (repeated 500s under the report cache) or inject styling into
            # the rendered PDF.
            Paragraph(_esc(finding["description"]) or "", body),
            Paragraph("Observed", styles["Heading4"]),
            Paragraph(_esc(str(_json_text(finding["current_value"]))).replace("\n", "<br/>"), mono),
            Paragraph("Expected", styles["Heading4"]),
            Paragraph(_esc(str(_json_text(finding["expected_value"]))).replace("\n", "<br/>"), mono),
            Paragraph("Evidence", styles["Heading4"]),
            Paragraph(_esc(str(_json_text(finding["evidence"]))).replace("\n", "<br/>"), mono),
            Paragraph("Why it matters", styles["Heading4"]),
            Paragraph(_esc(finding["why_it_matters"]) or "", body),
            Paragraph("Recommended action", styles["Heading4"]),
            Paragraph(_esc(finding["recommendation"]) or "", body),
        ]
        if finding.get("verify"):
            block += [
                Paragraph("Verify", styles["Heading4"]),
                Paragraph(_esc(str(finding["verify"])).replace("\n", "<br/>"), mono),
            ]
        block.append(Spacer(1, 4 * mm))
        story.append(KeepTogether(block))

    references = data.get("baseline", {}).get("references") or []
    story += [PageBreak(), Paragraph("Standards referenced by the baseline", h2)]
    ref_rows = [["Standard", "Control", "Reference"]]
    ref_rows += [[str(r.get("standard")), str(r.get("control")), str(r.get("url") or "")] for r in references]
    reft = Table(ref_rows, colWidths=[38 * mm, 82 * mm, 50 * mm], repeatRows=1)
    reft.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123c66")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 6.8),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#dfe5ec")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story += [
        reft,
        Spacer(1, 4 * mm),
        Paragraph(
            "Benchmark recommendation numbering is intentionally not asserted because it "
            "changes between benchmark revisions; the Windows setting name is the stable "
            "identifier.",
            small,
        ),
    ]
    story += [
        Spacer(1, 6 * mm),
        HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#dfe5ec")),
        Spacer(1, 2 * mm),
        Paragraph(
            f"Generated by SecureConfigAI {data['generated_at']}. This report is an "
            f"assessment artifact; it does not execute remediation.",
            small,
        ),
    ]

    def footer(canvas, doc_obj):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5b6b7f"))
        canvas.drawString(15 * mm, 8 * mm, f"SecureConfigAI Â· {data['report_id']}")
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc_obj.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return path
