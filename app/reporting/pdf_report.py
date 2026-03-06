"""
PDF Report Generator
Produces a formatted A4 PDF compliance report from an AuditResult
using ReportLab Platypus.

Structure:
  Page 1 — Executive Summary: score, rating, rule counts, findings by
            severity/type, and full audit summary text.
  Page 2+ — Findings Detail: one row per finding, colour-coded by severity.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

if TYPE_CHECKING:
    from app.validation.engine import AuditResult

# ── Palette ────────────────────────────────────────────────────────────────────

_NAVY       = colors.HexColor("#1F3864")
_NAVY_LIGHT = colors.HexColor("#D6DCF0")
_WHITE      = colors.white
_GRAY_BG    = colors.HexColor("#F0F2F5")
_GRAY_TEXT  = colors.HexColor("#595959")

_SEV_BG = {
    "CRITICAL": colors.HexColor("#FF4C4C"),
    "HIGH":     colors.HexColor("#FF8C00"),
    "MEDIUM":   colors.HexColor("#FFD700"),
    "LOW":      colors.HexColor("#70AD47"),
}
_SEV_FG = {
    "CRITICAL": colors.white,
    "HIGH":     colors.white,
    "MEDIUM":   colors.black,
    "LOW":      colors.white,
}
_SEV_TINT = {
    "CRITICAL": colors.HexColor("#FFE5E5"),
    "HIGH":     colors.HexColor("#FFF0E0"),
    "MEDIUM":   colors.HexColor("#FFFBE6"),
    "LOW":      colors.HexColor("#F0F9ED"),
}

_SCORE_BG = {
    "COMPLIANT":           colors.HexColor("#70AD47"),
    "PARTIALLY COMPLIANT": colors.HexColor("#FFD700"),
    "NON-COMPLIANT":       colors.HexColor("#FF4C4C"),
}
_SCORE_FG = {
    "COMPLIANT":           colors.white,
    "PARTIALLY COMPLIANT": colors.black,
    "NON-COMPLIANT":       colors.white,
}

# ── Page geometry ──────────────────────────────────────────────────────────────

_PAGE_W, _PAGE_H = A4              # 595 × 842 pt
_MARGIN = 1.8 * cm
_USABLE_W = _PAGE_W - 2 * _MARGIN  # ≈ 457 pt


# ── Paragraph styles ───────────────────────────────────────────────────────────

def _styles() -> dict:
    return {
        "title": ParagraphStyle(
            "rpt_title",
            fontName="Helvetica-Bold", fontSize=18,
            textColor=_NAVY, alignment=TA_CENTER, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "rpt_subtitle",
            fontName="Helvetica", fontSize=9,
            textColor=_GRAY_TEXT, alignment=TA_CENTER, spaceAfter=14,
        ),
        "section_hdr": ParagraphStyle(
            "rpt_sec",
            fontName="Helvetica-Bold", fontSize=10,
            textColor=_WHITE, backColor=_NAVY,
            alignment=TA_LEFT, leftIndent=0,
            spaceBefore=10, spaceAfter=2,
            borderPadding=(4, 6, 4, 6),
        ),
        "kv_label": ParagraphStyle(
            "rpt_kv_label",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=_NAVY,
        ),
        "kv_value": ParagraphStyle(
            "rpt_kv_value",
            fontName="Helvetica", fontSize=9,
            textColor=colors.black,
        ),
        "cell": ParagraphStyle(
            "rpt_cell",
            fontName="Helvetica", fontSize=8, leading=11,
        ),
        "cell_bold": ParagraphStyle(
            "rpt_cell_bold",
            fontName="Helvetica-Bold", fontSize=8, leading=11,
        ),
        "summary_text": ParagraphStyle(
            "rpt_summary",
            fontName="Helvetica", fontSize=9, leading=13,
            textColor=_GRAY_TEXT, spaceAfter=4,
        ),
        "page2_title": ParagraphStyle(
            "rpt_p2_title",
            fontName="Helvetica-Bold", fontSize=14,
            textColor=_NAVY, alignment=TA_LEFT, spaceAfter=6,
        ),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf_report(result: "AuditResult") -> bytes:
    """
    Build a PDF compliance report from *result* and return the raw bytes.

    Args:
        result: AuditResult produced by ``app.validation.engine.run_audit``.

    Returns:
        Raw PDF bytes ready to be written to disk or streamed as an HTTP response.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=_MARGIN, rightMargin=_MARGIN,
        topMargin=_MARGIN, bottomMargin=_MARGIN,
        title="Firewall Compliance Audit Report",
    )

    st = _styles()
    story = []

    _build_summary_page(story, st, result)
    story.append(PageBreak())
    _build_findings_page(story, st, result)

    doc.build(story)
    return buf.getvalue()


# ── Page 1: Executive Summary ─────────────────────────────────────────────────

def _build_summary_page(story: list, st: dict, result: "AuditResult") -> None:
    story.append(Paragraph("Firewall Compliance Audit Report", st["title"]))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        st["subtitle"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=_NAVY, spaceAfter=12))

    # ── Compliance score box ───────────────────────────────────────────
    score = result.compliance_score
    rating = (
        "COMPLIANT"           if score >= 90 else
        "PARTIALLY COMPLIANT" if score >= 70 else
        "NON-COMPLIANT"
    )
    bg = _SCORE_BG[rating]
    fg = _SCORE_FG[rating]

    score_style = ParagraphStyle(
        "score_num",
        fontName="Helvetica-Bold", fontSize=36,
        textColor=fg, alignment=TA_CENTER,
    )
    rating_style = ParagraphStyle(
        "score_rating",
        fontName="Helvetica-Bold", fontSize=12,
        textColor=fg, alignment=TA_CENTER,
    )

    score_tbl = Table(
        [[Paragraph(f"{score:.1f}%", score_style)],
         [Paragraph(rating, rating_style)]],
        colWidths=[_USABLE_W],
        rowHeights=[48, 24],
    )
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 10))

    # ── Rule counts ───────────────────────────────────────────────────
    story.append(_section_header("AUDIT OVERVIEW", st))
    counts_data = [
        ["Firewall Rules Audited",   str(result.total_firewall_rules)],
        ["Policy Matrix Entries",    str(result.total_policy_rules)],
        ["Total Findings",           str(len(result.findings))],
    ]
    story.append(_kv_table(counts_data, st))
    story.append(Spacer(1, 6))

    # ── Findings by severity ──────────────────────────────────────────
    story.append(_section_header("FINDINGS BY SEVERITY", st))
    sev_rows = [["Severity", "Count"]]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = result.findings_by_severity.get(sev, 0)
        sev_rows.append([sev, str(count)])

    sev_tbl = Table(sev_rows, colWidths=[_USABLE_W * 0.6, _USABLE_W * 0.4])
    sev_style = [
        ("BACKGROUND",  (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR",   (0, 0), (-1, 0), _WHITE),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_GRAY_BG, _WHITE]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#C5CFE0")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]
    for row_idx, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW"), start=1):
        sev_style.append(("BACKGROUND",  (0, row_idx), (0, row_idx), _SEV_BG[sev]))
        sev_style.append(("TEXTCOLOR",   (0, row_idx), (0, row_idx), _SEV_FG[sev]))
        sev_style.append(("FONTNAME",    (0, row_idx), (0, row_idx), "Helvetica-Bold"))
    sev_tbl.setStyle(TableStyle(sev_style))
    story.append(sev_tbl)
    story.append(Spacer(1, 6))

    # ── Findings by type ──────────────────────────────────────────────
    if result.findings_by_type:
        story.append(_section_header("FINDINGS BY TYPE", st))
        type_rows = [["Finding Type", "Count"]]
        for ftype, count in sorted(result.findings_by_type.items()):
            type_rows.append([ftype.replace("_", " "), str(count)])
        type_tbl = Table(type_rows, colWidths=[_USABLE_W * 0.7, _USABLE_W * 0.3])
        type_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), _NAVY),
            ("TEXTCOLOR",   (0, 0), (-1, 0), _WHITE),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("ALIGN",       (1, 0), (1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_GRAY_BG, _WHITE]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#C5CFE0")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(type_tbl)
        story.append(Spacer(1, 6))

    # ── Summary text ──────────────────────────────────────────────────
    if result.summary:
        story.append(_section_header("AUDIT SUMMARY", st))
        story.append(Paragraph(result.summary, st["summary_text"]))


# ── Page 2+: Findings Detail ──────────────────────────────────────────────────

# Column widths (total = _USABLE_W ≈ 457 pt)
_FIND_COLS = [22, 52, 85, 95, 112, 91]   # #, Sev, Rule, Type, Desc, Remediation

def _build_findings_page(story: list, st: dict, result: "AuditResult") -> None:
    story.append(Paragraph("Findings Detail", st["page2_title"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_NAVY, spaceAfter=8))

    _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_ORDER.get(f.severity, 9), f.rule_name or ""),
    )

    headers = ["#", "Severity", "Rule Name", "Finding Type", "Description", "Remediation"]
    rows = [headers]

    for i, f in enumerate(sorted_findings, start=1):
        rows.append([
            str(i),
            f.severity,
            f.rule_name or "—",
            (f.finding_type or "").replace("_", " "),
            f.description or "",
            f.remediation or "",
        ])

    if not sorted_findings:
        rows.append(["—", "—", "—", "—", "No compliance findings — rulebase is fully compliant.", "—"])

    # Convert long text cells to Paragraphs so they wrap
    para_rows = []
    for row_idx, row in enumerate(rows):
        para_row = []
        for col_idx, cell in enumerate(row):
            if row_idx == 0:
                p = Paragraph(str(cell), ParagraphStyle(
                    "th", fontName="Helvetica-Bold", fontSize=8,
                    textColor=_WHITE, leading=10,
                ))
            else:
                p = Paragraph(str(cell), ParagraphStyle(
                    "td", fontName="Helvetica", fontSize=7,
                    textColor=colors.black, leading=10,
                ))
            para_row.append(p)
        para_rows.append(para_row)

    tbl = Table(para_rows, colWidths=_FIND_COLS, repeatRows=1)

    # Base style
    tbl_style = [
        # Header row
        ("BACKGROUND",    (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), _WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#C5CFE0")),
        # Center the # and Severity columns
        ("ALIGN",         (0, 1), (0, -1), "CENTER"),
        ("ALIGN",         (1, 1), (1, -1), "CENTER"),
    ]

    # Per-row severity tints and severity-cell colours
    for row_idx, finding in enumerate(sorted_findings, start=1):
        sev = finding.severity
        tint = _SEV_TINT.get(sev)
        if tint:
            # Tint all columns except the severity badge column
            for col in [0, 2, 3, 4, 5]:
                tbl_style.append(("BACKGROUND", (col, row_idx), (col, row_idx), tint))
        # Severity cell: solid colour + matching text colour
        tbl_style.append(("BACKGROUND", (1, row_idx), (1, row_idx), _SEV_BG.get(sev, _WHITE)))
        tbl_style.append(("TEXTCOLOR",  (1, row_idx), (1, row_idx), _SEV_FG.get(sev, colors.black)))
        tbl_style.append(("FONTNAME",   (1, row_idx), (1, row_idx), "Helvetica-Bold"))

    tbl.setStyle(TableStyle(tbl_style))
    story.append(tbl)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _section_header(text: str, st: dict) -> Table:
    """A full-width navy header row used as a section separator."""
    tbl = Table(
        [[Paragraph(text, st["section_hdr"])]],
        colWidths=[_USABLE_W],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    return tbl


def _kv_table(rows: list, st: dict) -> Table:
    """Two-column label/value table for the summary page stats."""
    tbl_data = [
        [Paragraph(label, st["kv_label"]), Paragraph(value, st["kv_value"])]
        for label, value in rows
    ]
    tbl = Table(tbl_data, colWidths=[_USABLE_W * 0.6, _USABLE_W * 0.4])
    tbl.setStyle(TableStyle([
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_GRAY_BG, _WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#C5CFE0")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("ALIGN",         (1, 0), (1, -1), "CENTER"),
    ]))
    return tbl
