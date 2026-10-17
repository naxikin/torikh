"""Dashboard PDF export (ReportLab, clearnet-independent)."""
from __future__ import annotations

import io
from typing import Dict

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def _short(value, limit: int = 110) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_dashboard_pdf(data: Dict[str, object], generated_at: str,
                        version: str) -> bytes:
    buffer = io.BytesIO()
    doc = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    left = 18 * mm
    y = height - 20 * mm

    def new_page() -> None:
        nonlocal y
        doc.showPage()
        doc.setFont("Helvetica", 9)
        y = height - 20 * mm

    def ensure(space: float = 20 * mm) -> None:
        if y < space:
            new_page()

    def text(value: str, size: int = 10, gap: float = 6,
             font: str = "Helvetica", color=(0.1, 0.12, 0.16)) -> None:
        nonlocal y
        ensure()
        doc.setFillColorRGB(*color)
        doc.setFont(font, size)
        doc.drawString(left, y, _short(value, 112))
        y -= gap

    def heading(value: str) -> None:
        nonlocal y
        ensure(28 * mm)
        y -= 4
        doc.setFillColorRGB(0.22, 0.26, 0.32)
        doc.setFont("Helvetica-Bold", 12)
        doc.drawString(left, y, _short(value, 80))
        y -= 15

    def rule() -> None:
        nonlocal y
        ensure()
        doc.setStrokeColorRGB(0.82, 0.85, 0.88)
        doc.line(left, y + 2, width - left, y + 2)
        y -= 10

    # Header
    doc.setFillColorRGB(0.96, 0.62, 0.04)
    doc.rect(left, y - 3, 5 * mm, 5 * mm, fill=1, stroke=0)
    doc.setFillColorRGB(0.1, 0.12, 0.16)
    doc.setFont("Helvetica-Bold", 18)
    doc.drawString(left + 8 * mm, y - 1, "XIKIN")
    doc.setFont("Helvetica", 9)
    doc.drawString(left + 8 * mm, y - 11, "dark-web OSINT dashboard report")
    y -= 24

    text("Generated: %s" % generated_at, 9, 12, color=(0.35, 0.4, 0.46))
    text("Tool version: xikin %s" % version, 9, 12, color=(0.35, 0.4, 0.46))
    rule()

    stats = data.get("stats") or {}
    heading("Overview")
    for label, key in (("Investigations", "runs"), ("Results collected", "results"),
                       ("Indicators", "indicators"), ("Evidence records", "evidence")):
        text("%-22s %s" % (label, stats.get(key, 0)), 10, 13)

    evidence = data.get("evidence") or {}
    text("Evidence chain: %s (%s records)"
         % ("verified" if evidence.get("ok") else "BROKEN",
            evidence.get("entries", 0)), 10, 13)
    rule()

    alerts = data.get("alerts") or []
    heading("Needs attention")
    if alerts:
        for alert in alerts:
            text("[%s] %s" % (str(alert.get("level", "warn")).upper(),
                              alert.get("text", "")), 9.5, 12)
    else:
        text("No open alerts.", 9.5, 12)

    watch_jobs = data.get("watch_jobs") or []
    heading("Monitoring")
    text("Watch jobs: %d (active %s) — new findings: %s"
         % (len(watch_jobs), data.get("watch_enabled", 0),
            data.get("watch_new_total", 0)), 10, 13)
    for job in watch_jobs[:10]:
        text("· %s [%s] every %s h — last: %s"
             % (_short(job.get("query"), 60), job.get("mode"),
                job.get("interval_hours") or 0,
                "never" if not job.get("last_run") else "recorded"), 9, 11)

    activity = data.get("activity") or []
    if activity:
        heading("Activity (last 14 days)")
        text("  ".join("%s:%s" % (day["label"], day["count"]) for day in activity),
             8.5, 14)

    runs = data.get("runs") or []
    heading("Recent investigations")
    if runs:
        for run in runs:
            text("[%s] %s — %s results / %s indicators"
                 % (str(run.get("status", "?")).upper(),
                    _short(run.get("query"), 60),
                    run.get("results_count", 0),
                    run.get("indicator_count", 0)), 9.5, 12)
    else:
        text("No investigations yet.", 9.5, 12)

    rule()
    text("Content safety filter active. Secrets masked. For lawful OSINT, "
         "threat intelligence and security research only.", 8,
         10, color=(0.35, 0.4, 0.46))

    doc.save()
    return buffer.getvalue()
