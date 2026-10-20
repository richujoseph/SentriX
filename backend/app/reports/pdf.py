"""Render an incident to a PDF report with reportlab.

Takes the same data as ``GET /incidents/{id}`` (an ``IncidentDetail`` dumped to
a dict), so the report matches what the dashboard shows. The timeline is
grouped like the frontend's: consecutive identical alerts collapse into one
row, and the tactic is shown where it changes.
"""

from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Must match FALLBACK_PREFIX in app/llm/summarizer.py.
FALLBACK_PREFIX = "[Automatic summary unavailable]"

SLATE_900 = colors.HexColor("#0f172a")
SLATE_700 = colors.HexColor("#334155")
SLATE_500 = colors.HexColor("#64748b")
SLATE_200 = colors.HexColor("#e2e8f0")
SLATE_50 = colors.HexColor("#f8fafc")
BLUE_600 = colors.HexColor("#2563eb")
BLUE_50 = colors.HexColor("#eff6ff")

# Same bands as the dashboard (frontend/src/severity.js).
SEVERITY_BANDS = [
    (75, "Critical", colors.HexColor("#dc2626")),
    (50, "High", colors.HexColor("#ea580c")),
    (25, "Medium", colors.HexColor("#ca8a04")),
    (0, "Low", colors.HexColor("#0284c7")),
]
ALERT_SEVERITY_COLORS = {
    1: colors.HexColor("#dc2626"),
    2: colors.HexColor("#ea580c"),
    3: colors.HexColor("#ca8a04"),
    4: colors.HexColor("#0284c7"),
}

base = getSampleStyleSheet()
STYLES = {
    "title": ParagraphStyle("title", parent=base["Title"], fontSize=20, leading=24, alignment=TA_LEFT, textColor=SLATE_900, spaceAfter=2),
    "subtitle": ParagraphStyle("subtitle", parent=base["Normal"], fontSize=9, textColor=SLATE_500),
    "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12, leading=15, textColor=SLATE_900, spaceBefore=14, spaceAfter=6),
    "body": ParagraphStyle("body", parent=base["Normal"], fontSize=10, leading=14.5, textColor=SLATE_900),
    "small": ParagraphStyle("small", parent=base["Normal"], fontSize=8.5, leading=11, textColor=SLATE_700),
    "muted": ParagraphStyle("muted", parent=base["Normal"], fontSize=8.5, leading=11, textColor=SLATE_500),
    "label": ParagraphStyle("label", parent=base["Normal"], fontSize=7.5, leading=9, textColor=SLATE_500),
    "action": ParagraphStyle("action", parent=base["Normal"], fontSize=10.5, leading=14.5, textColor=colors.HexColor("#1e3a8a")),
    "notice": ParagraphStyle("notice", parent=base["Normal"], fontSize=8.5, leading=11, textColor=colors.HexColor("#854d0e")),
}


def p(text: Any, style: str = "body") -> Paragraph:
    """A paragraph of plain text. Escapes it, since reportlab parses markup and
    alert signatures or hostnames could contain '<' or '&'."""
    return Paragraph(escape("" if text is None else str(text)), STYLES[style])


def severity_band(score: float) -> tuple[str, colors.Color]:
    for minimum, label, color in SEVERITY_BANDS:
        if score >= minimum:
            return label, color
    return SEVERITY_BANDS[-1][1], SEVERITY_BANDS[-1][2]


def as_datetime(value: datetime | str) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def fmt_dt(value: datetime | str | None, suffix: bool = True) -> str:
    if value is None:
        return "-"
    text = as_datetime(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f"{text} UTC" if suffix else text


def fmt_time(value: datetime | str) -> str:
    return as_datetime(value).astimezone(timezone.utc).strftime("%H:%M:%S")


def fmt_duration(start: datetime | str, end: datetime | str | None) -> str:
    seconds = max(0.0, (as_datetime(end or start) - as_datetime(start)).total_seconds())
    if seconds < 60:
        return f"{round(seconds)}s"
    if seconds < 3600:
        return f"{round(seconds / 60)}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def timeline_rows(alerts: list[dict[str, Any]], tactics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse consecutive identical alerts (same signature, target and tactic) into rows."""
    tactic_by_alert = {aid: t for t in tactics for aid in t["alert_ids"]}
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        tactic = tactic_by_alert.get(alert["id"])
        last = rows[-1] if rows else None
        if (
            last
            and last["signature"] == alert["signature"]
            and last["dest_ip"] == alert["dest_ip"]
            and last["tactic"] is tactic
        ):
            last["count"] += 1
            last["end"] = alert["timestamp"]
            if alert["dest_port"] is not None:
                last["ports"].add(alert["dest_port"])
            if alert["severity"] is not None:
                last["severity"] = min(last["severity"] or 9, alert["severity"])
            continue
        rows.append(
            {
                "tactic": tactic,
                "signature": alert["signature"],
                "dest_ip": alert["dest_ip"],
                "ports": {alert["dest_port"]} if alert["dest_port"] is not None else set(),
                "severity": alert["severity"],
                "start": alert["timestamp"],
                "end": alert["timestamp"],
                "count": 1,
            }
        )
    return rows


def target_label(ip: str | None, ports: set[int]) -> str:
    if not ip:
        return "-"
    ordered = sorted(ports)
    if not ordered:
        return ip
    if len(ordered) <= 3:
        return f"{ip}:{', '.join(map(str, ordered))}"
    return f"{ip} ({len(ordered)} ports)"


def facts_table(incident: dict[str, Any], width: float) -> Table:
    label, color = severity_band(incident["severity_score"])
    severity = Paragraph(
        f'<font color="{color.hexval()}"><b>{label.upper()}</b></font>  {incident["severity_score"]:.1f} / 100',
        STYLES["body"],
    )
    cells = [
        ("Severity", severity),
        ("Status", p(incident["status"].capitalize())),
        ("Source IP", p(incident["src_ip"])),
        ("Alerts", p(incident["alert_count"])),
        ("Started (UTC)", p(fmt_dt(incident["start_time"], suffix=False))),
        ("Ended (UTC)", p(fmt_dt(incident["end_time"], suffix=False))),
        ("Duration", p(fmt_duration(incident["start_time"], incident["end_time"]))),
        ("Tactics", p(len(incident["mitre_tactics"]))),
    ]
    data = []
    for i in range(0, len(cells), 4):
        row = cells[i : i + 4]
        data.append([p(name.upper(), "label") for name, _ in row])
        data.append([value for _, value in row])
    table = Table(data, colWidths=[width / 4] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SLATE_50),
                ("BOX", (0, 0), (-1, -1), 0.5, SLATE_200),
                ("LINEBEFORE", (0, 0), (0, -1), 3, color),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("TOPPADDING", (0, 2), (-1, 2), 7),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
            ]
        )
    )
    return table


def narrative_section(incident: dict[str, Any], width: float) -> list[Any]:
    summary = incident["summary"]
    flow: list[Any] = [p("Narrative", "h2")]
    if summary and summary.startswith(FALLBACK_PREFIX):
        flow.append(p("The AI model was unavailable; this is an automatic digest.", "notice"))
        flow.append(Spacer(1, 3))
        summary = summary[len(FALLBACK_PREFIX) :].strip()
    flow.append(p(summary or "No summary has been generated for this incident.", "body" if summary else "muted"))

    if incident["recommended_action"]:
        box = Table(
            [[p("RECOMMENDED ACTION", "label")], [p(incident["recommended_action"], "action")]],
            colWidths=[width],
        )
        box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), BLUE_50),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, BLUE_600),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 9),
                ]
            )
        )
        flow += [Spacer(1, 8), box]
    return flow


def tactics_section(incident: dict[str, Any], width: float) -> list[Any]:
    tactics = incident["mitre_tactics"]
    if not tactics:
        return [p("MITRE ATT&CK tactics", "h2"), p("No tactics identified.", "muted")]
    data = [[p("#", "label"), p("TACTIC", "label"), p("FIRST SEEN", "label"), p("ALERTS", "label")]]
    for i, tactic in enumerate(tactics, 1):
        data.append(
            [p(i, "small"), p(f"{tactic['id']}  {tactic['name']}", "small"), p(fmt_dt(tactic["first_seen"]), "small"), p(len(tactic["alert_ids"]), "small")]
        )
    table = Table(data, colWidths=[width * 0.06, width * 0.46, width * 0.34, width * 0.14], repeatRows=1)
    table.setStyle(_grid_style())
    return [p("MITRE ATT&CK tactics (in order)", "h2"), table]


def timeline_section(incident: dict[str, Any], width: float) -> list[Any]:
    rows = timeline_rows(incident["alerts"], incident["mitre_tactics"])
    data = [[p(h, "label") for h in ("TIME (UTC)", "TACTIC", "SEV", "SIGNATURE", "TARGET", "COUNT")]]
    style = _grid_style()
    previous_tactic: Any = object()
    for i, row in enumerate(rows, 1):
        tactic = row["tactic"]
        tactic_text = "" if tactic is previous_tactic else (f"{tactic['id']} {tactic['name']}" if tactic else "Unmapped")
        previous_tactic = tactic
        count = f"x{row['count']}" if row["count"] > 1 else "1"
        if row["count"] > 1 and as_datetime(row["end"]) - as_datetime(row["start"]) >= timedelta(seconds=1):
            count += f" / {fmt_duration(row['start'], row['end'])}"
        data.append(
            [
                p(fmt_time(row["start"]), "small"),
                p(tactic_text, "small"),
                p(f"S{row['severity']}" if row["severity"] else "-", "small"),
                p(row["signature"], "small"),
                p(target_label(row["dest_ip"], row["ports"]), "small"),
                p(count, "small"),
            ]
        )
        sev_color = ALERT_SEVERITY_COLORS.get(row["severity"])
        if sev_color is not None:
            style.add("TEXTCOLOR", (2, i), (2, i), sev_color)
        if tactic_text:
            style.add("LINEABOVE", (0, i), (-1, i), 0.8, SLATE_500)

    table = Table(
        data,
        colWidths=[width * w for w in (0.11, 0.19, 0.06, 0.32, 0.22, 0.10)],
        repeatRows=1,
    )
    table.setStyle(style)
    return [p("Attack timeline", "h2"), table]


def asset_block(target: dict[str, Any], alert_count: int, width: float) -> Table:
    """One targeted asset as a two-column grid of label/value pairs."""
    if target["known_asset"]:
        heading = Paragraph(
            f"<b>{escape(target['hostname'] or target['ip'])}</b>"
            f'  <font color="{SLATE_500.hexval()}">criticality {target["criticality"]} / 5</font>',
            STYLES["body"],
        )
        pairs = [
            ("IP", target["ip"]),
            ("Role", (target["role"] or "-").replace("_", " ").capitalize()),
            ("MAC", target["mac"] or "-"),
            ("Alerts", alert_count),
            ("First seen", fmt_dt(target["first_seen"])),
            ("Last seen", fmt_dt(target["last_seen"])),
        ]
    else:
        heading = Paragraph(
            f"<b>{escape(target['ip'])}</b>"
            f'  <font color="{SLATE_500.hexval()}">not in asset inventory</font>',
            STYLES["body"],
        )
        pairs = [("Alerts", alert_count), ("Role", "Unknown")]

    data = [[heading, "", "", ""]]
    for i in range(0, len(pairs), 2):
        row: list[Any] = []
        for label, value in pairs[i : i + 2]:
            row += [p(label.upper(), "label"), p(value, "small")]
        data.append(row + [""] * (4 - len(row)))
    table = Table(data, colWidths=[width * w for w in (0.13, 0.37, 0.13, 0.37)])
    table.setStyle(
        TableStyle(
            [
                ("SPAN", (0, 0), (-1, 0)),
                ("BACKGROUND", (0, 0), (-1, -1), SLATE_50),
                ("BOX", (0, 0), (-1, -1), 0.5, SLATE_200),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, 0), 7),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                ("TOPPADDING", (0, 1), (-1, -1), 2),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
            ]
        )
    )
    return table


def assets_section(incident: dict[str, Any], width: float) -> list[Any]:
    targets = incident["targets"]
    title = p("Targeted assets", "h2")
    if not targets:
        return [KeepTogether([title, p("No recorded target.", "muted")])]
    alert_counts: dict[str, int] = {}
    for alert in incident["alerts"]:
        alert_counts[alert["dest_ip"]] = alert_counts.get(alert["dest_ip"], 0) + 1

    blocks = [asset_block(t, alert_counts.get(t["ip"], 0), width) for t in targets]
    # Keep the heading on the same page as the first asset.
    flow: list[Any] = [KeepTogether([title, blocks[0]])]
    for block in blocks[1:]:
        flow += [Spacer(1, 6), block]
    return flow


def _grid_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), SLATE_50),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, SLATE_200),
            ("LINEBELOW", (0, 1), (-1, -1), 0.3, SLATE_200),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def render_incident_pdf(incident: dict[str, Any]) -> bytes:
    """Render an incident (``IncidentDetail`` as a dict) to PDF bytes."""
    buffer = BytesIO()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(SLATE_500)
        canvas.drawString(doc.leftMargin, 10 * mm, f"SentriX incident report #{incident['id']}  ·  Generated {generated}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=f"SentriX Incident #{incident['id']}",
        author="SentriX",
    )
    width = doc.width
    story: list[Any] = [
        p(f"Incident #{incident['id']}", "title"),
        p(f"SentriX incident report · generated {generated}", "subtitle"),
        Spacer(1, 10),
        facts_table(incident, width),
        KeepTogether(narrative_section(incident, width)),
        *tactics_section(incident, width),
        *timeline_section(incident, width),
        *assets_section(incident, width),
    ]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
