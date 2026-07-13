from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output" / "pdf"
OUTPUT_FILE = OUTPUT_DIR / "Project_ARGUS_Architecture_Comparison.pdf"

PAGE = landscape(A4)
PAGE_W, PAGE_H = PAGE
MARGIN_X = 15 * mm
MARGIN_TOP = 14 * mm
MARGIN_BOTTOM = 14 * mm

NAVY = colors.HexColor("#102A43")
BLUE = colors.HexColor("#1D4ED8")
TEAL = colors.HexColor("#0F766E")
CYAN = colors.HexColor("#DFF7F5")
PALE_BLUE = colors.HexColor("#EAF2FF")
PALE_GOLD = colors.HexColor("#FFF4D6")
PALE_RED = colors.HexColor("#FDEBEC")
INK = colors.HexColor("#243B53")
MUTED = colors.HexColor("#627D98")
GRID = colors.HexColor("#CBD5E1")
LIGHT = colors.HexColor("#F7FAFC")
WHITE = colors.white


styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=30,
        leading=34,
        textColor=WHITE,
        alignment=TA_LEFT,
        spaceAfter=5 * mm,
    )
)
styles.add(
    ParagraphStyle(
        name="CoverSubtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=13,
        leading=18,
        textColor=colors.HexColor("#DCEBFF"),
    )
)
styles.add(
    ParagraphStyle(
        name="SectionTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=23,
        textColor=NAVY,
        spaceAfter=4 * mm,
    )
)
styles.add(
    ParagraphStyle(
        name="SubTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=BLUE,
        spaceAfter=2 * mm,
        spaceBefore=2 * mm,
    )
)
styles.add(
    ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.4,
        leading=11.2,
        textColor=INK,
    )
)
styles.add(
    ParagraphStyle(
        name="Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.4,
        leading=13,
        textColor=INK,
    )
)
styles.add(
    ParagraphStyle(
        name="Callout",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=18,
        textColor=NAVY,
        alignment=TA_CENTER,
    )
)
styles.add(
    ParagraphStyle(
        name="TableHead",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8.3,
        leading=10.2,
        textColor=WHITE,
        alignment=TA_CENTER,
    )
)
styles.add(
    ParagraphStyle(
        name="TableCell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.6,
        leading=9.5,
        textColor=INK,
    )
)
styles.add(
    ParagraphStyle(
        name="TableCellBold",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=7.6,
        leading=9.5,
        textColor=NAVY,
    )
)
styles.add(
    ParagraphStyle(
        name="Tiny",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=6.8,
        leading=8.3,
        textColor=MUTED,
    )
)


def p(text, style="Body"):
    return Paragraph(text, styles[style])


def bullet(text):
    return p("&#8226; " + text, "BodySmall")


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#D8E2EC"))
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN_X, 9 * mm, PAGE_W - MARGIN_X, 9 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN_X, 5.5 * mm, "Project ARGUS Architecture Comparison")
    canvas.drawRightString(PAGE_W - MARGIN_X, 5.5 * mm, f"Page {doc.page}")
    canvas.restoreState()


def comparison_table(rows, widths=None):
    if widths is None:
        widths = [41 * mm, 101 * mm, 101 * mm]
    data = [
        [p("Architecture area", "TableHead"), p("Downloaded Argus 3.0", "TableHead"), p("Desktop Project ARGUS 5.1", "TableHead")]
    ]
    for area, old, new in rows:
        data.append([p(area, "TableCellBold"), p(old, "TableCell"), p(new, "TableCell")])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (0, -1), PALE_BLUE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.45, GRID),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (1, 1), (-1, -1), [WHITE, LIGHT]),
            ]
        )
    )
    return table


def metric_table():
    rows = [
        ("content.js", "42,335", "50,002", "1.18x"),
        ("service_worker.js", "52,482", "74,843", "1.43x"),
        ("popup.js", "17,301", "27,109", "1.57x"),
        ("engine/argus_engine.js", "31,581", "41,391", "1.31x"),
        ("backend/main.py", "15,004", "17,671", "1.18x"),
        ("Primary test files", "3", "16", "5.33x"),
    ]
    data = [[p(x, "TableHead") for x in ["Item", "Downloaded", "Desktop", "Growth"]]]
    data += [[p(a, "TableCellBold"), p(b, "TableCell"), p(c, "TableCell"), p(d, "TableCell")] for a, b, c, d in rows]
    table = Table(data, colWidths=[64 * mm, 35 * mm, 35 * mm, 28 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), TEAL),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, CYAN]),
                ("GRID", (0, 0), (-1, -1), 0.45, GRID),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


class ArgusDocTemplate(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(
            filename,
            pagesize=PAGE,
            leftMargin=MARGIN_X,
            rightMargin=MARGIN_X,
            topMargin=MARGIN_TOP,
            bottomMargin=MARGIN_BOTTOM,
            title="Project ARGUS Architecture Comparison",
            author="OpenAI Codex",
            subject="Comparison of downloaded Argus Security 3.0 and desktop Project ARGUS 5.1",
        )
        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="main",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )
        self.addPageTemplates(PageTemplate(id="all", frames=[frame], onPage=footer))


def build_pdf():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    doc = ArgusDocTemplate(str(OUTPUT_FILE))
    story = []

    # Cover
    cover = Table(
        [
            [
                p("PROJECT ARGUS", "CoverSubtitle"),
            ],
            [
                p("Architecture Comparison", "CoverTitle"),
            ],
            [
                p(
                    "Downloaded Argus Security 3.0 versus the desktop Project ARGUS Extension 5.1",
                    "CoverSubtitle",
                )
            ],
        ],
        colWidths=[doc.width],
        rowHeights=[14 * mm, 35 * mm, 26 * mm],
    )
    cover.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("LEFTPADDING", (0, 0), (-1, -1), 15 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 15 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 5 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story += [Spacer(1, 15 * mm), cover, Spacer(1, 12 * mm)]

    summary_box = Table(
        [[p("Core architectural shift", "SubTitle")], [p(
            "The downloaded build is primarily a score-driven deterministic rule engine. "
            "The desktop build is a layered, lifecycle-aware, evidence-governed hybrid detection system in which policy - not the model - controls the user-visible status, score, and warning.",
            "Callout",
        )]],
        colWidths=[doc.width],
    )
    summary_box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE_BLUE),
                ("BOX", (0, 0), (-1, -1), 1, BLUE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5 * mm),
            ]
        )
    )
    story += [summary_box, Spacer(1, 8 * mm)]
    paths = Table(
        [
            [p("Downloaded source", "TableHead"), p("Desktop source", "TableHead")],
            [
                p("C:/Users/User/Downloads/Argus-Security-main/Argus-Security-main", "BodySmall"),
                p("C:/Users/User/Desktop/Project-Argus-Extension", "BodySmall"),
            ],
            [p("Manifest version 3.0.0", "BodySmall"), p("Manifest version 5.1.0", "BodySmall")],
        ],
        colWidths=[doc.width / 2, doc.width / 2],
    )
    paths.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#526D82")),
                ("BACKGROUND", (1, 0), (1, 0), TEAL),
                ("GRID", (0, 0), (-1, -1), 0.5, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story += [paths, PageBreak()]

    # System flows
    story += [p("1. System flow and authority", "SectionTitle")]
    flow_data = [
        [p("Downloaded Argus Security 3.0", "TableHead"), p("Desktop Project ARGUS 5.1", "TableHead")],
        [
            p("Page metadata + webRequest", "TableCellBold"),
            p("Page, network, and security metadata", "TableCellBold"),
        ],
        [p("DOWN", "Tiny"), p("DOWN", "Tiny")],
        [
            p("service_worker.js", "TableCellBold"),
            p("Navigation and session validation", "TableCellBold"),
        ],
        [p("DOWN", "Tiny"), p("DOWN", "Tiny")],
        [
            p("argus_engine or legacy fallback", "TableCellBold"),
            p("Modular evidence engine + local trained model", "TableCellBold"),
        ],
        [p("DOWN", "Tiny"), p("DOWN", "Tiny")],
        [
            p("Numeric score threshold", "TableCellBold"),
            p("Evidence decision policy", "TableCellBold"),
        ],
        [p("DOWN", "Tiny"), p("DOWN", "Tiny")],
        [
            p("Warning + popup + storage", "TableCellBold"),
            p("Policy-approved score + warning permissions + UI/storage/reports", "TableCellBold"),
        ],
    ]
    flow = Table(flow_data, colWidths=[doc.width / 2, doc.width / 2])
    flow.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#526D82")),
                ("BACKGROUND", (1, 0), (1, 0), TEAL),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F1F5F9")),
                ("BACKGROUND", (1, 1), (1, -1), CYAN),
                ("BOX", (0, 0), (0, -1), 0.8, colors.HexColor("#526D82")),
                ("BOX", (1, 0), (1, -1), 0.8, TEAL),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, GRID),
                ("ALIGN", (0, 1), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ]
        )
    )
    story += [flow, Spacer(1, 5 * mm)]
    authority = Table(
        [
            [p("Who has final authority?", "SubTitle"), p("Why it matters", "SubTitle")],
            [
                p("3.0: the combined numeric score and thresholds directly drive SAFE, SUSPICIOUS, HIGH_RISK, and warning behavior.", "BodySmall"),
                p("A high score can become a visible warning even when the underlying signals are mainly static or contextual.", "BodySmall"),
            ],
            [
                p("5.1: the evidence decision policy is the sole user-visible authority. The model is advisory and cannot independently create SUSPICIOUS, HIGH_RISK, or a warning.", "BodySmall"),
                p("The UI receives a policy-approved score and explicit warningAllowed/overlayAllowed permissions, reducing model-only score inflation.", "BodySmall"),
            ],
        ],
        colWidths=[doc.width / 2, doc.width / 2],
    )
    authority.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PALE_GOLD),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE_BLUE]),
                ("GRID", (0, 0), (-1, -1), 0.5, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story += [authority, PageBreak()]

    # Differences part 1
    story += [p("2. What is different - detection and scoring", "SectionTitle")]
    diff1 = [
        (
            "Primary decision model",
            "Weighted deterministic analyzers feed a combined numeric score. The UI and warning logic largely follow thresholds.",
            "A hybrid design combines modular evidence analysis with a local trained calibrator, then applies a separate evidence policy before anything becomes user-visible.",
        ),
        (
            "Risk states",
            "SAFE, SUSPICIOUS, HIGH_RISK.",
            "SAFE, MONITORING, UNCERTAIN, SUSPICIOUS, HIGH_RISK. Observation quality is represented without treating uncertainty as danger.",
        ),
        (
            "High-risk rule",
            "HIGH_RISK at a score of 70 or above.",
            "HIGH_RISK requires allowlisted direct evidence connecting a sensitive source or dangerous action to a harmful sink.",
        ),
        (
            "Suspicious rule",
            "SUSPICIOUS at a score of 35 or above.",
            "SUSPICIOUS requires correlated evidence rather than score alone: at least two evidence groups and at least one observed behavioral group in the inspected policy.",
        ),
        (
            "Model-only output",
            "No independent governance layer prevents a high combined score from reaching the UI.",
            "Model-only output is capped at 5, cannot warn, and cannot independently create SUSPICIOUS or HIGH_RISK.",
        ),
        (
            "Static/context signals",
            "Static and contextual features can contribute directly to the overall score.",
            "Static single-group evidence is capped at 10. Context features inform confidence and analysis but are restricted from independently inflating visible risk.",
        ),
        (
            "Incomplete observation",
            "Limited explicit separation between incomplete telemetry and actual risk.",
            "Incomplete observation lowers confidence or yields MONITORING/UNCERTAIN; it is not supposed to add risk by itself.",
        ),
    ]
    story += [comparison_table(diff1), PageBreak()]

    # Differences part 2
    story += [p("3. What is different - lifecycle, destinations, and UI", "SectionTitle")]
    diff2 = [
        (
            "Navigation isolation",
            "Primarily tab-based maps, timer-based resets, and preservation logic.",
            "navigation_session_guard.js tracks tabId, pageKey, epoch, navigationId, frameId, and rejects stale messages or rescans.",
        ),
        (
            "SPA behavior",
            "Limited lifecycle treatment beyond fixed content-script scans.",
            "Explicit same-document page change handling for SPA navigation, plus stale page-context detection.",
        ),
        (
            "Scan lifecycle",
            "Initial scan followed by fixed rescans around 1.5 and 4 seconds.",
            "Progressive preliminary, final, and interaction-final phases with observation windows and shadow-mode support.",
        ),
        (
            "Destination classification",
            "Mostly same-site, third-party, and insecure destination distinctions.",
            "Fine-grained roles include first-party write, same-site API, identity/SSO, payment, analytics, ad network, CDN, unknown read/write/beacon, and executable source.",
        ),
        (
            "Popup freshness",
            "Popup reads the cached result immediately.",
            "Popup requests a rescan and checks same page, post-request freshness, and stable scan state before rendering. It also exposes richer evidence and export diagnostics.",
        ),
        (
            "Analyzer surface",
            "Seven analyzers plus a combiner form the core engine.",
            "Adds browser protection, URL lexical, mixed content, security headers, script integrity, unsandboxed frames, storage/cookie relay, WebSocket relay, encoded relay, and wildcard postMessage analysis.",
        ),
        (
            "Testing and validation",
            "Three primary test files and deterministic checks.",
            "Sixteen primary test files plus Playwright real-browser testing, datasets, training, randomized cross-validation, benign robustness tests, and an autonomous controller.",
        ),
        (
            "Versioned contracts",
            "Simpler manifest-centered versioning.",
            "Separate manifest, policy, model, evidence-policy, and report-schema versions. This improves traceability but creates drift risk if releases are not synchronized.",
        ),
    ]
    story += [comparison_table(diff2), PageBreak()]

    # Same
    story += [p("4. What is still the same", "SectionTitle")]
    same_items = [
        ("Extension platform", "Both are Chrome Manifest V3 extensions."),
        ("Major runtime pieces", "Both use content.js, service_worker.js, popup/options pages, and local extension storage."),
        ("Network observation", "Both use chrome.webRequest metadata as a central network signal source."),
        ("Privacy posture", "Both are designed around metadata rather than request bodies, typed values, credentials, or personal content."),
        ("Local operation", "Both operate locally and do not depend on an external generative AI service for normal scoring."),
        ("Backend role", "Both include an optional FastAPI compatibility/backend path; the browser extension remains the main runtime authority."),
        ("Fallback behavior", "Both retain a legacy fallback scorer when the modular engine is unavailable."),
        ("Detection foundation", "Both retain analyzer-based evidence collection and score combination as important implementation building blocks."),
        ("Product shell", "Permissions, popup workflow, service-worker coordination, and the overall extension product shape remain broadly recognizable."),
    ]
    same_data = [[p("Shared architecture element", "TableHead"), p("What remains common", "TableHead")]]
    same_data += [[p(a, "TableCellBold"), p(b, "TableCell")] for a, b in same_items]
    same = Table(same_data, colWidths=[58 * mm, 185 * mm], repeatRows=1, hAlign="LEFT")
    same.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), TEAL),
                ("BACKGROUND", (0, 1), (0, -1), CYAN),
                ("ROWBACKGROUNDS", (1, 1), (1, -1), [WHITE, LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.45, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story += [same, Spacer(1, 5 * mm)]
    story += [p("Measured implementation growth", "SubTitle"), metric_table(), Spacer(1, 2 * mm)]
    story += [p("Byte counts are a structural indicator, not a quality score. The largest relative growth is in popup.js and the test suite, reflecting richer diagnostics, freshness checks, and validation coverage.", "Tiny"), PageBreak()]

    # Implications
    story += [p("5. Architectural consequences and remaining risks", "SectionTitle")]
    consequences = [
        [
            p("Improved separation of concerns", "SubTitle"),
            p("Evidence collection, model calibration, lifecycle validation, and UI policy are separate stages. This makes it easier to diagnose whether a wrong score came from telemetry, classification, the model, policy, or display mapping.", "BodySmall"),
        ],
        [
            p("Safer user-visible decisions", "SubTitle"),
            p("The desktop design explicitly prevents model-only scores and static complexity from directly producing warnings. Direct evidence is required for HIGH_RISK, while correlated evidence is required for SUSPICIOUS.", "BodySmall"),
        ],
        [
            p("Better browser lifecycle handling", "SubTitle"),
            p("Session IDs, document/page keys, epochs, frame checks, and progressive scans reduce stale state surviving navigation - a major source of misleading popup results in browser extensions.", "BodySmall"),
        ],
        [
            p("More operational complexity", "SubTitle"),
            p("The stronger architecture has more modules, contracts, report fields, and version identifiers. It needs synchronized releases and end-to-end browser tests to avoid schema or version drift.", "BodySmall"),
        ],
    ]
    consequence_table = Table(consequences, colWidths=[59 * mm, 184 * mm])
    consequence_table.setStyle(
        TableStyle(
            [
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [PALE_BLUE, WHITE]),
                ("BOX", (0, 0), (-1, -1), 0.7, GRID),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [consequence_table, Spacer(1, 5 * mm)]

    risk_data = [
        [p("Remaining engineering risk", "TableHead"), p("Why it remains important", "TableHead")],
        [p("Monolithic content.js and service_worker.js", "TableCellBold"), p("Both files are still large coordination hubs, which makes lifecycle and state interactions harder to reason about.", "TableCell")],
        [p("Legacy fallback and backend scorer drift", "TableCellBold"), p("Alternative scoring paths can diverge from the modular evidence policy unless parity is tested explicitly.", "TableCell")],
        [p("Multiple version identifiers", "TableCellBold"), p("Manifest 5.1.0, policy 4.2.0, model 5.0.0, evidence policy v1, and report schema 2 improve traceability but require disciplined compatibility checks. Some documentation still refers to 4.2.", "TableCell")],
        [p("Configuration duplication", "TableCellBold"), p("Provider and category knowledge appears in both code and JSON configuration in places, increasing the chance of inconsistent destination classification.", "TableCell")],
    ]
    risk_table = Table(risk_data, colWidths=[70 * mm, 173 * mm], hAlign="LEFT")
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#9F1239")),
                ("BACKGROUND", (0, 1), (0, -1), PALE_RED),
                ("ROWBACKGROUNDS", (1, 1), (1, -1), [WHITE, LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.45, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story += [p("Remaining risks", "SubTitle"), risk_table, PageBreak()]

    # Conclusion and source basis
    story += [p("6. Bottom line", "SectionTitle")]
    conclusion = Table(
        [[p(
            "Project ARGUS 5.1 is not merely a larger version of Argus 3.0. It changes the decision architecture: "
            "browser telemetry is validated against navigation state, evidence is grouped and classified, a local model is constrained to an advisory role, and an explicit policy determines the user-visible result.",
            "Callout",
        )]],
        colWidths=[doc.width],
    )
    conclusion.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CYAN),
                ("BOX", (0, 0), (-1, -1), 1, TEAL),
                ("LEFTPADDING", (0, 0), (-1, -1), 12 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 8 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8 * mm),
            ]
        )
    )
    story += [conclusion, Spacer(1, 8 * mm)]

    verdicts = Table(
        [
            [p("Question", "TableHead"), p("Answer", "TableHead")],
            [p("Is the extension shell the same?", "TableCellBold"), p("Broadly yes. Both use the same MV3 content-script/service-worker/popup pattern and local metadata collection.", "TableCell")],
            [p("Is the detection architecture the same?", "TableCellBold"), p("No. The desktop build adds explicit lifecycle isolation, evidence governance, constrained model calibration, richer destination roles, and progressive observation.", "TableCell")],
            [p("Is the desktop version safer against score inflation?", "TableCellBold"), p("Architecturally yes: model-only and context-only paths are constrained. Real-browser validation is still required to prove every runtime path follows that policy.", "TableCell")],
            [p("Can the old code be considered a separate product lineage?", "TableCellBold"), p("It is the same product lineage and shell, but the desktop build represents a substantial decision-system redesign rather than a simple feature update.", "TableCell")],
        ],
        colWidths=[75 * mm, 168 * mm],
    )
    verdicts.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (0, -1), PALE_BLUE),
                ("ROWBACKGROUNDS", (1, 1), (1, -1), [WHITE, LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.45, GRID),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story += [verdicts, Spacer(1, 8 * mm)]

    source_note = Table(
        [[p("Review basis", "SubTitle")], [p(
            "This comparison was prepared from the source trees, manifests, engine modules, service-worker and popup flows, backend compatibility code, tests, and architecture documentation present in the two local project directories. No files were modified in the downloaded Argus source.",
            "BodySmall",
        )]],
        colWidths=[doc.width],
    )
    source_note.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE_GOLD),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#D69E2E")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story += [source_note]

    doc.build(story)
    print(OUTPUT_FILE)


if __name__ == "__main__":
    build_pdf()
