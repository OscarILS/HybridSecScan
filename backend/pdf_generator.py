"""
HybridSecScan — Generador de Reportes PDF Profesionales
Universidad Nacional Mayor de San Marcos — Ingeniería de Software

Estructura del reporte:
  Página 1  — Portada (clasificación, título, objetivo, scoring de riesgo)
  Página 2  — Resumen Ejecutivo (distribución de severidades, OWASP API Top 10)
  Página 3  — Flujo de Análisis DAST (pasos ejecutados, cobertura de pruebas)
  Páginas 4+ — Hallazgos detallados con CWE, evidencia y remediación
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Dict, List, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.colors import HexColor, white, black, Color
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle, Polygon
from reportlab.graphics import renderPDF

# ─────────────────────────────────────────────────────────────────────────────
# Paleta de colores
# ─────────────────────────────────────────────────────────────────────────────

C = {
    # Marca
    "navy":        HexColor("#0f172a"),
    "dark_card":   HexColor("#1e293b"),
    "border":      HexColor("#334155"),
    "blue":        HexColor("#3b82f6"),
    "violet":      HexColor("#8b5cf6"),
    "blue_light":  HexColor("#60a5fa"),

    # Severidades
    "critical":    HexColor("#ef4444"),
    "high":        HexColor("#f97316"),
    "medium":      HexColor("#eab308"),
    "low":         HexColor("#3b82f6"),
    "info":        HexColor("#94a3b8"),

    # Semáforo de salud
    "health_red":    HexColor("#ef4444"),
    "health_orange": HexColor("#f97316"),
    "health_yellow": HexColor("#eab308"),
    "health_blue":   HexColor("#3b82f6"),
    "health_green":  HexColor("#10b981"),

    # Texto
    "text_main":  HexColor("#f8fafc"),
    "text_muted": HexColor("#94a3b8"),
    "white":      white,
    "black":      black,
    "gray_100":   HexColor("#f8fafc"),
    "gray_200":   HexColor("#e2e8f0"),
    "gray_800":   HexColor("#1e293b"),
}

# ─────────────────────────────────────────────────────────────────────────────
# OWASP API Security Top 10 (2023)
# ─────────────────────────────────────────────────────────────────────────────

OWASP_CATEGORIES: Dict[str, str] = {
    "API1:2023":  "Broken Object Level Authorization",
    "API2:2023":  "Broken Authentication",
    "API3:2023":  "Broken Object Property Level Authorization",
    "API4:2023":  "Unrestricted Resource Consumption",
    "API5:2023":  "Broken Function Level Authorization",
    "API6:2023":  "Unrestricted Access to Sensitive Business Flows",
    "API7:2023":  "Server Side Request Forgery (SSRF)",
    "API8:2023":  "Security Misconfiguration",
    "API9:2023":  "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# Mapeo tipo SAST → categoría OWASP
SAST_TYPE_TO_OWASP: Dict[str, str] = {
    "sql_injection":             "API1:2023",
    "hardcoded_password":        "API2:2023",
    "hardcoded_credentials":     "API2:2023",
    "weak_crypto":               "API3:2023",
    "weak_cryptographic_key":    "API3:2023",
    "b105":                      "API2:2023",
    "b106":                      "API2:2023",
    "b107":                      "API2:2023",
    "b108":                      "API9:2023",
    "b201":                      "API8:2023",
    "b301":                      "API8:2023",
    "b302":                      "API8:2023",
    "b303":                      "API3:2023",
    "b304":                      "API3:2023",
    "b305":                      "API3:2023",
    "b306":                      "API3:2023",
    "b307":                      "API8:2023",
    "b308":                      "API8:2023",
    "b310":                      "API1:2023",
    "b311":                      "API3:2023",
    "b312":                      "API8:2023",
    "b314":                      "API8:2023",
    "b320":                      "API8:2023",
    "b321":                      "API8:2023",
    "b322":                      "API8:2023",
    "b323":                      "API3:2023",
    "b324":                      "API3:2023",
    "b325":                      "API3:2023",
    "b401":                      "API8:2023",
    "b402":                      "API8:2023",
    "b411":                      "API8:2023",
    "b412":                      "API5:2023",
    "b413":                      "API3:2023",
    "b501":                      "API8:2023",
    "b502":                      "API8:2023",
    "b503":                      "API8:2023",
    "b504":                      "API8:2023",
    "b505":                      "API3:2023",
    "b506":                      "API8:2023",
    "b507":                      "API8:2023",
    "b601":                      "API8:2023",
    "b602":                      "API8:2023",
    "b603":                      "API8:2023",
    "b604":                      "API8:2023",
    "b605":                      "API8:2023",
    "b606":                      "API8:2023",
    "b607":                      "API8:2023",
    "b608":                      "API1:2023",
    "b609":                      "API8:2023",
    "b610":                      "API1:2023",
    "b611":                      "API1:2023",
    "b701":                      "API8:2023",
    "b702":                      "API8:2023",
    "b703":                      "API8:2023",
    "path_traversal":            "API1:2023",
    "command_injection":         "API8:2023",
    "xss":                       "API8:2023",
    "open_redirect":             "API8:2023",
    "insecure_deserialization":  "API8:2023",
    "broken_auth":               "API2:2023",
    "sensitive_data_exposure":   "API3:2023",
}

# Pasos del análisis DAST
DAST_STEPS = [
    {
        "num": "01",
        "title": "Reconocimiento Inicial",
        "desc": "Resolución DNS, detección de protocolo HTTP/HTTPS, identificación del servidor web y tecnologías.",
        "checks": ["DNS resolution", "HTTP/HTTPS detection", "Server fingerprinting", "Framework detection"],
    },
    {
        "num": "02",
        "title": "Análisis de Cabeceras de Seguridad",
        "desc": "Verificación de las 6 cabeceras de seguridad críticas según OWASP (CSP, HSTS, X-Frame-Options, etc.).",
        "checks": ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                   "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"],
    },
    {
        "num": "03",
        "title": "Prueba de Configuración CORS",
        "desc": "Inyección de origen malicioso y origen null para detectar políticas CORS permisivas o reflejadas.",
        "checks": ["Origin reflection test", "Null origin test", "Wildcard CORS detection"],
    },
    {
        "num": "04",
        "title": "Enumeración de Rutas Sensibles",
        "desc": "Sondeo de 19 rutas críticas comunes en APIs REST (admin, swagger, actuator, métricas, etc.).",
        "checks": ["/admin", "/swagger-ui.html", "/actuator/health", "/.env",
                   "/api/v1/users", "/metrics", "/debug", "/backup"],
    },
    {
        "num": "05",
        "title": "Verificación de Métodos HTTP",
        "desc": "Detección de métodos peligrosos habilitados: TRACE (refleja cabeceras) y CONNECT (proxy tunnel).",
        "checks": ["TRACE method", "CONNECT method", "OPTIONS disclosure"],
    },
    {
        "num": "06",
        "title": "Prueba de Divulgación de Errores",
        "desc": "Envío de peticiones malformadas para provocar stack traces, rutas internas o mensajes de BD.",
        "checks": ["Stack trace in response", "Internal path disclosure",
                   "Database error messages", "Framework version leak"],
    },
    {
        "num": "07",
        "title": "Evaluación de Rate Limiting",
        "desc": "15 peticiones rápidas consecutivas para verificar si existe throttling o control de velocidad.",
        "checks": ["429 Too Many Requests", "Retry-After header", "X-RateLimit headers",
                   "Response time degradation"],
    },
    {
        "num": "08",
        "title": "Análisis SSL/TLS e Información de Servidor",
        "desc": "Detección de información del servidor en cabeceras y verificación de redirección HTTPS.",
        "checks": ["Server header", "X-Powered-By", "HTTPS redirect", "Certificate validation"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sev(v: Dict) -> str:
    raw = v.get("severity") or v.get("risk") or v.get("issue_severity") or "low"
    return str(raw).upper()


def _sev_color(sev: str) -> Color:
    s = sev.upper()
    return C.get(s.lower(), C["info"])  # type: ignore[return-value]


def _health_score(summary: Dict) -> int:
    c = int(summary.get("critical", 0))
    h = int(summary.get("high",     0))
    m = int(summary.get("medium",   0))
    l = int(summary.get("low",      0))
    score = 100 - (c * 20 + h * 8 + m * 3 + l * 1)
    return max(0, min(100, score))


def _health_label(score: int) -> tuple[str, Color]:
    if score >= 85: return "Excelente",  C["health_green"]
    if score >= 60: return "Bueno",      C["health_blue"]
    if score >= 40: return "Normal",     C["health_yellow"]
    if score >= 20: return "Arriesgado", C["health_orange"]
    return "Crítico",   C["health_red"]


def _owasp_for_vuln(v: Dict) -> str:
    """Obtiene la categoría OWASP API Top 10 de un hallazgo."""
    cat = v.get("owasp_category", "")
    if cat:
        return cat
    vtype = str(v.get("type") or v.get("test_id") or "").lower().replace(" ", "_")
    for key, owasp in SAST_TYPE_TO_OWASP.items():
        if key in vtype:
            return owasp
    cwe = str(v.get("cwe") or "")
    cwe_map = {
        "89": "API1:2023", "22": "API1:2023", "284": "API1:2023",
        "287": "API2:2023", "798": "API2:2023",
        "200": "API3:2023", "327": "API3:2023",
        "770": "API4:2023",
        "285": "API5:2023",
        "918": "API7:2023",
        "16":  "API8:2023", "693": "API8:2023", "79": "API8:2023",
        "78":  "API8:2023", "319": "API8:2023", "942": "API8:2023",
    }
    for cid, owasp in cwe_map.items():
        if cid in cwe:
            return owasp
    return ""


def _build_owasp_table(vulnerabilities: List[Dict]) -> Dict[str, Dict[str, int]]:
    """Cuenta hallazgos por categoría OWASP y severidad."""
    result: Dict[str, Dict[str, int]] = {}
    for cat_id in OWASP_CATEGORIES:
        result[cat_id] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulnerabilities:
        cat = _owasp_for_vuln(v)
        if cat in result:
            sev = _sev(v).lower()
            bucket = sev if sev in result[cat] else "info"
            result[cat][bucket] += 1
    return result


def _styles():
    base = getSampleStyleSheet()

    def p(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "cover_title": p("cover_title",
            fontSize=28, fontName="Helvetica-Bold",
            textColor=C["white"], alignment=TA_LEFT, leading=34),
        "cover_subtitle": p("cover_sub",
            fontSize=13, fontName="Helvetica",
            textColor=HexColor("#93c5fd"), alignment=TA_LEFT),
        "cover_meta": p("cover_meta",
            fontSize=9, fontName="Helvetica",
            textColor=HexColor("#cbd5e1"), alignment=TA_LEFT, spaceAfter=3),
        "section_title": p("sec_title",
            fontSize=11, fontName="Helvetica-Bold",
            textColor=C["blue_light"], spaceBefore=6, spaceAfter=4,
            borderPad=4),
        "body": p("body",
            fontSize=9, fontName="Helvetica",
            textColor=HexColor("#1e293b"), leading=13, spaceAfter=4),
        "body_small": p("body_small",
            fontSize=8, fontName="Helvetica",
            textColor=HexColor("#334155"), leading=11, spaceAfter=2),
        "label": p("label",
            fontSize=8, fontName="Helvetica-Bold",
            textColor=HexColor("#334155"), spaceAfter=2),
        "step_title": p("step_title",
            fontSize=9, fontName="Helvetica-Bold",
            textColor=HexColor("#1e293b"), spaceAfter=2),
        "step_body": p("step_body",
            fontSize=8, fontName="Helvetica",
            textColor=HexColor("#475569"), leading=11, spaceAfter=2),
        "finding_title": p("finding_title",
            fontSize=10, fontName="Helvetica-Bold",
            textColor=HexColor("#0f172a"), spaceAfter=3),
        "finding_body": p("finding_body",
            fontSize=8.5, fontName="Helvetica",
            textColor=HexColor("#334155"), leading=12, spaceAfter=3),
        "finding_label": p("finding_label",
            fontSize=8, fontName="Helvetica-Bold",
            textColor=HexColor("#64748b"), spaceAfter=1),
        "footer": p("footer",
            fontSize=7, fontName="Helvetica",
            textColor=HexColor("#94a3b8"), alignment=TA_CENTER),
        "toc_row": p("toc_row",
            fontSize=9, fontName="Helvetica",
            textColor=HexColor("#334155")),
        "payload_code": p("payload_code",
            fontSize=7.5, fontName="Courier",
            textColor=HexColor("#c7d2fe"), leading=11, spaceAfter=1),
        "payload_label": p("payload_label",
            fontSize=7, fontName="Courier-Bold",
            textColor=HexColor("#818cf8"), spaceAfter=1),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Componentes gráficos
# ─────────────────────────────────────────────────────────────────────────────

def _health_bar_drawing(score: int, width: float = 380, height: float = 28) -> Drawing:
    """Barra de salud estilo semáforo con marcador de posición."""
    d = Drawing(width, height + 20)
    segments = [
        (0.00, 0.20, C["health_red"]),
        (0.20, 0.40, C["health_orange"]),
        (0.40, 0.60, C["health_yellow"]),
        (0.60, 0.85, C["health_blue"]),
        (0.85, 1.00, C["health_green"]),
    ]
    bar_y = 8
    r = 4
    for lo, hi, col in segments:
        x0 = lo * width
        x1 = hi * width
        d.add(Rect(x0, bar_y, x1 - x0, height, fillColor=col, strokeColor=None))

    # Marcador
    mx = (score / 100) * width
    d.add(Polygon([mx, bar_y + height + 10, mx - 6, bar_y + height + 2, mx + 6, bar_y + height + 2],
                  fillColor=C["black"], strokeColor=None))
    d.add(Rect(mx - 1, bar_y, 2, height, fillColor=C["black"], strokeColor=None))

    # Etiquetas
    for pct, label in [(0, "0"), (20, "20"), (40, "40"), (60, "60"), (85, "85"), (100, "100")]:
        d.add(String(pct / 100 * width, bar_y - 7, label,
                     fontSize=6, fillColor=HexColor("#475569"), textAnchor="middle"))
    return d


def _severity_donut(counts: Dict[str, int], width: float = 110, height: float = 110) -> Drawing:
    """Mini donut de distribución de severidades."""
    import math
    d = Drawing(width, height)
    total = sum(counts.values()) or 1
    cx, cy, r_out, r_in = width / 2, height / 2, 46, 26

    order = ["critical", "high", "medium", "low", "info"]
    colors = [C["critical"], C["high"], C["medium"], C["low"], C["info"]]

    angle = 90.0
    for sev, col in zip(order, colors):
        val = counts.get(sev, 0)
        if val == 0:
            continue
        sweep = 360 * val / total
        # Approximar arco con polígono (30 segmentos)
        pts_out, pts_in = [], []
        steps = max(int(sweep / 5), 2)
        for i in range(steps + 1):
            a = math.radians(angle - sweep * i / steps)
            pts_out.append((cx + r_out * math.cos(a), cy + r_in * 2 * math.sin(a) / 2 + (cy - r_in)))
        # Simple: usar círculo relleno con rect recortado (approx)
        a_start = math.radians(angle)
        a_end   = math.radians(angle - sweep)
        # Use wedge approximation
        wedge_pts = [cx, cy]
        for i in range(steps + 1):
            a = math.radians(angle - sweep * i / steps)
            wedge_pts += [cx + r_out * math.cos(a), cy + r_out * math.sin(a)]
        d.add(Polygon(wedge_pts, fillColor=col, strokeColor=C["white"], strokeWidth=1))
        angle -= sweep

    # Hole (inner circle)
    d.add(Circle(cx, cy, r_in, fillColor=C["white"], strokeColor=None))
    # Total text
    d.add(String(cx, cy - 4, str(sum(counts.values())),
                 fontSize=10, fillColor=HexColor("#0f172a"),
                 textAnchor="middle", fontName="Helvetica-Bold"))
    d.add(String(cx, cy - 14, "total",
                 fontSize=6, fillColor=HexColor("#94a3b8"),
                 textAnchor="middle"))
    return d


def _sev_badge_cell(sev: str) -> Paragraph:
    col_map = {
        "CRITICAL": ("#fca5a5", "#ef4444"),
        "HIGH":     ("#fdba74", "#f97316"),
        "MEDIUM":   ("#fde047", "#eab308"),
        "LOW":      ("#93c5fd", "#3b82f6"),
        "INFO":     ("#cbd5e1", "#64748b"),
    }
    bg, fg = col_map.get(sev.upper(), ("#cbd5e1", "#64748b"))
    style = ParagraphStyle("sev_badge", fontSize=7, fontName="Helvetica-Bold",
                           textColor=HexColor(fg), alignment=TA_CENTER,
                           backColor=HexColor(bg), borderPad=2,
                           spaceAfter=0, borderRadius=3)
    return Paragraph(sev.upper(), style)


# ─────────────────────────────────────────────────────────────────────────────
# Secciones del documento
# ─────────────────────────────────────────────────────────────────────────────

def _cover_page(story, scan_data: Dict, styles, score: int, label: str, score_color: Color):
    W, _ = A4
    usable = W - 3 * cm

    # ── Barra clasificación ──────────────────────────────────────────────
    class_data = [["CONFIDENCIAL — USO RESTRINGIDO"]]
    class_t = Table(class_data, colWidths=[usable])
    class_t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C["critical"]),
        ("TEXTCOLOR",   (0, 0), (-1, -1), C["white"]),
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(class_t)
    story.append(Spacer(1, 1.8 * cm))

    # ── Logo / Marca ─────────────────────────────────────────────────────
    brand_data = [["[ HS ]  HybridSecScan"]]
    brand_t = Table(brand_data, colWidths=[usable])
    brand_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["navy"]),
        ("TEXTCOLOR",     (0, 0), (-1, -1), HexColor("#60a5fa")),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 22),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(brand_t)
    story.append(Spacer(1, 0.8 * cm))

    # ── Título principal ─────────────────────────────────────────────────
    scan_type = scan_data.get("scan_type", "SECURITY").upper()
    type_label = {
        "SAST":   "Reporte de Análisis Estático (SAST)",
        "DAST":   "Reporte de Análisis Dinámico (DAST)",
        "HYBRID": "Reporte de Auditoría Híbrida SAST+DAST",
    }.get(scan_type, "Reporte de Auditoría de Seguridad")

    title_data = [[Paragraph(f"<b>Auditoría de Seguridad de APIs REST</b>", styles["cover_title"])],
                  [Paragraph(type_label, styles["cover_subtitle"])]]
    title_t = Table(title_data, colWidths=[usable])
    title_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["navy"]),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(title_t)
    story.append(Spacer(1, 1.2 * cm))

    # ── Metadata del escaneo ─────────────────────────────────────────────
    ts_raw = scan_data.get("timestamp", datetime.now().isoformat())
    try:
        ts = datetime.fromisoformat(str(ts_raw)).strftime("%d/%m/%Y %H:%M UTC")
    except Exception:
        ts = str(ts_raw)

    target = str(scan_data.get("target") or "N/A")
    meta_rows = [
        ["Objetivo analizado:", target],
        ["Tipo de análisis:",   scan_type],
        ["Fecha de ejecución:", ts],
        ["Analista:",           "HybridSecScan Engine v1.0"],
        ["Organización:",       "Universidad Nacional Mayor de San Marcos"],
        ["Marco de referencia:", "OWASP API Security Top 10 (2023)"],
    ]
    meta_t = Table(meta_rows, colWidths=[4 * cm, usable - 4 * cm])
    meta_t.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",     (0, 0), (0, -1), HexColor("#64748b")),
        ("TEXTCOLOR",     (1, 0), (1, -1), HexColor("#1e293b")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.5, HexColor("#e2e8f0")),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 1.2 * cm))

    # ── Score de salud ───────────────────────────────────────────────────
    score_header = [["PUNTUACIÓN DE RIESGO"]]
    sh_t = Table(score_header, colWidths=[usable])
    sh_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["navy"]),
        ("TEXTCOLOR",     (0, 0), (-1, -1), HexColor("#94a3b8")),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(sh_t)
    story.append(Spacer(1, 0.3 * cm))

    # Score — número compacto en una sola fila junto a la barra
    score_inline_style = ParagraphStyle("score_inline", fontSize=26,
                                        fontName="Helvetica-Bold",
                                        textColor=score_color, alignment=TA_LEFT,
                                        leading=30)
    slash_style = ParagraphStyle("slash", fontSize=10,
                                 fontName="Helvetica",
                                 textColor=HexColor("#94a3b8"), alignment=TA_LEFT,
                                 leading=30)
    score_lbl_style = ParagraphStyle("score_lbl", fontSize=13,
                                     fontName="Helvetica-Bold",
                                     textColor=score_color, alignment=TA_LEFT,
                                     leading=30)

    score_t = Table(
        [[
            Paragraph(str(score), score_inline_style),
            Paragraph("/ 100", slash_style),
            Paragraph(label, score_lbl_style),
        ]],
        colWidths=[1.6 * cm, 1.5 * cm, usable - 3.1 * cm],
    )
    score_t.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 3),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(score_t)
    story.append(Spacer(1, 0.4 * cm))

    # Barra de health
    bar_d = _health_bar_drawing(score, width=usable - 0.5 * cm)
    story.append(Spacer(1, 0.5 * cm))

    # Nota de puntuación
    note_style = ParagraphStyle("note", fontSize=8, fontName="Helvetica",
                                textColor=HexColor("#64748b"),
                                alignment=TA_LEFT)
    story.append(Paragraph(
        "Puntuación calculada sobre 100: Crítica −20 pts, Alta −8 pts, Media −3 pts, Baja −1 pt. "
        "Escala: 0–19 Crítico | 20–39 Arriesgado | 40–59 Normal | 60–84 Bueno | 85–100 Excelente",
        note_style))

    story.append(PageBreak())


def _executive_summary(story, scan_data: Dict, styles, owasp_counts: Dict):
    W, _ = A4
    usable = W - 3 * cm
    summary = scan_data.get("summary", {})
    vulns   = scan_data.get("vulnerabilities", [])

    sev_counts = {
        "critical": int(summary.get("critical", 0)),
        "high":     int(summary.get("high",     0)),
        "medium":   int(summary.get("medium",   0)),
        "low":      int(summary.get("low",      0)),
        "info":     int(summary.get("info",     0)),
    }
    total = sum(sev_counts.values())

    # ── Título de sección ────────────────────────────────────────────────
    _section_bar(story, "RESUMEN EJECUTIVO", usable)
    story.append(Spacer(1, 0.4 * cm))

    # ── Distribución de severidades ──────────────────────────────────────
    sev_header = Table([["DISTRIBUCIÓN DE VULNERABILIDADES"]], colWidths=[usable])
    sev_header.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["dark_card"]),
        ("TEXTCOLOR",     (0, 0), (-1, -1), HexColor("#94a3b8")),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(sev_header)
    story.append(Spacer(1, 0.25 * cm))

    # Tabla de conteos por severidad
    def sev_row(label, key, color):
        count = sev_counts.get(key, 0)
        pct   = f"{count / total * 100:.1f}%" if total else "0%"
        bar_w = max(0.1, count / max(total, 1)) * (usable - 8 * cm)
        bar_d = Drawing(usable - 8 * cm, 10)
        bar_d.add(Rect(0, 2, bar_w, 8, fillColor=color, strokeColor=None))
        return [Paragraph(f"<b>{label}</b>", styles["body"]), str(count), pct, bar_d]

    dist_data = [
        ["Severidad", "Hallazgos", "%", "Distribución"],
        sev_row("CRITICAL", "critical", C["critical"]),
        sev_row("HIGH",     "high",     C["high"]),
        sev_row("MEDIUM",   "medium",   C["medium"]),
        sev_row("LOW",      "low",      C["low"]),
        [Paragraph("<b>TOTAL</b>", styles["body"]), str(total), "100%", ""],
    ]
    dist_t = Table(dist_data,
                   colWidths=[3.5 * cm, 2 * cm, 1.5 * cm, usable - 7 * cm])
    dist_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C["navy"]),
        ("TEXTCOLOR",     (0, 0), (-1, 0), HexColor("#94a3b8")),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (1, 0), (2, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (0, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -2), [HexColor("#f8fafc"), HexColor("#f1f5f9")]),
        ("BACKGROUND",    (0, -1), (-1, -1), HexColor("#e2e8f0")),
        ("FONTNAME",      (0, -1), (-1, -1), "Helvetica-Bold"),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, C["blue"]),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
    ]))
    story.append(dist_t)
    story.append(Spacer(1, 0.6 * cm))

    # ── OWASP API Top 10 ─────────────────────────────────────────────────
    _section_bar(story, "OWASP API SECURITY TOP 10 — COBERTURA Y HALLAZGOS", usable)
    story.append(Spacer(1, 0.25 * cm))

    owasp_rows = [["ID", "Categoría", "Crítica", "Alta", "Media", "Baja", "Info", "Total"]]
    for cat_id, cat_name in OWASP_CATEGORIES.items():
        counts = owasp_counts.get(cat_id, {})
        c = counts.get("critical", 0)
        h = counts.get("high",     0)
        m = counts.get("medium",   0)
        l = counts.get("low",      0)
        i = counts.get("info",     0)
        t = c + h + m + l + i

        def num(n, color):
            if n == 0:
                return Paragraph("<font color='#94a3b8'>0</font>", styles["body_small"])
            return Paragraph(f"<b><font color='#{color}'>{n}</font></b>",
                             styles["body_small"])

        owasp_rows.append([
            Paragraph(f"<b>{cat_id}</b>", styles["body_small"]),
            Paragraph(cat_name, styles["body_small"]),
            num(c, "ef4444"), num(h, "f97316"),
            num(m, "ca8a04"), num(l, "3b82f6"),
            num(i, "94a3b8"),
            Paragraph(f"<b>{t}</b>" if t > 0 else "<font color='#94a3b8'>0</font>",
                      styles["body_small"]),
        ])

    owasp_t = Table(owasp_rows,
                    colWidths=[2.4 * cm, 6.2 * cm,
                               1.2 * cm, 1.2 * cm, 1.2 * cm, 1.2 * cm, 1.2 * cm, 1.2 * cm])
    owasp_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C["navy"]),
        ("TEXTCOLOR",     (0, 0), (-1, 0), HexColor("#94a3b8")),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (2, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (1, -1), 6),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [HexColor("#f8fafc"), HexColor("#f1f5f9")]),
        ("LINEBELOW",     (0, 0), (-1, 0), 1, C["blue"]),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ("LINEAFTER",     (0, 0), (0, -1), 0.5, HexColor("#cbd5e1")),
        ("LINEAFTER",     (1, 0), (1, -1), 0.5, HexColor("#e2e8f0")),
    ]))
    story.append(owasp_t)
    story.append(PageBreak())


def _dast_flow_page(story, scan_data: Dict, styles):
    W, _ = A4
    usable = W - 3 * cm
    vulns  = scan_data.get("vulnerabilities", [])
    target = str(scan_data.get("target") or "N/A")

    _section_bar(story, "FLUJO DEL ANÁLISIS DINÁMICO (DAST)", usable)
    story.append(Spacer(1, 0.2 * cm))

    intro_style = ParagraphStyle("intro", fontSize=8.5, fontName="Helvetica",
                                 textColor=HexColor("#475569"), leading=13)
    story.append(Paragraph(
        f"El análisis dinámico se ejecutó contra el objetivo <b>{target}</b> siguiendo 8 fases "
        "secuenciales de prueba activa. Cada fase produce hallazgos independientes que luego "
        "son correlacionados con los resultados SAST mediante el motor Random Forest.",
        intro_style))
    story.append(Spacer(1, 0.4 * cm))

    # Contar hallazgos por tipo de check (aproximación por owasp_category)
    owasp_hits: Dict[str, int] = {}
    for v in vulns:
        cat = _owasp_for_vuln(v)
        if cat:
            owasp_hits[cat] = owasp_hits.get(cat, 0) + 1

    step_owasp_map = {
        "01": [],
        "02": ["API8:2023"],
        "03": ["API8:2023"],
        "04": ["API9:2023"],
        "05": ["API5:2023"],
        "06": ["API8:2023", "API9:2023"],
        "07": ["API4:2023"],
        "08": ["API8:2023"],
    }

    for i, step in enumerate(DAST_STEPS):
        findings_in_step = sum(owasp_hits.get(c, 0) for c in step_owasp_map.get(step["num"], []))
        has_finding = findings_in_step > 0

        status_color = C["critical"] if has_finding else HexColor("#10b981")
        status_text  = f"⚠ {findings_in_step} hallazgo(s)" if has_finding else "✓ Sin hallazgos"

        step_num_style = ParagraphStyle("sn", fontSize=14, fontName="Helvetica-Bold",
                                        textColor=C["blue"] if not has_finding else C["critical"])

        checks_text = " · ".join(step["checks"][:4])
        if len(step["checks"]) > 4:
            checks_text += f" · +{len(step['checks'])-4} más"

        step_data = [
            [
                Paragraph(step["num"], step_num_style),
                [
                    Paragraph(f"<b>{step['title']}</b>", styles["step_title"]),
                    Paragraph(step["desc"], styles["step_body"]),
                    Paragraph(f"<i>Verificaciones: {checks_text}</i>", styles["step_body"]),
                ],
                Paragraph(f"<b><font color='#{status_color.hexval()}'>{status_text}</font></b>",
                          styles["body_small"]),
            ]
        ]

        bg = HexColor("#fff5f5") if has_finding else HexColor("#f0fdf4")
        border = C["critical"] if has_finding else HexColor("#10b981")

        step_t = Table(step_data, colWidths=[1.2 * cm, usable - 4.5 * cm, 3.3 * cm])
        step_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (2, 0), (2, -1), "CENTER"),
            ("VALIGN",        (2, 0), (2, -1), "MIDDLE"),
            ("BOX",           (0, 0), (-1, -1), 1, border),
        ]))
        story.append(KeepTogether([step_t, Spacer(1, 0.25 * cm)]))

        # Flecha conectora (excepto último)
        if i < len(DAST_STEPS) - 1:
            arr = Drawing(usable, 12)
            arr.add(Line(usable / 2, 12, usable / 2, 2,
                         strokeColor=HexColor("#cbd5e1"), strokeWidth=1))
            arr.add(Polygon([usable / 2, 0, usable / 2 - 4, 5, usable / 2 + 4, 5],
                            fillColor=HexColor("#cbd5e1"), strokeColor=None))
            story.append(arr)

    story.append(PageBreak())


def _infer_payload(v: Dict) -> Dict:
    """Reconstruye un payload de ataque básico para hallazgos DAST sin request_payload."""
    source   = v.get('source', '')
    vuln_type = v.get('type', '')
    url      = v.get('url', '')
    evidence = (v.get('evidence') or '')[:300]
    param    = v.get('parameter', '')

    base = {
        'method': 'GET',
        'url': url,
        'sent_headers': {'User-Agent': 'HybridSecScan/2.0 Security Scanner'},
        'response': evidence,
    }

    if 'CORS' in source or 'CORS' in vuln_type:
        return {**base,
                'sent_headers': {'Origin': 'https://evil-attacker.example.com',
                                 'User-Agent': 'HybridSecScan/2.0 Security Scanner'},
                'probe': 'Inyección de origen hostil para verificar política CORS'}

    if 'Security Header' in source or 'Missing Security Header' in vuln_type:
        return {**base,
                'probe': f'Inspección del header de seguridad HTTP: {param or vuln_type}'}

    if 'Endpoint' in source or 'Sensitive' in vuln_type:
        return {**base,
                'probe': f'Descubrimiento de ruta sensible: {param or url}'}

    if 'Error' in source or 'Information Disclosure' in vuln_type:
        probes = {"?id='": 'SQL injection probe', '?page=-9999': 'Negative page probe',
                  '/nonexistent_endpoint_xyz_abc': 'Invalid path probe'}
        matched = next((f"{p} — {d}" for p, d in probes.items() if p in url), 'Error disclosure probe')
        return {**base, 'probe': matched}

    if 'Rate' in source or 'Rate Limiting' in vuln_type:
        return {**base,
                'method': 'GET (x15)',
                'probe': 'Flood de peticiones: 15 GETs a ~20 req/s (delay=50ms)'}

    if 'HTTP Method' in source or 'Dangerous HTTP' in vuln_type:
        return {**base,
                'method': 'OPTIONS',
                'probe': 'Enumeración de métodos HTTP permitidos'}

    if 'Information' in source or 'Server Information' in vuln_type:
        return {**base,
                'probe': f'Inspección de headers que revelan información del servidor ({param})'}

    if 'SSL' in source or 'Insecure Transport' in vuln_type:
        return {**base,
                'probe': 'Verificación de redirección HTTP → HTTPS (sin seguir redirects)'}

    if url:
        return {**base, 'probe': f'Prueba DAST activa sobre {url}'}

    return {}


def _findings_pages(story, scan_data: Dict, styles):
    W, _ = A4
    usable = W - 3 * cm
    vulns  = scan_data.get("vulnerabilities", [])

    if not vulns:
        _section_bar(story, "HALLAZGOS DETALLADOS", usable)
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("No se detectaron vulnerabilidades en este escaneo.", styles["body"]))
        return

    # Ordenar por severidad
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(_sev(v), 5))

    _section_bar(story, f"HALLAZGOS DETALLADOS  ({len(vulns)} vulnerabilidades)", usable)
    story.append(Spacer(1, 0.3 * cm))

    for idx, v in enumerate(sorted_vulns, 1):
        sev   = _sev(v)
        col   = _sev_color(sev)
        title = (v.get("title") or v.get("type") or v.get("alert") or
                 v.get("test_name") or "Vulnerabilidad de Seguridad")
        source = v.get("source", scan_data.get("scan_type", ""))
        owasp  = _owasp_for_vuln(v)
        cat_name = OWASP_CATEGORIES.get(owasp, "")

        # Encabezado del hallazgo
        header_content = [
            [
                Paragraph(f"{idx:02d}", ParagraphStyle("idx", fontSize=16,
                    fontName="Helvetica-Bold", textColor=col)),
                [
                    Paragraph(f"<b>{title}</b>", styles["finding_title"]),
                    Paragraph(
                        f"{'<b>' + source + '</b>  ·  ' if source else ''}"
                        f"{'<b>' + owasp + '</b>  ' + cat_name if owasp else ''}",
                        styles["finding_label"]),
                ],
                _sev_badge_cell(sev),
            ]
        ]

        hdr_t = Table(header_content, colWidths=[1.2 * cm, usable - 4 * cm, 2.8 * cm])
        hdr_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f8fafc")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (2, 0), (2, -1), "CENTER"),
            ("LINEBELOW",     (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ("LINEBEFORE",    (0, 0), (0, -1), 3, col),
        ]))

        # Cuerpo del hallazgo
        body_rows = []

        def add_row(label: str, value: str):
            if value and str(value).strip():
                body_rows.append([
                    Paragraph(label, styles["finding_label"]),
                    Paragraph(str(value)[:800], styles["finding_body"]),
                ])

        desc = (v.get("description") or v.get("issue_text") or v.get("evidence") or "")
        add_row("Descripción", desc)

        loc = v.get("file") or v.get("url") or v.get("endpoint") or ""
        line = v.get("line") or v.get("line_number") or ""
        if loc:
            add_row("Ubicación", f"{loc}{(':' + str(line)) if line else ''}")

        param = v.get("parameter") or ""
        add_row("Parámetro", param)

        cwe = str(v.get("cwe") or v.get("cweid") or "")
        add_row("Referencia CWE", cwe)

        evidence = v.get("evidence") or ""
        if evidence and evidence != desc:
            add_row("Evidencia", evidence[:400])

        sol = (v.get("solution") or v.get("recommendation") or
               v.get("more_info") or "")
        add_row("Remediación", sol)

        tool = v.get("tool") or v.get("source") or ""
        if tool:
            add_row("Detectado por", tool)

        body_t = Table(body_rows, colWidths=[2.8 * cm, usable - 2.8 * cm])
        body_t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), HexColor("#f1f5f9")),
            ("BACKGROUND",    (1, 0), (1, -1), C["white"]),
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.3, HexColor("#e2e8f0")),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
        ]))

        # ── Bloque de payload de ataque ──────────────────────────────────────
        # Si no hay request_payload guardado (scans anteriores), reconstruir desde datos del hallazgo
        payload = v.get("request_payload") or {}
        if not payload and v.get("url"):
            payload = _infer_payload(v)
        payload_block = None
        if payload:
            lines = []
            method  = payload.get("method", "")
            req_url = payload.get("url", "")
            probe   = payload.get("probe", "")
            response_text = payload.get("response", "")
            sent    = payload.get("sent_headers", {})

            if method and req_url:
                lines.append(Paragraph(
                    f"<b>►</b> {method} {req_url}",
                    styles["payload_code"]))
            for hname, hval in sent.items():
                lines.append(Paragraph(
                    f"  {hname}: {hval}",
                    styles["payload_code"]))
            if probe:
                lines.append(Paragraph(
                    f"  [Sonda] {probe}",
                    styles["payload_label"]))
            if response_text:
                # Truncar línea larga de respuesta
                resp_short = response_text[:350] + ("…" if len(response_text) > 350 else "")
                lines.append(Paragraph(
                    f"  [Respuesta] {resp_short}",
                    styles["payload_code"]))

            if lines:
                missing_hdr = payload.get("missing_header", "")
                block_label = f"PAYLOAD DEL ATAQUE{' — header: ' + missing_hdr if missing_hdr else ''}"
                payload_inner = Table(
                    [[line] for line in lines],
                    colWidths=[usable - 1 * cm],
                )
                payload_inner.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#0f172a")),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                    ("TOPPADDING",    (0, 0), (0, 0),   6),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
                    ("TOPPADDING",    (0, 1), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -2), 1),
                ]))
                payload_label_t = Table(
                    [[Paragraph(
                        f"<font color='#818cf8'><b>{block_label}</b></font>",
                        styles["payload_label"])]],
                    colWidths=[usable - 1 * cm],
                )
                payload_label_t.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#1e1b4b")),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("TOPPADDING",    (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                payload_block = Table(
                    [[payload_label_t], [payload_inner]],
                    colWidths=[usable - 1 * cm],
                )
                payload_block.setStyle(TableStyle([
                    ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#4338ca")),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                    ("TOPPADDING",    (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]))

        elements = [hdr_t, body_t]
        if payload_block:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(payload_block)
        elements.append(Spacer(1, 0.35 * cm))
        story.append(KeepTogether(elements))


def _hybrid_correlations(story, scan_data: Dict, styles):
    W, _ = A4
    usable = W - 3 * cm
    correlations = scan_data.get("correlations", [])
    metrics      = scan_data.get("hybrid_metrics", {})

    _section_bar(story, "MOTOR DE CORRELACIÓN ML — RESULTADOS", usable)
    story.append(Spacer(1, 0.3 * cm))

    # Métricas del motor
    m_data = [
        ["Hallazgos SAST analizados", str(metrics.get("total_sast", 0))],
        ["Hallazgos DAST analizados", str(metrics.get("total_dast", 0))],
        ["Reducción de falsos positivos", f"{metrics.get('fp_reduction', 0):.1f}%"],
        ["Correlaciones confirmadas",  str(len([c for c in correlations if c.get("confidence_score", 0) >= 0.5]))],
    ]
    m_t = Table(m_data, colWidths=[6 * cm, 4 * cm])
    m_t.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",     (0, 0), (0, -1), HexColor("#64748b")),
        ("TEXTCOLOR",     (1, 0), (1, -1), HexColor("#0f172a")),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [HexColor("#f8fafc"), HexColor("#f1f5f9")]),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
    ]))
    story.append(m_t)
    story.append(Spacer(1, 0.5 * cm))

    if not correlations:
        story.append(Paragraph("No se generaron correlaciones en este análisis.", styles["body"]))
        return

    _section_bar(story, "CORRELACIONES DETECTADAS", usable)
    story.append(Spacer(1, 0.25 * cm))

    for i, corr in enumerate(correlations[:20], 1):
        conf = corr.get("confidence_score", 0) * 100
        conf_col = C["critical"] if conf < 40 else C["medium"] if conf < 70 else HexColor("#10b981")
        sast_v = corr.get("sast_vulnerability", {})
        dast_v = corr.get("dast_vulnerability", {})
        expl   = corr.get("explanation", "")

        rows = [
            [Paragraph(f"<b>Correlación #{i}</b>", styles["step_title"]),
             Paragraph(f"<b><font color='#{conf_col.hexval()}'>"
                       f"Confianza: {conf:.1f}%</font></b>", styles["body_small"])],
            [Paragraph(f"SAST → {sast_v.get('type','?')} en "
                       f"{sast_v.get('file','?')}:{sast_v.get('line','')}",
                       styles["finding_body"]), ""],
            [Paragraph(f"DAST → {dast_v.get('type','?')} en "
                       f"{dast_v.get('endpoint', dast_v.get('url','?'))}",
                       styles["finding_body"]), ""],
        ]
        if expl:
            rows.append([Paragraph(f"<i>{expl}</i>", styles["finding_body"]), ""])

        ct = Table(rows, colWidths=[usable - 3.5 * cm, 3.5 * cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#f1f5f9")),
            ("SPAN",          (0, 1), (-1, 1)),
            ("SPAN",          (0, 2), (-1, 2)),
            ("SPAN",          (0, 3), (-1, 3)),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ("LINEBELOW",     (0, 0), (-1, 0), 0.5, HexColor("#e2e8f0")),
        ]))
        story.append(KeepTogether([ct, Spacer(1, 0.2 * cm)]))


def _section_bar(story, title: str, usable: float):
    t = Table([[title]], colWidths=[usable])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C["navy"]),
        ("TEXTCOLOR",     (0, 0), (-1, -1), HexColor("#60a5fa")),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)


def _page_header_footer(canvas, doc):
    canvas.saveState()
    W, H = A4
    # Header line
    canvas.setStrokeColor(HexColor("#1e293b"))
    canvas.setLineWidth(0.5)
    canvas.line(1.5 * cm, H - 1.2 * cm, W - 1.5 * cm, H - 1.2 * cm)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(HexColor("#3b82f6"))
    canvas.drawString(1.5 * cm, H - 1.0 * cm, "HybridSecScan")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(HexColor("#94a3b8"))
    canvas.drawRightString(W - 1.5 * cm, H - 1.0 * cm,
                           "CONFIDENCIAL — OWASP API Security Top 10 (2023)")

    # Footer
    canvas.line(1.5 * cm, 1.2 * cm, W - 1.5 * cm, 1.2 * cm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(HexColor("#94a3b8"))
    canvas.drawString(1.5 * cm, 0.9 * cm,
                      f"Generado: {datetime.now().strftime('%d/%m/%Y %H:%M')}  |  "
                      "Universidad Nacional Mayor de San Marcos")
    canvas.drawRightString(W - 1.5 * cm, 0.9 * cm, f"Página {doc.page}")
    canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# API pública
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    """
    Genera el PDF profesional de auditoría.

    Args:
        scan_data: Dict con scan_type, target, timestamp, vulnerabilities,
                   summary, y opcionalmente correlations / hybrid_metrics.

    Returns:
        bytes: PDF listo para descarga.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title="HybridSecScan Security Report",
        author="HybridSecScan Engine",
    )

    styles    = _styles()
    vulns     = scan_data.get("vulnerabilities", [])
    summary   = scan_data.get("summary", {})
    scan_type = str(scan_data.get("scan_type", "SAST")).upper()

    score       = _health_score(summary)
    label, scol = _health_label(score)
    owasp_counts = _build_owasp_table(vulns)

    story: List[Any] = []

    # Página 1 — Portada
    _cover_page(story, scan_data, styles, score, label, scol)

    # Página 2 — Resumen ejecutivo + OWASP
    _executive_summary(story, scan_data, styles, owasp_counts)

    # Página 3 — Flujo DAST (solo si hay info dinámica)
    if scan_type in ("DAST", "HYBRID"):
        _dast_flow_page(story, scan_data, styles)

    # Correlaciones (solo HYBRID)
    if scan_type == "HYBRID" and scan_data.get("correlations"):
        _hybrid_correlations(story, scan_data, styles)
        story.append(PageBreak())

    # Hallazgos detallados
    _findings_pages(story, scan_data, styles)

    doc.build(story,
              onFirstPage=_page_header_footer,
              onLaterPages=_page_header_footer)

    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes


def generate_json_summary(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    vulns = scan_data.get("vulnerabilities", [])
    summary = scan_data.get("summary", {})
    return {
        "scan_type":   scan_data.get("scan_type"),
        "target":      scan_data.get("target"),
        "timestamp":   scan_data.get("timestamp"),
        "health_score": _health_score(summary),
        "summary":     summary,
        "owasp_coverage": {
            cat_id: sum(_build_owasp_table(vulns).get(cat_id, {}).values())
            for cat_id in OWASP_CATEGORIES
        },
        "vulnerabilities_count": len(vulns),
        "severity_distribution": {
            "critical": sum(1 for v in vulns if _sev(v) == "CRITICAL"),
            "high":     sum(1 for v in vulns if _sev(v) == "HIGH"),
            "medium":   sum(1 for v in vulns if _sev(v) == "MEDIUM"),
            "low":      sum(1 for v in vulns if _sev(v) == "LOW"),
        },
    }
