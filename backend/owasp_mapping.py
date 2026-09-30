"""
Mapeo único de hallazgos a la edición 2023 del OWASP API Security Top 10.

Es la única fuente de verdad del proyecto: escáner DAST, integración ZAP, reportes PDF
y metadatos de escaneo usan estas funciones.

Criterio para vulnerabilidades sin categoría propia en la edición 2023
------------------------------------------------------------------------
La edición 2023 eliminó la categoría de inyección (API8:2019 Injection). Las fallas de
implementación que no tienen categoría propia en 2023 —inyección SQL, de comandos y de
código, XSS, path traversal, deserialización insegura, XXE, redirección abierta,
criptografía débil, dependencias vulnerables— se clasifican en API8:2023 Security
Misconfiguration. Es una convención de este proyecto, no una asignación oficial de OWASP;
como referencia complementaria corresponden a OWASP Top 10:2021 (A03 Injection,
A02 Cryptographic Failures, A06 Vulnerable and Outdated Components).
"""

import re
from typing import Dict, Optional

OWASP_API_2023: Dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery (SSRF)",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

DEFAULT_CATEGORY = "API8:2023"

# CWE → categoría. Lo no listado y sin categoría propia cae en API8 vía category_for_cwe.
_CWE: Dict[int, str] = {
    # API1 — acceso a objetos ajenos
    639: "API1:2023",
    284: "API1:2023",
    # API2 — autenticación y credenciales
    287: "API2:2023",
    798: "API2:2023",
    259: "API2:2023",
    521: "API2:2023",
    613: "API2:2023",
    347: "API2:2023",
    330: "API2:2023",
    338: "API2:2023",
    # API3 — exposición de propiedades / datos en respuestas
    200: "API3:2023",
    213: "API3:2023",
    915: "API3:2023",
    # API4 — consumo de recursos
    770: "API4:2023",
    400: "API4:2023",
    799: "API4:2023",
    # API5 — autorización a nivel de función
    285: "API5:2023",
    862: "API5:2023",
    863: "API5:2023",
    # API7 — SSRF
    918: "API7:2023",
}

# Reglas de Bandit que no son API8 (el resto de reglas de Bandit → API8).
_BANDIT: Dict[str, str] = {
    "b105": "API2:2023",  # hardcoded password string
    "b106": "API2:2023",  # hardcoded password funcarg
    "b107": "API2:2023",  # hardcoded password default
    "b311": "API2:2023",  # random no criptográfico (tokens)
    "b310": "API7:2023",  # urllib.urlopen con esquemas arbitrarios
}

# Palabras clave en tipos / nombres de alerta → categoría. Se evalúan en orden.
_KEYWORDS = [
    (("bola", "idor", "broken_object_level", "broken object level", "broken_access_control"), "API1:2023"),
    (
        (
            "broken_auth",
            "broken auth",
            "authentication",
            "jwt",
            "hardcoded_password",
            "hardcoded_credentials",
            "hardcoded password",
            "default credentials",
            "insecure_random",
            "insecure random",
            "predictable token",
            "session",
        ),
        "API2:2023",
    ),
    (
        ("mass_assignment", "mass assignment", "sensitive_data_exposure", "excessive data", "object property"),
        "API3:2023",
    ),
    (("rate limit", "rate_limit", "resource consumption", "resource_consumption"), "API4:2023"),
    (("http methods", "http_methods", "function level", "function_level"), "API5:2023"),
    (("business flow", "business_flow"), "API6:2023"),
    (("ssrf", "server side request", "server_side_request"), "API7:2023"),
    (("inventory", "sensitive endpoint", "sensitive_endpoint", "asset management"), "API9:2023"),
    (("unsafe consumption", "unsafe_consumption", "third-party api", "third party api"), "API10:2023"),
    # Sin categoría propia en 2023 → API8 (ver docstring del módulo)
    (
        (
            "injection",
            "sqli",
            "xss",
            "cross-site scripting",
            "cross site scripting",
            "cross_site_scripting",
            "traversal",
            "deserializ",
            "xxe",
            "redirect",
            "crypto",
            "misconfig",
            "header",
            "cors",
            "debug",
            "disclosure",
            "transport",
            "tls",
            "ssl",
            "vulnerable dependenc",
        ),
        DEFAULT_CATEGORY,
    ),
]


def cwe_number(raw) -> Optional[int]:
    """'CWE-89', 'cwe-89', 89 o {'id': 89} → 89 (comparación exacta, sin subcadenas)."""
    if isinstance(raw, dict):
        raw = raw.get("id")
    if raw is None:
        return None
    m = re.search(r"\d+", str(raw))
    return int(m.group()) if m else None


def category_for_cwe(raw) -> Optional[str]:
    """Categoría para un CWE; None si no hay CWE."""
    n = cwe_number(raw)
    if n is None or n == 0:
        return None
    return _CWE.get(n, DEFAULT_CATEGORY)


def category_for_bandit(test_id: str) -> Optional[str]:
    """Categoría para una regla de Bandit (p. ej. 'B608'); None si no es una regla de Bandit."""
    t = (test_id or "").strip().lower()
    if not re.fullmatch(r"b\d{3}", t):
        return None
    return _BANDIT.get(t, DEFAULT_CATEGORY)


def category_for_text(text: str) -> Optional[str]:
    """Categoría por palabras clave en un tipo o nombre de alerta; None si ninguna coincide."""
    t = (text or "").lower()
    for keywords, category in _KEYWORDS:
        if any(k in t for k in keywords):
            return category
    return None


def categorize(finding: dict) -> str:
    """
    Categoría de un hallazgo (dict), calculada a partir de su contenido:
    1. regla de Bandit (test_id)
    2. palabras clave del tipo / nombre de alerta
    3. CWE
    4. owasp_category guardada (solo si es válida en 2023), como último recurso
    La etiqueta guardada va al final a propósito: escaneos antiguos se generaron con la
    numeración 2019 (p. ej. cabeceras como API7) y deben recategorizarse al leerlos.
    Devuelve '' si no hay información suficiente.
    """
    explicit = finding.get("owasp_category") or finding.get("owasp")
    return (
        category_for_bandit(finding.get("test_id", ""))
        or category_for_text(str(finding.get("type") or finding.get("alert") or finding.get("name") or ""))
        or category_for_cwe(finding.get("cwe") or finding.get("issue_cwe") or finding.get("cwe_id"))
        or (explicit if explicit in OWASP_API_2023 else "")
    )
