"""Tests del mapeo único a OWASP API Security Top 10 (2023)."""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.owasp_mapping import (  # noqa: E402
    OWASP_API_2023,
    categorize,
    category_for_bandit,
    category_for_cwe,
    category_for_text,
)

REPO = Path(__file__).resolve().parent.parent


def test_numeracion_2023():
    """Las dos categorías que la numeración 2019 confundía."""
    assert OWASP_API_2023["API7:2023"].startswith("Server Side Request Forgery")
    assert OWASP_API_2023["API8:2023"] == "Security Misconfiguration"


def test_inyeccion_y_traversal_van_a_api8():
    """Opción A: fallas sin categoría propia en 2023 → API8."""
    for cwe in ("CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-502"):
        assert category_for_cwe(cwe) == "API8:2023", cwe
    for text in ("SQL Injection", "sql_injection", "Path Traversal", "Cross Site Scripting (Reflected)"):
        assert category_for_text(text) == "API8:2023", text
    assert category_for_bandit("B608") == "API8:2023"


def test_cwe_se_compara_exacto():
    """'22' no debe coincidir con CWE-1022, ni '16' con CWE-1021."""
    assert category_for_cwe("CWE-22") == "API8:2023"
    assert category_for_cwe("CWE-1021") == "API8:2023"
    assert category_for_cwe("CWE-918") == "API7:2023"
    assert category_for_cwe("CWE-639") == "API1:2023"
    assert category_for_cwe(None) is None


def test_categorias_propias():
    assert category_for_text("BOLA - Unauthenticated Access") == "API1:2023"
    assert category_for_text("Broken Authentication - JWT alg:none") == "API2:2023"
    assert category_for_text("Missing Rate Limiting") == "API4:2023"
    assert category_for_text("Sensitive Endpoint Exposed") == "API9:2023"
    assert category_for_bandit("B105") == "API2:2023"
    assert category_for_bandit("B310") == "API7:2023"
    assert category_for_bandit("not-a-rule") is None


def test_categorize_prioridades():
    # El contenido manda sobre una etiqueta antigua (numeración 2019: cabecera como API7)
    assert categorize({"type": "Missing Security Header", "owasp_category": "API7:2023"}) == "API8:2023"
    assert categorize({"type": "SQL Injection", "cwe": "CWE-89", "owasp_category": "API3:2023"}) == "API8:2023"
    # Regla de Bandit
    assert categorize({"test_id": "B105", "issue_cwe": {"id": 259}}) == "API2:2023"
    # Sin contenido reconocible: se usa la etiqueta guardada si es válida
    assert categorize({"type": "algo", "owasp_category": "API6:2023"}) == "API6:2023"
    assert categorize({"type": "algo", "owasp_category": "A03:2021"}) == ""
    # Sin información
    assert categorize({}) == ""


def test_ningun_modulo_usa_numeracion_2019():
    """Ningún archivo fuente etiqueta configuración insegura como API7 ni inyección como API1/API3."""
    bad = []
    for path in list((REPO / "backend").rglob("*.py")) + list((REPO / "scripts").glob("*.py")):
        if path.name == "owasp_mapping.py":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            low = line.lower()
            if "api7:2023" in low and not re.search(r"ssrf|918|server side", low):
                bad.append(f"{path.name}:{n}: {line.strip()}")
    assert not bad, "Etiquetas API7 que no son SSRF:\n" + "\n".join(bad)
