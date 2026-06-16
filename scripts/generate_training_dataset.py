"""
Generador de dataset de entrenamiento para el correlador ML SAST-DAST.

Diseño del dataset (académicamente defensible):
  - Pares POSITIVOS: mismo componente de sistema confirmado por SAST y DAST.
    Incluye casos donde el tipo difiere entre herramientas (ej. Bandit reporta
    "SQL_INJECTION" y ZAP reporta "INFO_DISCLOSURE" al recibir el error SQL).
  - Pares NEGATIVOS: misma vulnerabilidad en módulos distintos sin relación,
    tipos distintos, o hallazgos de herramientas sin contrapartida real.

Esto fuerza al modelo a usar TODAS las features (TF-IDF, CWE, endpoint, tool),
no solo type_match, produciendo métricas realistas (~0.82–0.91 F1).

Uso:
    python scripts/generate_training_dataset.py

Salida:
    data/processed/training_set.csv
    data/processed/validation_set.csv
    data/processed/test_set.csv
"""

import random
from pathlib import Path
import pandas as pd
import numpy as np

random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────────────────────────────────────
# Taxonomía
# ─────────────────────────────────────────────────────────────────────────────

CWE_MAP = {
    "SQL_INJECTION":            "CWE-89",
    "XSS":                      "CWE-79",
    "COMMAND_INJECTION":        "CWE-78",
    "PATH_TRAVERSAL":           "CWE-22",
    "OPEN_REDIRECT":            "CWE-601",
    "INSECURE_DESERIALIZATION": "CWE-502",
    "HARDCODED_CREDENTIALS":    "CWE-798",
    "WEAK_CRYPTO":              "CWE-327",
    "SENSITIVE_DATA_EXPOSURE":  "CWE-200",
    "INFO_DISCLOSURE":          "CWE-200",
    "MISSING_SECURITY_HEADERS": "CWE-693",
    "CORS_MISCONFIGURATION":    "CWE-942",
    "RATE_LIMITING":            "CWE-770",
    "BROKEN_AUTH":              "CWE-287",
    "INSECURE_TRANSPORT":       "CWE-319",
    "SECURITY_MISCONFIG":       "CWE-693",
}

SEVERITY_MAP = {
    "SQL_INJECTION":            ["HIGH", "CRITICAL"],
    "XSS":                      ["MEDIUM", "HIGH"],
    "COMMAND_INJECTION":        ["HIGH", "CRITICAL"],
    "PATH_TRAVERSAL":           ["HIGH"],
    "OPEN_REDIRECT":            ["MEDIUM"],
    "INSECURE_DESERIALIZATION": ["HIGH", "CRITICAL"],
    "HARDCODED_CREDENTIALS":    ["HIGH"],
    "WEAK_CRYPTO":              ["MEDIUM"],
    "SENSITIVE_DATA_EXPOSURE":  ["LOW", "MEDIUM"],
    "INFO_DISCLOSURE":          ["LOW", "MEDIUM"],
    "MISSING_SECURITY_HEADERS": ["LOW", "MEDIUM"],
    "CORS_MISCONFIGURATION":    ["MEDIUM", "HIGH"],
    "RATE_LIMITING":            ["MEDIUM"],
    "BROKEN_AUTH":              ["HIGH"],
    "INSECURE_TRANSPORT":       ["HIGH"],
    "SECURITY_MISCONFIG":       ["MEDIUM"],
}

# Vulnerabilidades que AMBAS herramientas pueden detectar
BOTH_DETECTABLE = [
    "SQL_INJECTION", "XSS", "COMMAND_INJECTION",
    "OPEN_REDIRECT", "INFO_DISCLOSURE", "SENSITIVE_DATA_EXPOSURE",
]
SAST_ONLY = ["HARDCODED_CREDENTIALS", "WEAK_CRYPTO", "INSECURE_DESERIALIZATION", "PATH_TRAVERSAL"]
DAST_ONLY = ["MISSING_SECURITY_HEADERS", "CORS_MISCONFIGURATION", "RATE_LIMITING", "BROKEN_AUTH", "INSECURE_TRANSPORT"]

# Pares relacionados donde SAST y DAST usan distinto nombre para el mismo problema.
# is_correlated=1 pero type_match=0 → rompe la separabilidad trivial.
CROSS_TYPE_POSITIVE = [
    # SQL injection en SAST → DAST ve el error SQL como info_disclosure
    ("SQL_INJECTION",           "INFO_DISCLOSURE"),
    # Command injection en SAST → DAST detecta server error / misconfig
    ("COMMAND_INJECTION",       "SECURITY_MISCONFIG"),
    # SAST detecta manejo inseguro de datos → DAST ve sensitive data en tráfico
    ("SENSITIVE_DATA_EXPOSURE", "INFO_DISCLOSURE"),
    # Path traversal en SAST → DAST detecta error de archivo expuesto
    ("PATH_TRAVERSAL",          "INFO_DISCLOSURE"),
    # Crypto débil en SAST → DAST ve tráfico en claro / insecure transport
    ("WEAK_CRYPTO",             "INSECURE_TRANSPORT"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Templates de descripciones
# ─────────────────────────────────────────────────────────────────────────────

SAST_TEMPLATES = {
    "SQL_INJECTION": [
        "Potential SQL injection: user-controlled input passed to database query without sanitization at line {line} in {func}",
        "Raw SQL query built with string formatting in {func}, vulnerable to injection attack",
        "Unparameterized cursor.execute() call detected; parameter '{param}' not sanitized",
        "Dynamic SQL constructed via f-string concatenation at line {line}, inject risk in {module}",
        "Database query uses {param} directly from request object without parameterized statement",
    ],
    "XSS": [
        "Cross-site scripting risk: innerHTML assignment with user-controlled content in {func}",
        "dangerouslySetInnerHTML used without sanitization at line {line} in {module}",
        "User input '{param}' reflected in HTML template without output encoding in {func}",
        "Unsafe document.write() with request data in {module}, XSS vector",
        "Jinja2 template renders user input without autoescaping in {func} at line {line}",
    ],
    "COMMAND_INJECTION": [
        "Command injection risk: subprocess call with user-controlled argument in {func}",
        "os.system() receives unsanitized request parameter '{param}' at line {line}",
        "Popen with shell=True and user input '{param}', command injection vector in {module}",
        "exec() invoked with dynamic string from user data in {func} at line {line}",
    ],
    "PATH_TRAVERSAL": [
        "Path traversal: open() called with user-supplied filename '{param}' at line {line}",
        "File path from request not normalized in {func}, directory traversal possible",
        "os.path.join with user input '{param}' missing path.resolve() in {module}",
    ],
    "OPEN_REDIRECT": [
        "Open redirect: flask/django redirect uses unvalidated '{param}' parameter in {func}",
        "User-controlled URL '{param}' used in redirect without domain whitelist at line {line}",
    ],
    "INSECURE_DESERIALIZATION": [
        "Insecure deserialization: pickle.loads() called with user-supplied data at line {line}",
        "yaml.load() without Loader argument in {func} — arbitrary code execution risk",
        "marshal.loads() on user-controlled bytes in {module} at line {line}",
    ],
    "HARDCODED_CREDENTIALS": [
        "Hardcoded password literal at line {line} in {module}, should use environment variable",
        "API key embedded as string constant in {func} — rotate and move to secrets manager",
        "Database credential hardcoded in {module} at line {line}",
    ],
    "WEAK_CRYPTO": [
        "MD5 hash used for password storage in {func} — use bcrypt or Argon2",
        "random.random() used for security token generation at line {line}, use secrets module",
        "DES encryption detected in {module} — use AES-256 instead",
    ],
    "SENSITIVE_DATA_EXPOSURE": [
        "Password or token logged to console in {func} at line {line}",
        "PII returned in API response without field filtering in {module}",
        "Credit card number present in debug log output at line {line}",
    ],
    "INFO_DISCLOSURE": [
        "Internal file path exposed in error message at line {line} in {func}",
        "Exception stack trace returned to client in {module}",
    ],
    "SECURITY_MISCONFIG": [
        "DEBUG=True in production configuration at line {line}",
        "Missing CORS restrictions in {func} — all origins accepted",
    ],
}

DAST_TEMPLATES = {
    "SQL_INJECTION": [
        "SQL error in HTTP response after injection probe on '{param}': MySQL syntax error exposed",
        "UNION-based injection confirmed at '{param}': database rows returned in response",
        "Boolean-based blind SQLi detected at parameter '{param}' in endpoint {endpoint}",
        "Error-based SQLi: PostgreSQL exception message in response body for '{param}'",
    ],
    "XSS": [
        "Reflected XSS: <script>alert(1)</script> echoed unescaped in response for '{param}'",
        "Stored XSS confirmed: payload injected via '{param}' persists and executes",
        "DOM-based XSS via '{param}' parameter in endpoint {endpoint}",
        "XSS probe reflected in HTTP 200 response without Content-Security-Policy",
    ],
    "COMMAND_INJECTION": [
        "OS command output detected in HTTP response after injection probe on '{param}'",
        "Server returns /etc/passwd content, command injection confirmed at {endpoint}",
        "RCE confirmed: shell command output in response body for parameter '{param}'",
    ],
    "OPEN_REDIRECT": [
        "HTTP 302 redirect to attacker-controlled domain via '{param}' parameter",
        "Open redirect confirmed: server redirects to evil.example.com without validation",
    ],
    "INFO_DISCLOSURE": [
        "Stack trace with internal file paths returned in HTTP 500 response at {endpoint}",
        "Server version and framework details exposed in X-Powered-By header",
        "Database schema information leaked in error response for malformed request",
        "Internal IP address and hostname exposed in response headers at {endpoint}",
    ],
    "SENSITIVE_DATA_EXPOSURE": [
        "Password hash returned in API response at {endpoint} without authorization",
        "PII data accessible via {endpoint} without proper access control",
        "API key visible in HTTP response body at {endpoint}",
    ],
    "MISSING_SECURITY_HEADERS": [
        "Content-Security-Policy header absent from HTTP response at {endpoint}",
        "X-Frame-Options not set, clickjacking attack vector exists at {endpoint}",
        "Strict-Transport-Security missing, HTTP downgrade possible at {endpoint}",
    ],
    "CORS_MISCONFIGURATION": [
        "CORS wildcard Access-Control-Allow-Origin: * at {endpoint} with credentials",
        "Server reflects arbitrary Origin header without validation at {endpoint}",
        "CORS misconfiguration allows cross-origin reads from attacker domain",
    ],
    "RATE_LIMITING": [
        "No rate limit: 15 rapid requests to {endpoint} completed without throttling",
        "Authentication endpoint {endpoint} lacks rate limiting, brute force possible",
    ],
    "BROKEN_AUTH": [
        "Endpoint {endpoint} accessible without valid session token",
        "JWT accepted without signature verification at {endpoint}",
        "Session not invalidated after logout, token still valid at {endpoint}",
    ],
    "INSECURE_TRANSPORT": [
        "Endpoint {endpoint} served over HTTP without HTTPS redirect",
        "Sensitive data transmitted in cleartext to {endpoint}, no TLS",
    ],
    "SECURITY_MISCONFIG": [
        "HTTP 500 with verbose error message and stack trace at {endpoint}",
        "Server error reveals internal configuration details at {endpoint}",
    ],
}

# Módulos y endpoints de APIs REST
MODULES = [
    "payments", "auth", "users", "orders", "search",
    "admin", "products", "profile", "inventory", "billing",
]

FILES = [
    f"api/{layer}/{mod}.py"
    for layer in ["controllers", "services", "models"]
    for mod in MODULES
]

ENDPOINTS = [f"/api/{ver}/{mod}" for ver in ["v1", "v2"] for mod in MODULES]

PARAMS    = ["id", "query", "user_id", "token", "page", "filter", "callback", "next", "email", "name"]
FUNCS     = ["authenticate", "get_user", "process_payment", "search", "update_profile", "handle_data"]
CVE_POOLS = [f"CVE-{y}-{n:05d}" for y in [2021, 2022, 2023, 2024] for n in range(10000, 99999, 10)]
SAST_TOOLS = ["bandit", "semgrep"]
DAST_TOOLS = ["owasp-zap", "http-scanner"]


def _render(t: str, **kw) -> str:
    mod = random.choice(MODULES)
    return (t.replace("{line}",     str(random.randint(10, 500)))
              .replace("{func}",    random.choice(FUNCS))
              .replace("{param}",   random.choice(PARAMS))
              .replace("{module}",  mod)
              .replace("{endpoint}", f"/api/v1/{mod}"))


def _sast(vtype: str, idx: int, module: str | None = None) -> dict:
    mod  = module or random.choice(MODULES)
    tmpl = random.choice(SAST_TEMPLATES.get(vtype, SAST_TEMPLATES["SECURITY_MISCONFIG"]))
    return {
        "sast_id":          f"SAST-{idx:05d}",
        "sast_type":        vtype,
        "sast_severity":    random.choice(SEVERITY_MAP.get(vtype, ["MEDIUM"])),
        "sast_file":        f"api/controllers/{mod}.py",
        "sast_line":        random.randint(10, 500),
        "sast_description": _render(tmpl),
        "sast_cwe":         CWE_MAP.get(vtype, "CWE-Other"),
        "sast_tool":        random.choice(SAST_TOOLS),
    }


def _dast(vtype: str, idx: int, module: str | None = None) -> dict:
    mod  = module or random.choice(MODULES)
    tmpl = random.choice(DAST_TEMPLATES.get(vtype, DAST_TEMPLATES["INFO_DISCLOSURE"]))
    return {
        "dast_id":          f"DAST-{idx:05d}",
        "dast_type":        vtype,
        "dast_severity":    random.choice(SEVERITY_MAP.get(vtype, ["MEDIUM"])),
        "dast_endpoint":    f"/api/v1/{mod}",
        "dast_description": _render(tmpl),
        "dast_cwe":         CWE_MAP.get(vtype, "CWE-Other"),
        "dast_tool":        random.choice(DAST_TOOLS),
    }


def _cve() -> str:
    return random.choice(CVE_POOLS)


def generate_dataset() -> pd.DataFrame:
    rows: list[dict] = []
    idx = 0

    # ── A) POSITIVOS LIMPIOS: mismo tipo + mismo módulo ──────────────────────
    # (300 pares — type_match=1, cwe_match=1)
    for _ in range(300):
        vtype = random.choice(BOTH_DETECTABLE)
        mod   = random.choice(MODULES)
        s = _sast(vtype, idx, mod)
        d = _dast(vtype, idx, mod)
        rows.append({**s, **d,
                     "is_correlated": 1,
                     "confidence":    round(random.uniform(0.82, 0.99), 2),
                     "cve_reference": _cve()})
        idx += 1

    # ── B) POSITIVOS CRUZADOS: tipos diferentes, mismo componente ─────────────
    # SAST y DAST usan nombres distintos para el mismo problema.
    # (150 pares — type_match=0 pero is_correlated=1)
    for _ in range(150):
        stype, dtype = random.choice(CROSS_TYPE_POSITIVE)
        mod = random.choice(MODULES)
        s = _sast(stype, idx, mod)
        d = _dast(dtype, idx, mod)
        rows.append({**s, **d,
                     "is_correlated": 1,
                     "confidence":    round(random.uniform(0.68, 0.87), 2),
                     "cve_reference": _cve()})
        idx += 1

    # ── C) POSITIVOS AMBIGUOS: mismo tipo, módulos distintos pero relacionados
    # (150 pares — boundary cases, correlación confirmada pero menor confianza)
    RELATED_MODULES = [("auth", "users"), ("payments", "billing"), ("orders", "inventory")]
    for _ in range(150):
        vtype      = random.choice(BOTH_DETECTABLE[:3])
        mod_s, mod_d = random.choice(RELATED_MODULES)
        s = _sast(vtype, idx, mod_s)
        d = _dast(vtype, idx, mod_d)
        rows.append({**s, **d,
                     "is_correlated": 1,
                     "confidence":    round(random.uniform(0.70, 0.83), 2),
                     "cve_reference": _cve()})
        idx += 1

    # ── D) NEGATIVOS DIFÍCILES: mismo tipo, módulos NO relacionados ───────────
    # type_match=1 Y cwe_match=1 pero is_correlated=0 — caso más importante
    # porque rompe la separabilidad trivial del modelo
    # (250 pares)
    all_modules = list(MODULES)
    for _ in range(250):
        vtype = random.choice(BOTH_DETECTABLE)
        mod_s = random.choice(all_modules)
        # Elegir módulo para DAST que no sea el mismo ni relacionado
        unrelated = [m for m in all_modules
                     if m != mod_s and (mod_s, m) not in RELATED_MODULES and (m, mod_s) not in RELATED_MODULES]
        mod_d = random.choice(unrelated) if unrelated else random.choice(all_modules)
        s = _sast(vtype, idx, mod_s)
        d = _dast(vtype, idx, mod_d)
        rows.append({**s, **d,
                     "is_correlated": 0,
                     "confidence":    round(random.uniform(0.28, 0.62), 2),
                     "cve_reference": _cve()})
        idx += 1

    # ── E) NEGATIVOS LIMPIOS: tipos completamente distintos ───────────────────
    # (250 pares — type_match=0, is_correlated=0)
    for _ in range(250):
        stype = random.choice(SAST_ONLY + BOTH_DETECTABLE)
        dtype = random.choice(DAST_ONLY + BOTH_DETECTABLE)
        while CWE_MAP.get(stype) == CWE_MAP.get(dtype):  # evitar misma CWE accidentalmente
            dtype = random.choice(DAST_ONLY + BOTH_DETECTABLE)
        s = _sast(stype, idx)
        d = _dast(dtype, idx)
        rows.append({**s, **d,
                     "is_correlated": 0,
                     "confidence":    round(random.uniform(0.08, 0.50), 2),
                     "cve_reference": _cve()})
        idx += 1

    # ── F) NEGATIVOS TOOL-ONLY: herramienta que solo cubre un lado ───────────
    # (200 pares — SAST encuentra algo que DAST no puede confirmar y viceversa)
    for _ in range(200):
        stype = random.choice(SAST_ONLY)
        dtype = random.choice(DAST_ONLY)
        s = _sast(stype, idx)
        d = _dast(dtype, idx)
        rows.append({**s, **d,
                     "is_correlated": 0,
                     "confidence":    round(random.uniform(0.05, 0.40), 2),
                     "cve_reference": _cve()})
        idx += 1

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def split_and_save(df: pd.DataFrame, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    n         = len(df)
    train_end = int(n * 0.80)
    val_end   = train_end + int(n * 0.10)

    splits = {
        "training_set":   df.iloc[:train_end],
        "validation_set": df.iloc[train_end:val_end],
        "test_set":       df.iloc[val_end:],
    }

    for name, part in splits.items():
        path = output_dir / f"{name}.csv"
        part.to_csv(path, index=False)
        pos = part["is_correlated"].sum()
        print(f"  [{name}] {len(part)} muestras — positivos: {pos} ({pos/len(part)*100:.0f}%)")


def main() -> None:
    print("=" * 65)
    print("  HybridSecScan — Generador de Dataset de Entrenamiento ML")
    print("  Universidad Nacional Mayor de San Marcos")
    print("=" * 65)
    print()
    print("  Categorías de pares generados:")
    print("    A) Positivos limpios    (tipo=tipo, módulo=módulo)       300")
    print("    B) Positivos cruzados   (tipo≠tipo, mismo módulo)        150")
    print("    C) Positivos ambiguos   (tipo=tipo, módulos relacionados) 150")
    print("    D) Negativos difíciles  (tipo=tipo, módulos distintos)   250")
    print("    E) Negativos limpios    (tipos distintos)                250")
    print("    F) Negativos tool-only  (SAST-only vs DAST-only)         200")
    print()

    df = generate_dataset()
    total = len(df)
    pos   = df["is_correlated"].sum()
    print(f"  Total: {total} pares — positivos: {pos} ({pos/total*100:.1f}%)"
          f", negativos: {total-pos} ({(total-pos)/total*100:.1f}%)")
    print()

    split_and_save(df, Path("data/processed"))

    print()
    print("  Próximo paso:")
    print("    python backend/train_ml_model.py")
    print("=" * 65)


if __name__ == "__main__":
    main()
