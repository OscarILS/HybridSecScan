"""
Motor de análisis DAST real para HybridSecScan.

Implementa dos estrategias:
  1. ZAPDaemonScanner  — usa OWASP ZAP si está corriendo como daemon en :8080
  2. HTTPSecurityScanner — probing HTTP activo, siempre disponible

La función pública `run_dast_scan()` intenta ZAP primero y cae al HTTP Scanner
si ZAP no está disponible. Ambas rutas producen hallazgos reales y estructurados.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constantes de configuración
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 10

# Header → (severidad, OWASP API Top 10, CWE, descripción)
SECURITY_HEADERS: Dict[str, Tuple[str, str, str, str]] = {
    "Content-Security-Policy":   ("HIGH",   "API7:2023", "CWE-693",  "Previene XSS e inyección de contenido"),
    "X-Frame-Options":           ("MEDIUM", "API7:2023", "CWE-1021", "Previene ataques de clickjacking"),
    "X-Content-Type-Options":    ("LOW",    "API7:2023", "CWE-693",  "Previene MIME-type sniffing"),
    "Strict-Transport-Security": ("HIGH",   "API7:2023", "CWE-319",  "Fuerza conexiones HTTPS"),
    "Referrer-Policy":           ("LOW",    "API7:2023", "CWE-200",  "Controla información del referrer"),
    "Permissions-Policy":        ("LOW",    "API7:2023", "CWE-693",  "Controla permisos del navegador"),
}

# (path, severidad, descripción legible)
SENSITIVE_PATHS: List[Tuple[str, str, str]] = [
    ("/.env",              "HIGH",     "Variables de entorno expuestas"),
    ("/config",            "HIGH",     "Endpoint de configuración accesible"),
    ("/config.json",       "HIGH",     "Configuración JSON expuesta"),
    ("/admin",             "HIGH",     "Panel administrativo expuesto"),
    ("/admin/",            "HIGH",     "Panel administrativo expuesto"),
    ("/api/admin",         "HIGH",     "Endpoint administrativo API expuesto"),
    ("/swagger.json",      "MEDIUM",   "Documentación Swagger pública"),
    ("/openapi.json",      "MEDIUM",   "Especificación OpenAPI pública"),
    ("/api-docs",          "MEDIUM",   "Documentación de API pública"),
    ("/docs",              "MEDIUM",   "Documentación pública"),
    ("/actuator",          "HIGH",     "Spring Boot Actuator expuesto"),
    ("/actuator/env",      "CRITICAL", "Variables de entorno vía Actuator"),
    ("/actuator/dump",     "CRITICAL", "Dump de threads vía Actuator"),
    ("/metrics",           "MEDIUM",   "Métricas del sistema expuestas"),
    ("/debug",             "HIGH",     "Endpoint de debug accesible"),
    ("/phpinfo.php",       "HIGH",     "phpinfo() expuesto"),
    ("/.git/config",       "CRITICAL", "Repositorio Git expuesto"),
    ("/health",            "LOW",      "Endpoint de health check público"),
]

DANGEROUS_HTTP_METHODS = {"TRACE", "CONNECT"}

# Patrones de exposición de stack traces en respuestas
STACK_TRACE_PATTERNS = [
    "Traceback (most recent call last)",
    'File "', "line ",
    "at com.", "at org.", "at java.",
    "System.Exception", "NullPointerException",
    "Microsoft.CSharp",
    "SQLException", "ORA-", "MySQL server",
    "stack trace:", "StackTrace",
]

RATE_LIMIT_PROBE_COUNT = 15
RATE_LIMIT_PROBE_DELAY = 0.05   # segundos entre requests


# ──────────────────────────────────────────────────────────────────────────────
# Modelo de hallazgo
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanFinding:
    """Hallazgo DAST normalizado, compatible con el correlador SAST."""
    id:              str  = field(default_factory=lambda: str(uuid.uuid4()))
    type:            str  = ""
    alert:           str  = ""
    severity:        str  = "LOW"
    risk:            str  = "Low"
    confidence:      str  = "Medium"
    url:             str  = ""
    parameter:       str  = ""
    description:     str  = ""
    solution:        str  = ""
    evidence:        str  = ""
    cwe:             str  = ""
    cweid:           str  = ""
    owasp_category:  str  = ""
    source:          str  = "HTTP Scanner"
    request_payload: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":              self.id,
            "type":            self.type,
            "alert":           self.alert,
            "severity":        self.severity,
            "risk":            self.risk,
            "confidence":      self.confidence,
            "url":             self.url,
            "parameter":       self.parameter,
            "description":     self.description,
            "solution":        self.solution,
            "evidence":        self.evidence,
            "cwe":             self.cwe,
            "cweid":           self.cweid,
            "owasp_category":  self.owasp_category,
            "source":          self.source,
            "request_payload": self.request_payload,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Scanner HTTP real (siempre disponible)
# ──────────────────────────────────────────────────────────────────────────────

class HTTPSecurityScanner:
    """
    Scanner DAST que realiza peticiones HTTP reales al objetivo.

    Cubre las siguientes categorías OWASP API Security Top 10 (2023):
      - API4:2023  Unrestricted Resource Consumption  → rate limiting
      - API5:2023  Broken Function Level Authorization → HTTP methods
      - API7:2023  Security Misconfiguration          → security headers, SSL
      - API8:2023  Security Misconfiguration (impl.)  → CORS, error disclosure, server info
      - API9:2023  Improper Inventory Management      → sensitive endpoints
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "HybridSecScan/2.0 Security Scanner"

    def scan(self, target_url: str) -> List[ScanFinding]:
        logger.info(f"[HTTPScanner] Iniciando escaneo real contra {target_url}")
        findings: List[ScanFinding] = []

        checks = [
            ("security_headers",    self._check_security_headers),
            ("cors_policy",         self._check_cors_policy),
            ("sensitive_endpoints", self._check_sensitive_endpoints),
            ("http_methods",        self._check_http_methods),
            ("error_disclosure",    self._check_error_disclosure),
            ("rate_limiting",       self._check_rate_limiting),
            ("server_info",         self._check_server_info),
            ("ssl_config",          self._check_ssl),
        ]

        for name, check in checks:
            try:
                result = check(target_url)
                findings.extend(result)
                logger.info(f"  [{name}] {len(result)} hallazgo(s)")
            except Exception as exc:
                logger.warning(f"  [{name}] falló: {exc}")

        logger.info(f"[HTTPScanner] Total hallazgos reales: {len(findings)}")
        return findings

    # ── checks individuales ───────────────────────────────────────────────────

    def _check_security_headers(self, url: str) -> List[ScanFinding]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            present = set(resp.headers.keys())
            payload = {
                "method": "GET",
                "url": url,
                "sent_headers": {"User-Agent": "HybridSecScan/2.0 Security Scanner"},
                "probe": "Inspección de cabeceras de seguridad HTTP",
                "response": f"HTTP {resp.status_code} — {len(present)} headers recibidos",
            }
            for header, (severity, owasp, cwe, explanation) in SECURITY_HEADERS.items():
                if header not in present:
                    findings.append(ScanFinding(
                        type="Missing Security Header",
                        alert=f"Header ausente: {header}",
                        severity=severity,
                        risk=severity.capitalize(),
                        confidence="High",
                        url=url,
                        parameter=header,
                        description=(
                            f'El header HTTP "{header}" no está presente en la respuesta. '
                            f"{explanation}."
                        ),
                        solution=f'Agregar el header "{header}" en la configuración del servidor.',
                        evidence=f"Header no encontrado. Headers presentes: {sorted(present)}",
                        cwe=cwe,
                        cweid=cwe.replace("CWE-", ""),
                        owasp_category=owasp,
                        source="HTTP Scanner – Security Headers",
                        request_payload={**payload, "missing_header": header},
                    ))
        except Exception as exc:
            logger.debug(f"security_headers: {exc}")
        return findings

    def _check_cors_policy(self, url: str) -> List[ScanFinding]:
        findings = []
        try:
            # Probe con origen malicioso
            evil = "https://evil-attacker.example.com"
            resp = self.session.get(
                url,
                headers={"Origin": evil},
                timeout=self.timeout,
                verify=False,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            evil_payload = {
                "method": "GET",
                "url": url,
                "sent_headers": {
                    "Origin": evil,
                    "User-Agent": "HybridSecScan/2.0 Security Scanner",
                },
                "probe": "Inyección de origen hostil para verificar política CORS",
                "response": (
                    f"HTTP {resp.status_code} | "
                    f"Access-Control-Allow-Origin: {acao or '(ausente)'} | "
                    f"Access-Control-Allow-Credentials: {resp.headers.get('Access-Control-Allow-Credentials', '(ausente)')}"
                ),
            }

            if acao == "*" and acac == "true":
                findings.append(ScanFinding(
                    type="CORS Misconfiguration",
                    alert="CORS: Wildcard con credenciales habilitadas",
                    severity="CRITICAL",
                    risk="Critical",
                    confidence="High",
                    url=url,
                    parameter="Access-Control-Allow-Origin",
                    description=(
                        "El servidor permite CORS con wildcard (*) y credenciales habilitadas "
                        "simultáneamente. Cualquier origen puede hacer peticiones autenticadas."
                    ),
                    solution="Especificar orígenes explícitos en vez de wildcard cuando se usan credenciales.",
                    evidence=(
                        f"Access-Control-Allow-Origin: {acao}  |  "
                        f"Access-Control-Allow-Credentials: {resp.headers.get('Access-Control-Allow-Credentials')}"
                    ),
                    cwe="CWE-942",
                    cweid="942",
                    owasp_category="API8:2023",
                    source="HTTP Scanner – CORS",
                    request_payload=evil_payload,
                ))
            elif acao == evil:
                findings.append(ScanFinding(
                    type="CORS Misconfiguration",
                    alert="CORS: Reflexión de origen sin validación",
                    severity="HIGH",
                    risk="High",
                    confidence="High",
                    url=url,
                    parameter="Access-Control-Allow-Origin",
                    description=(
                        "El servidor refleja el origen de la petición en el header "
                        "Access-Control-Allow-Origin sin validación contra una lista blanca."
                    ),
                    solution="Validar el origen contra una lista explícita de orígenes permitidos.",
                    evidence=f"Origen enviado: {evil}  →  ACAO recibido: {acao}",
                    cwe="CWE-942",
                    cweid="942",
                    owasp_category="API8:2023",
                    source="HTTP Scanner – CORS",
                    request_payload=evil_payload,
                ))
            elif acao == "*":
                findings.append(ScanFinding(
                    type="CORS Misconfiguration",
                    alert="CORS: Wildcard sin restricción de origen",
                    severity="MEDIUM",
                    risk="Medium",
                    confidence="Medium",
                    url=url,
                    parameter="Access-Control-Allow-Origin",
                    description="El servidor permite peticiones desde cualquier origen (*).",
                    solution="Restringir Access-Control-Allow-Origin a orígenes conocidos.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    cwe="CWE-942",
                    cweid="942",
                    owasp_category="API8:2023",
                    source="HTTP Scanner – CORS",
                    request_payload=evil_payload,
                ))

            # Probe con origen null (explotable desde iframes sandboxed)
            null_resp = self.session.get(
                url,
                headers={"Origin": "null"},
                timeout=self.timeout,
                verify=False,
            )
            if null_resp.headers.get("Access-Control-Allow-Origin") == "null":
                findings.append(ScanFinding(
                    type="CORS Misconfiguration",
                    alert='CORS: Origen "null" aceptado',
                    severity="MEDIUM",
                    risk="Medium",
                    confidence="High",
                    url=url,
                    parameter="Access-Control-Allow-Origin",
                    description='El servidor acepta "null" como origen, explotable desde iframes sandboxed.',
                    solution='No incluir "null" como origen permitido en CORS.',
                    evidence='Access-Control-Allow-Origin: null',
                    cwe="CWE-942",
                    cweid="942",
                    owasp_category="API8:2023",
                    source="HTTP Scanner – CORS",
                    request_payload={
                        "method": "GET",
                        "url": url,
                        "sent_headers": {"Origin": "null"},
                        "probe": 'Prueba de origen "null" — explotable desde iframes sandboxed',
                        "response": f"HTTP {null_resp.status_code} | Access-Control-Allow-Origin: null",
                    },
                ))
        except Exception as exc:
            logger.debug(f"cors_policy: {exc}")
        return findings

    def _check_sensitive_endpoints(self, url: str) -> List[ScanFinding]:
        findings = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path, severity, desc in SENSITIVE_PATHS:
            probe = f"{origin}{path}"
            try:
                resp = self.session.get(
                    probe,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                if resp.status_code in (200, 201, 202, 204):
                    findings.append(ScanFinding(
                        type="Sensitive Endpoint Exposed",
                        alert=f"Endpoint sensible accesible: {path}",
                        severity=severity,
                        risk=severity.capitalize(),
                        confidence="High",
                        url=probe,
                        parameter="path",
                        description=(
                            f"{desc}. El endpoint {path} devuelve HTTP {resp.status_code} "
                            "sin requerir autenticación."
                        ),
                        solution=f"Proteger {path} con autenticación/autorización o deshabilitarlo.",
                        evidence=(
                            f"HTTP {resp.status_code} en {probe}  |  "
                            f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}"
                        ),
                        cwe="CWE-200",
                        cweid="200",
                        owasp_category="API9:2023",
                        source="HTTP Scanner – Endpoint Discovery",
                        request_payload={
                            "method": "GET",
                            "url": probe,
                            "sent_headers": {
                                "User-Agent": "HybridSecScan/2.0 Security Scanner",
                            },
                            "probe": f"Descubrimiento de ruta sensible: {path}",
                            "response": (
                                f"HTTP {resp.status_code} | "
                                f"Content-Type: {resp.headers.get('Content-Type', 'N/A')} | "
                                f"Content-Length: {resp.headers.get('Content-Length', len(resp.content))} bytes"
                            ),
                        },
                    ))
            except Exception:
                pass
        return findings

    def _check_http_methods(self, url: str) -> List[ScanFinding]:
        findings = []
        try:
            resp = self.session.options(url, timeout=self.timeout, verify=False)
            raw = resp.headers.get("Allow", resp.headers.get("Access-Control-Allow-Methods", ""))
            allowed = {m.strip().upper() for m in raw.split(",") if m.strip()}
            dangerous = DANGEROUS_HTTP_METHODS & allowed
            if dangerous:
                findings.append(ScanFinding(
                    type="Dangerous HTTP Methods Allowed",
                    alert=f"Métodos peligrosos habilitados: {', '.join(sorted(dangerous))}",
                    severity="MEDIUM",
                    risk="Medium",
                    confidence="High",
                    url=url,
                    parameter="Allow",
                    description=(
                        f"El servidor permite métodos HTTP potencialmente peligrosos: "
                        f"{', '.join(sorted(dangerous))}."
                    ),
                    solution="Deshabilitar TRACE y CONNECT. Proteger PUT/DELETE con autenticación.",
                    evidence=f"Allow: {raw}",
                    cwe="CWE-749",
                    cweid="749",
                    owasp_category="API5:2023",
                    source="HTTP Scanner – HTTP Methods",
                    request_payload={
                        "method": "OPTIONS",
                        "url": url,
                        "sent_headers": {"User-Agent": "HybridSecScan/2.0 Security Scanner"},
                        "probe": "Enumeración de métodos HTTP permitidos",
                        "response": (
                            f"HTTP {resp.status_code} | "
                            f"Allow: {raw or '(no especificado)'} | "
                            f"Métodos peligrosos confirmados: {', '.join(sorted(dangerous))}"
                        ),
                    },
                ))
        except Exception as exc:
            logger.debug(f"http_methods: {exc}")
        return findings

    def _check_error_disclosure(self, url: str) -> List[ScanFinding]:
        findings = []
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        probes = [
            (f"{url}?id='",                          "SQL injection probe",   "?id='"),
            (f"{url}?page=-9999",                    "Negative page probe",   "?page=-9999"),
            (f"{origin}/nonexistent_endpoint_xyz_abc", "Invalid path probe",  "/nonexistent_endpoint_xyz_abc"),
        ]

        for probe_url, probe_name, probe_payload in probes:
            try:
                resp = self.session.get(probe_url, timeout=self.timeout, verify=False)
                body = resp.text[:5000]
                for pattern in STACK_TRACE_PATTERNS:
                    if pattern.lower() in body.lower():
                        findings.append(ScanFinding(
                            type="Information Disclosure",
                            alert="Stack trace o error interno expuesto en respuesta HTTP",
                            severity="MEDIUM",
                            risk="Medium",
                            confidence="High",
                            url=probe_url,
                            parameter=probe_name,
                            description=(
                                f'La aplicación revela detalles internos de errores. '
                                f'Se detectó el patrón "{pattern}" en la respuesta '
                                f"HTTP {resp.status_code}. Puede exponer rutas, tecnologías y datos de BD."
                            ),
                            solution=(
                                "Implementar páginas de error genéricas para el cliente. "
                                "Registrar detalles internos en logs del servidor."
                            ),
                            evidence=f'Patrón "{pattern}" detectado en respuesta a {probe_url}',
                            cwe="CWE-209",
                            cweid="209",
                            owasp_category="API8:2023",
                            source="HTTP Scanner – Error Disclosure",
                            request_payload={
                                "method": "GET",
                                "url": probe_url,
                                "sent_headers": {"User-Agent": "HybridSecScan/2.0 Security Scanner"},
                                "probe": f"{probe_name} — payload: {probe_payload}",
                                "response": (
                                    f"HTTP {resp.status_code} | "
                                    f'Patrón detectado: "{pattern}" | '
                                    f"Body (primeros 200 chars): {body[:200].strip()!r}"
                                ),
                            },
                        ))
                        break
            except Exception:
                pass
        return findings

    def _check_rate_limiting(self, url: str) -> List[ScanFinding]:
        findings = []
        rate_limit_indicators = {
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "RateLimit-Limit",
            "Retry-After",
        }

        statuses: List[int] = []
        has_rate_limit = False

        try:
            for _ in range(RATE_LIMIT_PROBE_COUNT):
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    has_rate_limit = True
                    break
                if any(h in resp.headers for h in rate_limit_indicators):
                    has_rate_limit = True
                    break
                time.sleep(RATE_LIMIT_PROBE_DELAY)

            if not has_rate_limit:
                req_rate = 1 / RATE_LIMIT_PROBE_DELAY if RATE_LIMIT_PROBE_DELAY else 0
                findings.append(ScanFinding(
                    type="Missing Rate Limiting",
                    alert="Sin control de tasa (rate limiting) detectable",
                    severity="MEDIUM",
                    risk="Medium",
                    confidence="Medium",
                    url=url,
                    parameter="HTTP responses",
                    description=(
                        f"Se enviaron {RATE_LIMIT_PROBE_COUNT} peticiones rápidas sin obtener "
                        "respuesta 429 ni headers de rate limiting. La API puede ser vulnerable "
                        "a abuso de recursos o ataques de fuerza bruta."
                    ),
                    solution=(
                        "Implementar rate limiting por IP y por usuario. "
                        "Devolver HTTP 429 con header Retry-After al superar el límite."
                    ),
                    evidence=f"{RATE_LIMIT_PROBE_COUNT} requests. Códigos: {statuses}",
                    cwe="CWE-770",
                    cweid="770",
                    owasp_category="API4:2023",
                    source="HTTP Scanner – Rate Limiting",
                    request_payload={
                        "method": "GET (x{})".format(RATE_LIMIT_PROBE_COUNT),
                        "url": url,
                        "sent_headers": {"User-Agent": "HybridSecScan/2.0 Security Scanner"},
                        "probe": (
                            f"Flood de peticiones: {RATE_LIMIT_PROBE_COUNT} GETs "
                            f"a ~{req_rate:.0f} req/s (delay={RATE_LIMIT_PROBE_DELAY*1000:.0f}ms)"
                        ),
                        "response": (
                            f"Todos respondieron sin HTTP 429. "
                            f"Códigos obtenidos: {statuses}. "
                            f"Headers de rate limit ausentes (X-RateLimit-*, Retry-After)."
                        ),
                    },
                ))
        except Exception as exc:
            logger.debug(f"rate_limiting: {exc}")
        return findings

    def _check_server_info(self, url: str) -> List[ScanFinding]:
        findings = []
        info_headers = {
            "Server":           "versión del servidor web",
            "X-Powered-By":     "tecnología backend",
            "X-AspNet-Version": "versión de ASP.NET",
            "X-Generator":      "generador de la aplicación",
        }
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            for header, desc in info_headers.items():
                value = resp.headers.get(header, "")
                if value:
                    findings.append(ScanFinding(
                        type="Server Information Disclosure",
                        alert=f"Header {header} expone información del servidor",
                        severity="LOW",
                        risk="Low",
                        confidence="High",
                        url=url,
                        parameter=header,
                        description=(
                            f'El header "{header}" revela {desc} ("{value}"). '
                            "Facilita ataques dirigidos a versiones específicas."
                        ),
                        solution=f'Eliminar o suprimir el header "{header}" en la configuración del servidor.',
                        evidence=f"{header}: {value}",
                        cwe="CWE-200",
                        cweid="200",
                        owasp_category="API8:2023",
                        source="HTTP Scanner – Information Disclosure",
                        request_payload={
                            "method": "GET",
                            "url": url,
                            "sent_headers": {"User-Agent": "HybridSecScan/2.0 Security Scanner"},
                            "probe": "Inspección de headers de respuesta que revelan información del servidor",
                            "response": (
                                f"HTTP {resp.status_code} | "
                                f"Header filtrado → {header}: {value}"
                            ),
                        },
                    ))
        except Exception as exc:
            logger.debug(f"server_info: {exc}")
        return findings

    def _check_ssl(self, url: str) -> List[ScanFinding]:
        findings = []
        parsed = urlparse(url)
        if parsed.scheme == "http":
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)
                location = resp.headers.get("Location", "")
                if resp.status_code not in (301, 302, 307, 308) or not location.startswith("https"):
                    findings.append(ScanFinding(
                        type="Insecure Transport",
                        alert="API accesible sin HTTPS sin redirección",
                        severity="HIGH",
                        risk="High",
                        confidence="High",
                        url=url,
                        parameter="scheme",
                        description=(
                            "La API acepta conexiones HTTP sin cifrar y no redirige a HTTPS. "
                            "Los datos transmitidos son vulnerables a interceptación (MITM)."
                        ),
                        solution="Forzar HTTPS. Configurar redirección 301 HTTP → HTTPS y habilitar HSTS.",
                        evidence=f"HTTP {resp.status_code} desde {url} sin redirección HTTPS",
                        cwe="CWE-319",
                        cweid="319",
                        owasp_category="API8:2023",
                        source="HTTP Scanner – SSL/TLS",
                        request_payload={
                            "method": "GET",
                            "url": url,
                            "sent_headers": {"User-Agent": "HybridSecScan/2.0 Security Scanner"},
                            "probe": "Verificación de redirección HTTP → HTTPS (sin seguir redirects)",
                            "response": (
                                f"HTTP {resp.status_code} | "
                                f"Location: {location or '(sin Location header)'} | "
                                "Sin redirección a HTTPS — tráfico transmitido en texto plano"
                            ),
                        },
                    ))
            except Exception as exc:
                logger.debug(f"ssl_config: {exc}")
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# Cliente OWASP ZAP daemon (opcional)
# ──────────────────────────────────────────────────────────────────────────────

class ZAPDaemonScanner:
    """
    Controlador de OWASP ZAP en modo daemon vía su API REST.

    Para iniciar ZAP como daemon ejecutar (ejemplo Linux/macOS):
        zap.sh -daemon -port 8080 -host 127.0.0.1 \\
               -config api.disablekey=true \\
               -config api.addrs.addr.name=.* \\
               -config api.addrs.addr.enabled=true

    Con Docker:
        docker run -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \\
               zap.sh -daemon -port 8080 -host 0.0.0.0 \\
               -config api.disablekey=true
    """

    ZAP_URL         = "http://localhost:8080"
    SPIDER_TIMEOUT  = 120   # segundos
    ASCAN_TIMEOUT   = 300   # segundos
    POLL_INTERVAL   = 5     # segundos

    def is_available(self) -> bool:
        try:
            resp = requests.get(
                f"{self.ZAP_URL}/JSON/core/view/version/",
                timeout=3,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def scan(self, target_url: str) -> List[ScanFinding]:
        logger.info(f"[ZAP] Escaneo contra {target_url}")

        # Spider
        logger.info("[ZAP] Iniciando Spider...")
        r = requests.get(
            f"{self.ZAP_URL}/JSON/spider/action/scan/",
            params={"url": target_url, "recurse": "true"},
            timeout=DEFAULT_TIMEOUT,
        )
        spider_id = r.json().get("scan", "0")
        self._wait_for_completion(
            f"{self.ZAP_URL}/JSON/spider/view/status/",
            {"scanId": spider_id},
            label="Spider",
            timeout=self.SPIDER_TIMEOUT,
        )

        # Dejar que el escaneo pasivo procese el tráfico del spider
        logger.info("[ZAP] Esperando escaneo pasivo...")
        time.sleep(5)

        # Active Scan
        logger.info("[ZAP] Iniciando Active Scan...")
        r = requests.get(
            f"{self.ZAP_URL}/JSON/ascan/action/scan/",
            params={"url": target_url, "recurse": "true", "inScopeOnly": "false"},
            timeout=DEFAULT_TIMEOUT,
        )
        ascan_id = r.json().get("scan", "0")
        self._wait_for_completion(
            f"{self.ZAP_URL}/JSON/ascan/view/status/",
            {"scanId": ascan_id},
            label="Active Scan",
            timeout=self.ASCAN_TIMEOUT,
        )

        # Obtener alertas
        alerts_r = requests.get(
            f"{self.ZAP_URL}/JSON/core/view/alerts/",
            params={"baseurl": target_url},
            timeout=DEFAULT_TIMEOUT,
        )
        alerts = alerts_r.json().get("alerts", [])
        logger.info(f"[ZAP] {len(alerts)} alertas encontradas")
        return [self._map_alert(a, target_url) for a in alerts]

    def _wait_for_completion(
        self,
        status_url: str,
        params: Dict,
        label: str,
        timeout: int,
    ) -> None:
        elapsed = 0
        while elapsed < timeout:
            r = requests.get(status_url, params=params, timeout=DEFAULT_TIMEOUT)
            progress = int(r.json().get("status", 0))
            logger.info(f"  [ZAP] {label}: {progress}%")
            if progress >= 100:
                return
            time.sleep(self.POLL_INTERVAL)
            elapsed += self.POLL_INTERVAL
        logger.warning(f"[ZAP] {label} timeout después de {timeout}s")

    def _map_alert(self, alert: Dict, base_url: str) -> ScanFinding:
        risk_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "LOW",
        }
        severity = risk_map.get(alert.get("risk", "Low"), "LOW")
        if "critical" in alert.get("risk", "").lower():
            severity = "CRITICAL"

        cwe_id = str(alert.get("cweid", "0"))
        return ScanFinding(
            type=alert.get("name", "Unknown"),
            alert=alert.get("name", "Unknown"),
            severity=severity,
            risk=alert.get("risk", "Low"),
            confidence=alert.get("confidence", "Medium"),
            url=alert.get("url", base_url),
            parameter=alert.get("param", ""),
            description=alert.get("description", ""),
            solution=alert.get("solution", ""),
            evidence=alert.get("evidence", ""),
            cwe=f"CWE-{cwe_id}",
            cweid=cwe_id,
            owasp_category=self._map_owasp(alert.get("name", "")),
            source="OWASP ZAP",
        )

    @staticmethod
    def _map_owasp(name: str) -> str:
        n = name.lower()
        if any(k in n for k in ["sql", "injection", "xss", "script"]):
            return "API8:2023"
        if any(k in n for k in ["auth", "session", "csrf", "token"]):
            return "API2:2023"
        if any(k in n for k in ["cors", "access-control", "origin"]):
            return "API8:2023"
        if any(k in n for k in ["disclosure", "information", "server", "stack"]):
            return "API8:2023"
        if "rate" in n or "limit" in n:
            return "API4:2023"
        if any(k in n for k in ["header", "csp", "hsts", "config"]):
            return "API7:2023"
        return "API8:2023"


# ──────────────────────────────────────────────────────────────────────────────
# Punto de entrada público
# ──────────────────────────────────────────────────────────────────────────────

def run_dast_scan(target_url: str) -> Dict[str, Any]:
    """
    Ejecuta un escaneo DAST real contra target_url.

    Prioridad:
      1. OWASP ZAP daemon (si está corriendo en localhost:8080)
      2. HTTP Security Scanner (siempre disponible, sin dependencias externas)

    Devuelve un diccionario con el mismo esquema que esperan
    el motor de correlación y el endpoint /scan/dast.
    """
    zap = ZAPDaemonScanner()
    zap_available = zap.is_available()

    if zap_available:
        logger.info("[DAST] ZAP daemon detectado → usando OWASP ZAP")
        scanner_name = "OWASP ZAP (daemon)"
        try:
            findings = zap.scan(target_url)
        except Exception as exc:
            logger.warning(f"[DAST] ZAP falló ({exc}) → fallback a HTTP Scanner")
            findings = HTTPSecurityScanner().scan(target_url)
            scanner_name = "HTTP Security Scanner (ZAP fallback)"
    else:
        logger.info("[DAST] ZAP no disponible → usando HTTP Security Scanner")
        scanner_name = "HTTP Security Scanner"
        findings = HTTPSecurityScanner().scan(target_url)

    vuln_dicts = [f.to_dict() for f in findings]

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1

    return {
        "scan_type":     "DAST",
        "tool":          scanner_name,
        "zap_available": zap_available,
        "target_url":    target_url,
        "vulnerabilities": vuln_dicts,
        "summary": {
            "total_issues":  len(findings),
            "alerts_found":  len(findings),
            **counts,
        },
    }
