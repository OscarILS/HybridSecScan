"""
Cobertura DAST guiada por OpenAPI.

En lugar de escanear solo la URL raíz, este módulo lee la especificación OpenAPI de
la API objetivo, enumera sus endpoints reales y ejecuta comprobaciones de observación
(lectura de respuestas) sobre ellos. Amplía la cobertura hacia categorías del OWASP API
Security Top 10 (2023) que dependen de conocer la estructura de la API.

Comprobación implementada:
  - API3:2023 Broken Object Property Level Authorization → exposición excesiva de datos:
    se recorren los endpoints GET accesibles y se marca cualquier respuesta JSON que
    devuelva campos sensibles (contraseñas, tokens, indicadores de rol, etc.).

Es una comprobación de auditoría de solo lectura: hace peticiones GET y analiza lo que la
API devuelve; no envía cargas de ataque. Pensada para APIs de prueba en entornos
controlados y pruebas autorizadas.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

try:
    from backend.dast_scanner import ScanFinding
except ImportError:  # ejecución desde backend/ como cwd
    from dast_scanner import ScanFinding  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10

# Nombres de campo que no deberían aparecer en una respuesta de API hacia el cliente.
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "hashed_password",
    "secret",
    "secret_content",
    "token",
    "auth_token",
    "api_key",
    "apikey",
    "private_key",
    "ssn",
    "credit_card",
    "cvv",
    "admin",
    "is_admin",
    "role",
}


def load_spec(source: str, session: Optional[requests.Session] = None, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """
    Carga una especificación OpenAPI desde una URL (http/https) o un archivo local
    (JSON o YAML). Devuelve el documento como dict, o {} si no se pudo cargar.
    """
    try:
        if source.startswith(("http://", "https://")):
            sess = session or requests.Session()
            raw = sess.get(source, timeout=timeout, verify=False).text
        else:
            with open(source, "r", encoding="utf-8") as fh:
                raw = fh.read()
    except Exception as exc:
        logger.warning(f"[openapi] no se pudo leer la especificación {source}: {exc}")
        return {}

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        import yaml

        return yaml.safe_load(raw) or {}
    except Exception as exc:
        logger.warning(f"[openapi] la especificación {source} no es JSON ni YAML válido: {exc}")
        return {}


def iter_operations(spec: Dict) -> List[Tuple[str, str, Dict]]:
    """Lista de (path, método en mayúsculas, objeto operación) declarados en el spec."""
    ops: List[Tuple[str, str, Dict]] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "options", "head"):
                ops.append((path, method.upper(), operation if isinstance(operation, dict) else {}))
    return ops


def _server_base(spec: Dict, target_url: str) -> str:
    """Base para construir URLs: la raíz del target más el basePath del spec si lo hay."""
    parsed = urlparse(target_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        sp = urlparse(url)
        if sp.path and not sp.netloc:
            return root + sp.path.rstrip("/")
    base_path = spec.get("basePath")  # OpenAPI 2.x
    if isinstance(base_path, str) and base_path:
        return root + base_path.rstrip("/")
    return root


def _sensitive_keys_in(obj: Any, found: set) -> None:
    """Recorre una estructura JSON y acumula los nombres de campo sensibles presentes."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in SENSITIVE_FIELDS:
                found.add(str(key).lower())
            _sensitive_keys_in(value, found)
    elif isinstance(obj, list):
        for item in obj:
            _sensitive_keys_in(item, found)


def check_excessive_data_exposure(
    target_url: str,
    spec: Dict,
    session: Optional[requests.Session] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[ScanFinding]:
    """
    API3:2023 — exposición excesiva de datos.

    Recorre los endpoints GET sin parámetros de ruta obligatorios, hace la petición y
    marca cualquier respuesta JSON que incluya campos sensibles. Solo lectura.
    """
    sess = session or requests.Session()
    base = _server_base(spec, target_url)
    findings: List[ScanFinding] = []
    seen_endpoints = set()

    for path, method, _op in iter_operations(spec):
        if method != "GET" or "{" in path:  # saltar endpoints con parámetros de ruta obligatorios
            continue
        if path in seen_endpoints:
            continue
        seen_endpoints.add(path)

        url = urljoin(base + "/", path.lstrip("/"))
        try:
            resp = sess.get(url, timeout=timeout, verify=False)
        except Exception as exc:
            logger.debug(f"[openapi] GET {url} falló: {exc}")
            continue
        if resp.status_code != 200:
            continue
        try:
            body = resp.json()
        except ValueError:
            continue

        found: set = set()
        _sensitive_keys_in(body, found)
        if found:
            campos = ", ".join(sorted(found))
            findings.append(
                ScanFinding(
                    type="Excessive Data Exposure",
                    alert=f"Respuesta con campos sensibles en {path}",
                    severity="MEDIUM",
                    risk="Medium",
                    confidence="High",
                    url=url,
                    parameter=campos,
                    description=(
                        f"El endpoint GET {path} devuelve campos sensibles en la respuesta JSON "
                        f"({campos}). Una API no debería exponer estos datos al cliente; el filtrado "
                        f"de propiedades debe hacerse en el servidor."
                    ),
                    solution=(
                        "Devolver solo las propiedades necesarias para cada consumidor. No confiar en "
                        "que el cliente filtre; aplicar una lista de campos permitidos en el servidor."
                    ),
                    evidence=f"Campos sensibles detectados: {campos}. Fragmento: {resp.text[:200]}",
                    cwe="CWE-213",
                    cweid="213",
                    owasp_category="API3:2023",
                    source="OpenAPI Probe – Excessive Data Exposure",
                    request_payload={"method": "GET", "url": url, "probe": "Lectura de respuesta JSON"},
                )
            )
    return findings


def scan_openapi(
    target_url: str,
    spec_source: str,
    session: Optional[requests.Session] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[ScanFinding]:
    """
    Carga la especificación OpenAPI y ejecuta las comprobaciones guiadas por ella.
    Devuelve [] si la especificación no se pudo cargar.
    """
    spec = load_spec(spec_source, session=session, timeout=timeout)
    if not spec:
        return []
    ops = iter_operations(spec)
    logger.info(f"[openapi] {len(ops)} operaciones declaradas en la especificación")
    return check_excessive_data_exposure(target_url, spec, session=session, timeout=timeout)
