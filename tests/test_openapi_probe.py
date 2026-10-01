"""Tests de la cobertura DAST guiada por OpenAPI (backend/openapi_probe.py)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.openapi_probe import (  # noqa: E402
    SENSITIVE_FIELDS,
    _sensitive_keys_in,
    check_excessive_data_exposure,
    iter_operations,
)

SPEC = {
    "openapi": "3.0.1",
    "servers": [{"url": "http://localhost:5000"}],
    "paths": {
        "/users/v1": {"get": {"operationId": "get_all_users"}},
        "/users/v1/_debug": {"get": {"operationId": "debug"}},
        "/users/v1/{username}": {"get": {"operationId": "get_by_username"}},
        "/users/v1/register": {"post": {"operationId": "register"}},
    },
}


class _FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = str(payload)

    def json(self):
        import json

        return json.loads(json.dumps(self._payload))


class _FakeSession:
    """Devuelve respuestas predefinidas por path; registra qué URLs se consultaron."""

    def __init__(self, by_path):
        self.by_path = by_path
        self.requested = []

    def get(self, url, timeout=None, verify=None):
        self.requested.append(url)
        for path, resp in self.by_path.items():
            if url.endswith(path):
                return resp
        return _FakeResp(404, {})


def test_iter_operations_lista_metodos():
    ops = iter_operations(SPEC)
    assert ("/users/v1/_debug", "GET", {"operationId": "debug"}) in ops
    assert ("/users/v1/register", "POST", {"operationId": "register"}) in ops
    assert len(ops) == 4


def test_sensitive_keys_anidados():
    found = set()
    _sensitive_keys_in({"users": [{"username": "a", "password": "x", "admin": True}]}, found)
    assert found == {"password", "admin"}


def test_excessive_data_exposure_detecta_campos_sensibles():
    session = _FakeSession(
        {
            "/users/v1/_debug": _FakeResp(200, {"users": [{"username": "a", "password": "x", "admin": False}]}),
            "/users/v1": _FakeResp(200, {"users": [{"username": "a", "email": "a@b.c"}]}),
        }
    )
    findings = check_excessive_data_exposure("http://127.0.0.1:5000", SPEC, session=session)
    # Solo _debug expone campos sensibles; /users/v1 no
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "API3:2023"
    assert "_debug" in f.url
    assert "password" in f.parameter and "admin" in f.parameter


def test_excessive_data_exposure_salta_parametros_de_ruta():
    session = _FakeSession({})
    check_excessive_data_exposure("http://127.0.0.1:5000", SPEC, session=session)
    # El endpoint con {username} no debe consultarse (parámetro de ruta obligatorio)
    assert not any("{username}" in u for u in session.requested)
    # Tampoco los POST
    assert not any(u.endswith("/register") for u in session.requested)


def test_respuesta_no_json_no_falla():
    session = _FakeSession({"/users/v1/_debug": _FakeResp(200, "texto plano"), "/users/v1": _FakeResp(200, "x")})
    # No debe lanzar excepción aunque la respuesta no sea JSON con estructura esperada
    findings = check_excessive_data_exposure("http://127.0.0.1:5000", SPEC, session=session)
    assert isinstance(findings, list)


def test_campos_sensibles_cubren_lo_esperado():
    for campo in ("password", "token", "admin", "secret", "api_key"):
        assert campo in SENSITIVE_FIELDS
