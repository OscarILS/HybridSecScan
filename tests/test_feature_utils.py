"""Tests del helper de features compartido (backend/feature_utils.py)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.feature_utils import module_match, module_of_endpoint, module_of_file  # noqa: E402


def test_module_of_file():
    assert module_of_file("api/controllers/payments.py") == "payments"
    assert module_of_file("ProgramasPruebas/vulnerable_app.py") == "vulnerable_app"
    assert module_of_file("api\\services\\Auth.py") == "auth"
    assert module_of_file("") == ""


def test_module_of_endpoint():
    assert module_of_endpoint("/api/v1/payments") == "payments"
    assert module_of_endpoint("/login") == "login"
    assert module_of_endpoint("/users/v1/_debug") == "_debug"
    assert module_of_endpoint("") == ""


def test_module_match_dataset_shapes():
    # Categoría A del dataset sintético: mismo módulo -> 1
    assert module_match("api/controllers/payments.py", "/api/v1/payments") == 1
    # Categoría D: módulos distintos -> 0
    assert module_match("api/controllers/payments.py", "/api/v1/orders") == 0
    # Vacíos -> 0 (no inventar coincidencia)
    assert module_match("", "/api/v1/payments") == 0
    assert module_match("api/controllers/payments.py", "") == 0


def test_module_match_caso_real_vulnerable_app():
    # SQLi de vulnerable_app.py en /login: archivo y endpoint NO comparten módulo
    assert module_match("ProgramasPruebas/vulnerable_app.py", "/login") == 0
