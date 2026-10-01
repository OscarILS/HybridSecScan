"""Tests de los criterios de acierto de scripts/run_correlation_evaluation.py."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scripts.run_correlation_evaluation import dast_matches, metrics, sast_matches  # noqa: E402

GT = [
    {"id": "SQLI", "lines": [25, 25], "endpoint": "/login", "accepted_cwes": [89]},
    {"id": "SECRET", "lines": [15, 16], "endpoint": None, "accepted_cwes": [798, 259]},
    {"id": "DEBUG", "lines": [81, 81], "endpoint": "*", "accepted_cwes": [94, 209]},
]


def test_sast_requires_line_and_cwe():
    assert sast_matches({"line_number": 25, "issue_cwe": {"id": 89}}, GT) == {"SQLI"}
    assert sast_matches({"line_number": 16, "issue_cwe": {"id": 259}}, GT) == {"SECRET"}
    # Misma línea que DEBUG pero otro CWE (binding a todas las interfaces) → no acierta
    assert sast_matches({"line_number": 81, "issue_cwe": {"id": 605}}, GT) == set()
    # CWE correcto en otra línea → no acierta
    assert sast_matches({"line_number": 7, "issue_cwe": {"id": 89}}, GT) == set()


def test_dast_requires_endpoint_and_cwe():
    assert dast_matches({"url": "http://h:5000/login", "cwe": "CWE-89"}, GT) == {"SQLI"}
    assert dast_matches({"url": "http://h:5000/", "cwe": "CWE-89"}, GT) == set()
    # Falla global ('*'): vale en cualquier endpoint si el CWE es aceptado
    assert dast_matches({"url": "http://h:5000/deserialize", "cwe": "CWE-209"}, GT) == {"DEBUG"}
    # Vulnerabilidades sin endpoint (secretos en código) no son observables por DAST
    assert dast_matches({"url": "http://h:5000/", "cwe": "CWE-798"}, GT) == set()


GT_MULTI = [
    {
        "id": "DEBUG_EXPOSURE",
        "accepted_cwes": [200],
        "endpoint": "/users/v1/_debug",
        "locations": [
            {"file": "api_views/users.py", "lines": [24, 26]},
            {"file": "models/user_model.py", "lines": [58, 59]},
        ],
    },
    {"id": "BOLA", "accepted_cwes": [639], "endpoint": "/books/v1/{book_title}", "locations": []},
]


def test_sast_locations_check_file_and_line():
    hit = {"filename": r"x\vampi\models\user_model.py", "line_number": 58, "issue_cwe": {"id": 200}}
    assert sast_matches(hit, GT_MULTI) == {"DEBUG_EXPOSURE"}
    # Misma línea en otro archivo → no acierta
    other = {"filename": r"x\vampi\api_views\books.py", "line_number": 58, "issue_cwe": {"id": 200}}
    assert sast_matches(other, GT_MULTI) == set()


def test_dast_endpoint_templates():
    assert dast_matches({"url": "http://h/books/v1/bookTitle77", "cwe": "CWE-639"}, GT_MULTI) == {"BOLA"}
    # El parámetro cubre un solo segmento
    assert dast_matches({"url": "http://h/books/v1/a/b", "cwe": "CWE-639"}, GT_MULTI) == set()
    assert dast_matches({"url": "http://h/users/v1/_debug", "cwe": "CWE-200"}, GT_MULTI) == {"DEBUG_EXPOSURE"}


def test_metrics_precision_per_finding_recall_per_vulnerability():
    m = metrics([{"SECRET"}, {"SECRET"}, set(), {"SQLI"}], n_gt=3)
    assert m["correct_findings"] == 3 and m["incorrect_findings"] == 1
    assert m["precision"] == 0.75
    assert m["recall"] == round(2 / 3, 4)
    assert metrics([], n_gt=3)["precision"] == 0.0
