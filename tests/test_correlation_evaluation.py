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


def test_metrics_precision_per_finding_recall_per_vulnerability():
    m = metrics([{"SECRET"}, {"SECRET"}, set(), {"SQLI"}], n_gt=3)
    assert m["correct_findings"] == 3 and m["incorrect_findings"] == 1
    assert m["precision"] == 0.75
    assert m["recall"] == round(2 / 3, 4)
    assert metrics([], n_gt=3)["precision"] == 0.0
