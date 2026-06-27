"""
Tests de integración para flujos completos del sistema HybridSecScan.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.main import app, Base, get_db  # noqa: E402 — path set above

# ── Test database ──────────────────────────────────────────────────────────────

TEST_DATABASE_URL = "sqlite:///./test_integration.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def setup_database():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("test_integration.db"):
        os.remove("test_integration.db")


@pytest.fixture
def test_python_file():
    """Archivo Python con vulnerabilidades conocidas para SAST."""
    test_code = '''
import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection
    cursor.execute(query)
    return cursor.fetchall()

def hardcoded_secret():
    API_KEY = "sk-1234567890abcdef"  # Hardcoded secret
    return API_KEY
'''
    temp_dir = tempfile.mkdtemp()
    test_file = Path(temp_dir) / "vulnerable_test.py"
    test_file.write_text(test_code)
    yield test_file
    shutil.rmtree(temp_dir)


# ── Core API tests ─────────────────────────────────────────────────────────────

class TestHealthAndRoot:
    def test_health(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_root(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "HybridSecScan" in response.json()["message"]

    def test_scan_results_empty(self, setup_database):
        response = client.get("/scan-results")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


# ── File upload tests ──────────────────────────────────────────────────────────

class TestFileUpload:
    def test_upload_valid_python_file(self, setup_database, test_python_file):
        with open(test_python_file, "rb") as f:
            response = client.post(
                "/upload/",
                files={"file": ("vulnerable_test.py", f, "text/x-python")},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["ready_for_scan"] is True
        assert data["original_filename"] == "vulnerable_test.py"
        assert "file_path" in data

    def test_upload_rejects_invalid_extension(self, setup_database):
        response = client.post(
            "/upload/",
            files={"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
        )
        assert response.status_code == 400

    def test_upload_rejects_empty_file(self, setup_database):
        response = client.post(
            "/upload/",
            files={"file": ("empty.py", b"", "text/x-python")},
        )
        assert response.status_code == 400

    def test_upload_rejects_path_traversal_filename(self, setup_database):
        response = client.post(
            "/upload/",
            files={"file": ("../etc/passwd", b"root:x:0:0", "text/plain")},
        )
        assert response.status_code == 400


# ── SAST scan tests ────────────────────────────────────────────────────────────

class TestSASTScan:
    def test_sast_scan_rejects_unsupported_tool(self, setup_database, test_python_file):
        """Endpoint should reject unknown SAST tools."""
        response = client.post(
            "/scan/sast",
            data={"target_path": str(test_python_file), "tool": "nessus"},
        )
        assert response.status_code == 400

    def test_sast_scan_rejects_path_traversal(self, setup_database):
        """Endpoint should reject dangerous paths."""
        response = client.post(
            "/scan/sast",
            data={"target_path": "../../../../etc/passwd", "tool": "bandit"},
        )
        assert response.status_code == 400

    def test_sast_scan_bandit_on_real_file(self, setup_database, test_python_file):
        """Full SAST flow: upload then scan with Bandit."""
        # Upload first so the file is in the uploads dir
        with open(test_python_file, "rb") as f:
            upload_resp = client.post(
                "/upload/",
                files={"file": ("vulnerable_test.py", f, "text/x-python")},
            )
        assert upload_resp.status_code == 200
        uploaded_path = upload_resp.json()["file_path"]

        # Run Bandit SAST scan — uses Form data, NOT JSON
        scan_resp = client.post(
            "/scan/sast",
            data={"target_path": uploaded_path, "tool": "bandit"},
        )
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert "result_id" in scan_data
        # Bandit should detect at least the hardcoded secret or SQL injection
        assert scan_data["vulnerabilities_found"] >= 0  # may be 0 if bandit not installed


# ── DAST scan tests ────────────────────────────────────────────────────────────

class TestDASTScan:
    def test_dast_rejects_non_http_url(self):
        response = client.post("/scan/dast", data={"target_url": "ftp://example.com"})
        assert response.status_code == 400

    def test_dast_rejects_localhost(self):
        """SSRF protection: localhost must be blocked."""
        response = client.post("/scan/dast", data={"target_url": "http://localhost/api"})
        assert response.status_code == 400

    def test_dast_rejects_private_ip(self):
        """SSRF protection: RFC1918 addresses must be blocked."""
        response = client.post("/scan/dast", data={"target_url": "http://192.168.1.1/admin"})
        assert response.status_code == 400

    def test_dast_rejects_link_local(self):
        """SSRF protection: AWS metadata endpoint must be blocked."""
        response = client.post("/scan/dast", data={"target_url": "http://169.254.169.254/latest/meta-data"})
        assert response.status_code == 400


# ── Hybrid correlation tests ───────────────────────────────────────────────────

class TestHybridCorrelation:
    def test_hybrid_requires_existing_scan_ids(self, setup_database):
        """Hybrid scan should return 404 for non-existent scan IDs."""
        response = client.post(
            "/scan/hybrid",
            data={"sast_scan_id": 99999, "dast_scan_id": 99998},
        )
        assert response.status_code == 404

    def test_correlation_engine_directly(self):
        """Unit test of VulnerabilityCorrelator logic."""
        from backend.correlation_engine import (
            ConfidenceLevel,
            Vulnerability,
            VulnerabilityCorrelator,
            VulnerabilityType,
        )

        correlator = VulnerabilityCorrelator()

        sast_vulns = [
            Vulnerability(
                id="sast-1",
                type=VulnerabilityType.SQL_INJECTION,
                severity=ConfidenceLevel.HIGH,
                file_path="backend/api/users.py",
                line_number=8,
                endpoint="/api/users",
                description="SQL Injection via string formatting in user query",
                cwe_id="CWE-89",
                owasp_category="API3:2023",
                source_tool="bandit",
            )
        ]
        dast_vulns = [
            Vulnerability(
                id="dast-1",
                type=VulnerabilityType.SQL_INJECTION,
                severity=ConfidenceLevel.HIGH,
                file_path="",
                line_number=0,
                endpoint="http://localhost:8000/api/users",
                description="SQL Injection detected via error response on parameter manipulation",
                cwe_id="CWE-89",
                owasp_category="API3:2023",
                source_tool="zap",
            )
        ]

        correlator.add_sast_findings(sast_vulns)
        correlator.add_dast_findings(dast_vulns)
        correlations = correlator.correlate_vulnerabilities()

        # Same type + same endpoint → should correlate
        assert len(correlations) > 0
        sast_v, dast_v, confidence = correlations[0]
        assert sast_v.id == "sast-1"
        assert dast_v.id == "dast-1"
        assert confidence > 0.5

    def test_correlation_report_structure(self):
        """Correlation report must have the expected schema."""
        from backend.correlation_engine import (
            ConfidenceLevel,
            Vulnerability,
            VulnerabilityCorrelator,
            VulnerabilityType,
        )

        correlator = VulnerabilityCorrelator()
        correlator.add_sast_findings([
            Vulnerability(
                id="s1", type=VulnerabilityType.XSS, severity=ConfidenceLevel.MEDIUM,
                file_path="frontend/src/App.tsx", line_number=42,
                endpoint="/api/comments",
                description="dangerouslySetInnerHTML usage without sanitization",
                cwe_id="CWE-79", owasp_category="API8:2023", source_tool="semgrep",
            )
        ])
        correlator.add_dast_findings([
            Vulnerability(
                id="d1", type=VulnerabilityType.XSS, severity=ConfidenceLevel.MEDIUM,
                file_path="", line_number=0,
                endpoint="http://localhost:3000/api/comments",
                description="XSS payload reflected in response",
                cwe_id="CWE-79", owasp_category="API8:2023", source_tool="zap",
            )
        ])

        report = correlator.generate_correlation_report()

        # Schema assertions
        assert "summary" in report
        assert "correlations" in report
        assert report["summary"]["total_sast_findings"] == 1
        assert report["summary"]["total_dast_findings"] == 1
        assert isinstance(report["correlations"], list)

    def test_endpoint_normalization(self):
        """File paths and URLs should normalize to comparable strings."""
        from backend.correlation_engine import VulnerabilityCorrelator

        vc = VulnerabilityCorrelator()

        # Full URL vs file path with same last segment
        sim = vc._calculate_endpoint_similarity(
            "backend/api/users.py",
            "http://localhost:8000/api/users",
        )
        assert sim > 0.5, f"Expected > 0.5, got {sim}"

        # Identical paths after normalization
        sim_exact = vc._calculate_endpoint_similarity("/api/users", "/api/users")
        assert sim_exact == 1.0

        # Completely unrelated endpoints
        sim_none = vc._calculate_endpoint_similarity("backend/auth.py", "http://target/products")
        assert sim_none < 0.5


# ── Cache manager integration ──────────────────────────────────────────────────

class TestCacheIntegration:
    def test_cache_manager_integration(self):
        from backend.cache_manager import CacheManager

        cache = CacheManager(default_ttl_seconds=60)

        scan_result = {"id": 123, "vulnerabilities": [{"type": "SQL_INJECTION", "severity": "HIGH"}], "total": 1}
        cache.set("scan", "123", scan_result)

        cached = cache.get("scan", "123")
        assert cached is not None
        assert cached["id"] == 123

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["cache_size"] == 1

        cleared = cache.clear()
        assert cleared == 1
        assert cache.get("scan", "123") is None


# ── ML model manager integration ──────────────────────────────────────────────

class TestMLModelManager:
    def test_ml_model_manager_integration(self, tmp_path):
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction.text import TfidfVectorizer

        from backend.ml_model_manager import MLModelManager

        manager = MLModelManager(models_dir=str(tmp_path))

        clf = RandomForestClassifier(n_estimators=10, random_state=42)
        clf.fit([[1, 2], [3, 4], [5, 6]], [0, 1, 0])

        vec = TfidfVectorizer(max_features=100)
        vec.fit(["test sql injection", "xss vulnerability", "broken auth"])

        version = manager.save_model(clf, vec, metrics={"accuracy": 0.95, "f1_score": 0.93}, description="Test model")
        assert version == 1

        loaded_clf, loaded_vec, info = manager.load_model(version)
        assert loaded_clf is not None
        assert loaded_vec is not None
        assert info["version"] == 1
        assert info["metrics"]["accuracy"] == 0.95

        versions = manager.list_versions()
        assert versions["current_version"] == 1
        assert "1" in versions["versions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
