"""
Tests de integración para flujos completos del sistema HybridSecScan.
Prueba interacciones entre componentes: API, Base de datos, Herramientas SAST/DAST.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import shutil
from pathlib import Path
import json

# Importar aplicación
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.main import app, get_db, Base
from database.models import ScanResult, User

# Configurar base de datos de pruebas
TEST_DATABASE_URL = "sqlite:///./test_integration.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    """Override para usar base de datos de pruebas."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_database():
    """Fixture para crear y limpiar la base de datos de pruebas."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("test_integration.db"):
        os.remove("test_integration.db")


@pytest.fixture
def test_user():
    """Fixture para crear un usuario de prueba."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123",
        "full_name": "Test User"
    }


@pytest.fixture
def test_python_file():
    """Fixture para crear un archivo Python temporal de prueba."""
    test_code = '''
import sqlite3

def vulnerable_query(user_id):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def hardcoded_secret():
    API_KEY = "sk-1234567890abcdef"
    return API_KEY
'''
    
    temp_dir = tempfile.mkdtemp()
    test_file = Path(temp_dir) / "vulnerable_test.py"
    test_file.write_text(test_code)
    
    yield test_file
    
    # Cleanup
    shutil.rmtree(temp_dir)


class TestFullSASTFlow:
    """Pruebas del flujo completo SAST: subida de archivo -> análisis -> resultados."""
    
    def test_full_sast_flow(self, setup_database, test_python_file):
        """Prueba flujo completo de análisis SAST."""
        # 1. Subir archivo
        with open(test_python_file, 'rb') as f:
            response = client.post(
                "/upload/",
                files={"file": ("vulnerable_test.py", f, "text/x-python")}
            )
        
        assert response.status_code == 200
        upload_data = response.json()
        assert upload_data["ready_for_scan"] is True
        file_path = upload_data["file_path"]
        
        # 2. Ejecutar análisis Bandit
        response = client.post(
            "/scan/sast",
            json={"target_path": file_path, "tool": "bandit"}
        )
        
        assert response.status_code == 200
        scan_data = response.json()
        assert "result_id" in scan_data
        result_id = scan_data["result_id"]
        
        # 3. Obtener resultados
        response = client.get(f"/results/{result_id}")
        assert response.status_code == 200
        results = response.json()
        
        # 4. Verificar que se detectaron vulnerabilidades
        assert results["status"] == "completed"
        assert "results" in results
        assert results["results"]["total_issues"] > 0
        
        # Verificar que se detectó SQL injection y hardcoded secrets
        severity_breakdown = results["results"]["severity_breakdown"]
        assert severity_breakdown.get("HIGH", 0) > 0 or severity_breakdown.get("MEDIUM", 0) > 0


class TestFullDASTFlow:
    """Pruebas del flujo completo DAST: escaneo de URL -> resultados."""
    
    @pytest.mark.skipif(
        shutil.which("zap-cli") is None,
        reason="OWASP ZAP no está instalado"
    )
    def test_full_dast_flow(self, setup_database):
        """Prueba flujo completo de análisis DAST."""
        # 1. Ejecutar escaneo DAST (usando API de prueba local)
        test_url = "http://httpbin.org/get"
        
        response = client.post(
            "/scan/dast",
            json={"target_url": test_url}
        )
        
        # Puede fallar si ZAP no está instalado
        if response.status_code == 200:
            scan_data = response.json()
            assert "result_id" in scan_data
            result_id = scan_data["result_id"]
            
            # 2. Obtener resultados
            response = client.get(f"/results/{result_id}")
            assert response.status_code == 200
            results = response.json()
            assert results["status"] in ["completed", "failed"]


class TestHybridCorrelationFlow:
    """Pruebas del flujo de correlación híbrida SAST + DAST."""
    
    def test_hybrid_correlation_flow(self, setup_database, test_python_file):
        """Prueba correlación entre hallazgos SAST y DAST."""
        from backend.correlation_engine import VulnerabilityCorrelator, Vulnerability, VulnerabilityType, ConfidenceLevel
        
        # 1. Crear correlador
        correlator = VulnerabilityCorrelator()
        
        # 2. Agregar hallazgos SAST simulados
        sast_vulns = [
            Vulnerability(
                id="sast-1",
                type=VulnerabilityType.SQL_INJECTION,
                severity=ConfidenceLevel.HIGH,
                file_path=str(test_python_file),
                line_number=8,
                endpoint="/api/users",
                description="SQL Injection in user query",
                cwe_id="CWE-89",
                owasp_category="API8:2023",
                source_tool="Bandit"
            )
        ]
        correlator.add_sast_findings(sast_vulns)
        
        # 3. Agregar hallazgos DAST simulados
        dast_vulns = [
            Vulnerability(
                id="dast-1",
                type=VulnerabilityType.SQL_INJECTION,
                severity=ConfidenceLevel.HIGH,
                file_path="",
                line_number=0,
                endpoint="/api/users",
                description="SQL Injection detected via parameter manipulation",
                cwe_id="CWE-89",
                owasp_category="API8:2023",
                source_tool="OWASP ZAP"
            )
        ]
        correlator.add_dast_findings(dast_vulns)
        
        # 4. Ejecutar correlación
        correlations = correlator.correlate_vulnerabilities()
        
        # 5. Verificar que se encontraron correlaciones
        assert len(correlations) > 0
        
        correlation = correlations[0]
        assert correlation["sast_finding"]["id"] == "sast-1"
        assert correlation["dast_finding"]["id"] == "dast-1"
        assert correlation["confidence"] > 0.7
        assert correlation["correlation_type"] == "SAST-DAST Match"
        
        # 6. Generar reporte
        report = correlator.generate_correlation_report()
        assert report["total_sast_findings"] == 1
        assert report["total_dast_findings"] == 1
        assert report["total_correlations"] == 1
        assert report["correlation_rate"] == 1.0


class TestCacheIntegration:
    """Pruebas de integración con el sistema de caché."""
    
    def test_cache_manager_integration(self):
        """Prueba integración del gestor de caché."""
        from backend.cache_manager import CacheManager
        
        cache = CacheManager(default_ttl_seconds=60)
        
        # 1. Almacenar resultado de escaneo
        scan_result = {
            "id": 123,
            "vulnerabilities": [{"type": "SQL_INJECTION", "severity": "HIGH"}],
            "total": 1
        }
        cache.set("scan", "123", scan_result)
        
        # 2. Recuperar del caché
        cached_result = cache.get("scan", "123")
        assert cached_result is not None
        assert cached_result["id"] == 123
        assert cached_result["total"] == 1
        
        # 3. Verificar estadísticas
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["cache_size"] == 1
        
        # 4. Limpiar caché
        cleared = cache.clear()
        assert cleared == 1
        assert cache.get("scan", "123") is None


class TestMLModelManager:
    """Pruebas de integración con el gestor de modelos ML."""
    
    def test_ml_model_manager_integration(self, tmp_path):
        """Prueba integración del gestor de modelos ML."""
        from backend.ml_model_manager import MLModelManager
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction.text import TfidfVectorizer
        
        # 1. Crear gestor con directorio temporal
        manager = MLModelManager(models_dir=str(tmp_path))
        
        # 2. Entrenar modelo simple
        classifier = RandomForestClassifier(n_estimators=10, random_state=42)
        X_train = [[1, 2], [3, 4], [5, 6]]
        y_train = [0, 1, 0]
        classifier.fit(X_train, y_train)
        
        vectorizer = TfidfVectorizer(max_features=100)
        vectorizer.fit(["test sql injection", "xss vulnerability", "broken auth"])
        
        # 3. Guardar modelo
        metrics = {"accuracy": 0.95, "f1_score": 0.93}
        version = manager.save_model(
            classifier,
            vectorizer,
            metrics=metrics,
            description="Test model"
        )
        
        assert version == 1
        
        # 4. Cargar modelo
        loaded_classifier, loaded_vectorizer, info = manager.load_model(version)
        assert loaded_classifier is not None
        assert loaded_vectorizer is not None
        assert info["version"] == 1
        assert info["metrics"]["accuracy"] == 0.95
        
        # 5. Listar versiones
        versions = manager.list_versions()
        assert versions["current_version"] == 1
        assert "1" in versions["versions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
