"""
Tests de seguridad para HybridSecScan
Valida todas las medidas de seguridad implementadas
"""

import pytest
import tempfile
import json
import os
from pathlib import Path
from fastapi.testclient import TestClient
from fastapi import UploadFile
import io

# Importar modules del backend
import sys
sys.path.insert(0, '../backend')

from main import app, validate_scan_path, validate_uploaded_file, ALLOWED_EXTENSIONS, MAX_FILE_SIZE
from correlation_engine import VulnerabilityCorrelator, Vulnerability, VulnerabilityType, ConfidenceLevel

client = TestClient(app)

class TestSecurityValidations:
    """Suite de tests para validaciones de seguridad"""
    
    def test_path_traversal_prevention(self):
        """Test: Prevenir ataques de path traversal"""
        
        # Rutas peligrosas que deben ser rechazadas
        dangerous_paths = [
            "../../../etc/passwd",
            "/etc/shadow", 
            "~/.ssh/id_rsa",
            "/root/.bashrc",
            "../../windows/system32",
            "../../../../../var/log/auth.log"
        ]
        
        for dangerous_path in dangerous_paths:
            result = validate_scan_path(dangerous_path)
            assert result is None, f"Ruta peligrosa no fue rechazada: {dangerous_path}"
    
    def test_valid_paths_acceptance(self):
        """Test: Aceptar rutas válidas y seguras"""
        
        # Crear archivo temporal para test
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as tmp_file:
            tmp_file.write(b"print('hello world')")
            tmp_path = tmp_file.name
        
        try:
            result = validate_scan_path(tmp_path)
            # Debe retornar un Path válido (copiado a área segura)
            assert result is not None
            assert isinstance(result, Path)
            assert result.exists()
        finally:
            # Limpiar archivo temporal
            os.unlink(tmp_path)
    
    @pytest.mark.asyncio
    async def test_file_size_validation(self):
        """Test: Validación correcta de tamaño de archivos"""
        
        # Archivo muy grande (excede límite)
        large_content = b"x" * (MAX_FILE_SIZE + 1)
        large_file = UploadFile(
            filename="large.py",
            file=io.BytesIO(large_content)
        )
        
        with pytest.raises(Exception) as exc_info:
            await validate_uploaded_file(large_file)
        
        assert "demasiado grande" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio 
    async def test_file_extension_validation(self):
        """Test: Validación de extensiones de archivo"""
        
        # Extensión no permitida
        malicious_file = UploadFile(
            filename="malware.exe",
            file=io.BytesIO(b"malicious content")
        )
        
        with pytest.raises(Exception) as exc_info:
            await validate_uploaded_file(malicious_file)
            
        assert "no permitida" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_filename_sanitization(self):
        """Test: Sanitización de nombres de archivo"""
        
        dangerous_filenames = [
            "../../../etc/passwd.py",
            "file..with..dots.py",
            "file/with/slashes.py",
            None,
            ""
        ]
        
        for dangerous_name in dangerous_filenames:
            dangerous_file = UploadFile(
                filename=dangerous_name,
                file=io.BytesIO(b"print('test')")
            )
            
            with pytest.raises(Exception):
                await validate_uploaded_file(dangerous_file)
    
    def test_sast_endpoint_security(self):
        """Test: Endpoint SAST con validaciones de seguridad"""
        
        # Intentar path traversal via API
        response = client.post(
            "/scan/sast",
            data={
                "target_path": "../../../etc/passwd",
                "tool": "bandit"
            }
        )
        
        # Debe rechazar la petición
        assert response.status_code == 400
        assert "no válida" in response.json()["detail"].lower()
    
    def test_upload_endpoint_security(self):
        """Test: Endpoint de upload con validaciones"""
        
        # Intentar subir archivo malicioso
        malicious_content = b"import os; os.system('rm -rf /')"
        
        response = client.post(
            "/upload/",
            files={
                "file": ("malware.exe", io.BytesIO(malicious_content), "application/octet-stream")
            }
        )
        
        # Debe rechazar el archivo
        assert response.status_code == 400
        
    def test_health_endpoint(self):
        """Test: Endpoint de health check"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

class TestCorrelationEngine:
    """Tests para el motor de correlación ML"""
    
    def setUp(self):
        self.correlator = VulnerabilityCorrelator()
    
    def test_ml_model_initialization(self):
        """Test: Inicialización correcta del modelo ML"""
        correlator = VulnerabilityCorrelator()
        
        # El modelo debe inicializarse correctamente
        assert hasattr(correlator, 'ml_classifier')
        
        # Si scikit-learn está disponible, debe tener modelo
        try:
            import sklearn
            assert correlator.ml_classifier is not None
        except ImportError:
            # Si no está sklearn, debe ser None pero no crashear
            pass
    
    def test_vulnerability_correlation(self):
        """Test: Correlación básica de vulnerabilidades"""
        correlator = VulnerabilityCorrelator()
        
        # Crear vulnerabilidades de prueba que deberían correlacionarse
        sast_vuln = Vulnerability(
            id="SAST_001",
            type=VulnerabilityType.SQL_INJECTION,
            severity=ConfidenceLevel.HIGH,
            file_path="/api/users.py",
            line_number=45,
            endpoint="/api/users",
            description="Potential SQL injection in user query",
            cwe_id="CWE-89",
            owasp_category="API3-2023",
            source_tool="bandit"
        )
        
        dast_vuln = Vulnerability(
            id="DAST_001", 
            type=VulnerabilityType.SQL_INJECTION,
            severity=ConfidenceLevel.HIGH,
            file_path="",
            line_number=0,
            endpoint="/api/users",
            description="SQL error response detected",
            cwe_id="CWE-89",
            owasp_category="API3-2023",
            source_tool="zap"
        )
        
        correlator.add_sast_findings([sast_vuln])
        correlator.add_dast_findings([dast_vuln])
        
        # Generar correlaciones
        correlations = correlator.correlate_vulnerabilities()
        
        # Debe encontrar la correlación
        assert len(correlations) > 0
        
        # La confianza debe ser alta para vulnerabilidades similares
        first_correlation = correlations[0]
        assert first_correlation[2] > 0.7  # Confidence score > 0.7
    
    def test_confidence_calculation_range(self):
        """Test: El cálculo de confianza debe estar en rango válido"""
        correlator = VulnerabilityCorrelator()
        
        sast_vuln = Vulnerability(
            id="SAST_TEST", type=VulnerabilityType.XSS, severity=ConfidenceLevel.MEDIUM,
            file_path="/test.py", line_number=1, endpoint="/test", description="test",
            cwe_id="CWE-79", owasp_category="API8-2023", source_tool="bandit"
        )
        
        dast_vuln = Vulnerability(
            id="DAST_TEST", type=VulnerabilityType.BROKEN_AUTH, severity=ConfidenceLevel.LOW,
            file_path="", line_number=0, endpoint="/different", description="different test",
            cwe_id="CWE-287", owasp_category="API2-2023", source_tool="zap"
        )
        
        confidence = correlator._calculate_correlation_confidence(sast_vuln, dast_vuln)
        
        # La confianza debe estar en rango [0, 1]
        assert 0.0 <= confidence <= 1.0
    
    def test_report_generation(self):
        """Test: Generación de reporte de correlación"""
        correlator = VulnerabilityCorrelator()
        
        # Agregar algunas vulnerabilidades de prueba
        sast_vuln = Vulnerability(
            id="SAST_REPORT", type=VulnerabilityType.SENSITIVE_DATA, severity=ConfidenceLevel.HIGH,
            file_path="/config.py", line_number=10, endpoint="/config", description="hardcoded password",
            cwe_id="CWE-798", owasp_category="API7-2023", source_tool="semgrep"
        )
        
        correlator.add_sast_findings([sast_vuln])
        
        # Generar reporte
        report = correlator.generate_correlation_report()
        
        # Validar estructura del reporte
        assert "summary" in report
        assert "correlations" in report
        assert "total_sast_findings" in report["summary"]
        assert report["summary"]["total_sast_findings"] == 1

class TestAPIEndpoints:
    """Tests de integración para endpoints de la API"""
    
    def test_scan_results_endpoint(self):
        """Test: Endpoint de resultados de escaneo"""
        response = client.get("/scan-results")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_invalid_tool_parameter(self):
        """Test: Parámetro de herramienta inválido"""
        response = client.post(
            "/scan/sast",
            data={
                "target_path": "/tmp/test.py",
                "tool": "invalid_tool"
            }
        )
        
        assert response.status_code == 400
        assert "no soportada" in response.json()["detail"].lower()

# Tests de rendimiento y límites
class TestPerformanceLimits:
    """Tests para verificar límites de rendimiento y recursos"""
    
    def test_concurrent_requests_limit(self):
        """Test: Límite de peticiones concurrentes"""
        # Este test verificaría que el sistema maneja bien múltiples peticiones
        # En un entorno de producción, implementarías rate limiting
        pass
    
    def test_memory_usage_bounds(self):
        """Test: Uso de memoria dentro de límites"""
        # Test para verificar que el procesamiento de archivos grandes
        # no consume memoria excesiva
        pass

if __name__ == "__main__":
    # Ejecutar tests
    pytest.main([__file__, "-v", "--tb=short"])
