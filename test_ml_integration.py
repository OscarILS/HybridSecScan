"""
Test de integración del modelo ML en correlation_engine.py

Este script verifica:
1. Que el modelo entrenado se carga correctamente
2. Que puede hacer predicciones con pares SAST-DAST
3. Que el feature engineering funciona correctamente
"""

import sys
import os
from pathlib import Path

# Agregar backend al path
sys.path.insert(0, str(Path(__file__).parent))

from backend.correlation_engine import (
    VulnerabilityCorrelator,
    Vulnerability,
    VulnerabilityType,
    ConfidenceLevel
)

def create_test_vulnerabilities():
    """Crea vulnerabilidades de prueba para testing"""
    
    # SAST: SQL Injection encontrada por Bandit
    sast_vuln = Vulnerability(
        id="sast_1",
        type=VulnerabilityType.SQL_INJECTION,
        severity=ConfidenceLevel.HIGH,
        description="SQL injection vulnerability detected in user authentication query",
        file_path="/app/controllers/auth_controller.py",
        line_number=45,
        endpoint="/api/login",
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        source_tool="bandit"
    )
    
    # DAST: SQL Injection encontrada por ZAP
    dast_vuln = Vulnerability(
        id="dast_1",
        type=VulnerabilityType.SQL_INJECTION,
        severity=ConfidenceLevel.HIGH,
        description="SQL Injection found in login endpoint - ' OR '1'='1 payload succeeded",
        file_path="",  # DAST no tiene file_path
        line_number=0,  # DAST no tiene line_number
        endpoint="/api/login",
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
        source_tool="zap"
    )
    
    # SAST: XSS encontrada por Semgrep (no debería correlacionar con SQL Injection)
    sast_xss = Vulnerability(
        id="sast_2",
        type=VulnerabilityType.XSS,
        severity=ConfidenceLevel.MEDIUM,
        description="Cross-site scripting vulnerability in comment rendering",
        file_path="/app/views/comments.py",
        line_number=78,
        endpoint="/api/comments",
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
        source_tool="semgrep"
    )
    
    return sast_vuln, dast_vuln, sast_xss

def test_model_loading():
    """Test 1: Verificar que el modelo se carga correctamente"""
    print("=" * 80)
    print("TEST 1: Carga del modelo ML")
    print("=" * 80)
    
    try:
        correlator = VulnerabilityCorrelator()
        
        if correlator.ml_classifier is not None:
            print("✅ Modelo ML cargado exitosamente")
            print(f"   - Versión: {correlator.model_metrics.get('model_version', 'N/A')}")
            print(f"   - Features: {correlator.model_metrics.get('n_features', 'N/A')}")
            
            f1_score = correlator.model_metrics.get('f1_score', 0.0)
            accuracy = correlator.model_metrics.get('accuracy', 0.0)
            
            if isinstance(f1_score, (int, float)):
                print(f"   - F1-Score: {f1_score:.4f}")
            else:
                print(f"   - F1-Score: {f1_score}")
            
            if isinstance(accuracy, (int, float)):
                print(f"   - Accuracy: {accuracy:.4f}")
            else:
                print(f"   - Accuracy: {accuracy}")
                
            return correlator, True
        else:
            print("❌ Modelo ML no disponible, usando correlación determinística")
            return correlator, False
            
    except Exception as e:
        print(f"❌ Error cargando modelo: {str(e)}")
        import traceback
        traceback.print_exc()
        return None, False

def test_feature_engineering(correlator):
    """Test 2: Verificar que el feature engineering funciona"""
    print("\n" + "=" * 80)
    print("TEST 2: Feature Engineering")
    print("=" * 80)
    
    try:
        sast_vuln, dast_vuln, _ = create_test_vulnerabilities()
        
        print(f"\nSAST Vuln: {sast_vuln.type.value} en {sast_vuln.endpoint}")
        print(f"DAST Vuln: {dast_vuln.type.value} en {dast_vuln.endpoint}")
        
        # Generar features
        feature_vector = correlator._engineer_features_for_prediction(sast_vuln, dast_vuln)
        
        print(f"\n✅ Feature vector generado exitosamente")
        print(f"   - Dimensión: {len(feature_vector)} features")
        print(f"   - Primeras 10 features: {feature_vector[:10]}")
        print(f"   - Últimas 10 features: {feature_vector[-10:]}")
        
        # Verificar dimensionalidad esperada
        expected_features = correlator.model_metrics.get('n_features', 517)
        if len(feature_vector) == expected_features:
            print(f"   - ✅ Dimensionalidad correcta ({expected_features} features)")
            return True
        else:
            print(f"   - ❌ Dimensionalidad incorrecta: {len(feature_vector)} vs {expected_features} esperados")
            return False
            
    except Exception as e:
        print(f"❌ Error en feature engineering: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_ml_prediction(correlator):
    """Test 3: Verificar que el modelo puede hacer predicciones"""
    print("\n" + "=" * 80)
    print("TEST 3: Predicción ML")
    print("=" * 80)
    
    try:
        sast_vuln, dast_vuln, sast_xss = create_test_vulnerabilities()
        
        # Test 3.1: SQL Injection SAST + SQL Injection DAST (debería correlacionar)
        print("\n[Caso 1: SQL Injection SAST + SQL Injection DAST]")
        print(f"  SAST: {sast_vuln.type.value} en {sast_vuln.endpoint}")
        print(f"  DAST: {dast_vuln.type.value} en {dast_vuln.endpoint}")
        
        confidence_1 = correlator._calculate_correlation_confidence(sast_vuln, dast_vuln)
        print(f"  ➡️  Confianza de correlación: {confidence_1:.4f}")
        
        if confidence_1 > 0.7:
            print(f"  ✅ Correlación detectada correctamente (>0.7)")
        else:
            print(f"  ⚠️  Confianza baja, posible falso negativo")
        
        # Test 3.2: XSS SAST + SQL Injection DAST (NO debería correlacionar)
        print("\n[Caso 2: XSS SAST + SQL Injection DAST]")
        print(f"  SAST: {sast_xss.type.value} en {sast_xss.endpoint}")
        print(f"  DAST: {dast_vuln.type.value} en {dast_vuln.endpoint}")
        
        confidence_2 = correlator._calculate_correlation_confidence(sast_xss, dast_vuln)
        print(f"  ➡️  Confianza de correlación: {confidence_2:.4f}")
        
        if confidence_2 < 0.5:
            print(f"  ✅ No correlación detectada correctamente (<0.5)")
        else:
            print(f"  ⚠️  Confianza alta, posible falso positivo")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en predicción ML: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_full_correlation_workflow(correlator):
    """Test 4: Workflow completo de correlación"""
    print("\n" + "=" * 80)
    print("TEST 4: Workflow Completo de Correlación")
    print("=" * 80)
    
    try:
        sast_vuln, dast_vuln, sast_xss = create_test_vulnerabilities()
        
        # Agregar hallazgos al correlator
        correlator.add_sast_findings([sast_vuln, sast_xss])
        correlator.add_dast_findings([dast_vuln])
        
        print(f"\nHallazgos agregados:")
        print(f"  - SAST: {len(correlator.sast_findings)} vulnerabilidades")
        print(f"  - DAST: {len(correlator.dast_findings)} vulnerabilidades")
        
        # Ejecutar correlación
        correlations = correlator.correlate_vulnerabilities()
        
        print(f"\n✅ Correlaciones encontradas: {len(correlations)}")
        
        for i, (sast, dast, confidence) in enumerate(correlations, 1):
            print(f"\n[Correlación {i}]")
            print(f"  SAST: {sast.type.value} | {sast.endpoint} | {sast.source_tool}")
            print(f"  DAST: {dast.type.value} | {dast.endpoint} | {dast.source_tool}")
            print(f"  Confianza: {confidence:.4f}")
            
            if confidence > 0.7:
                print(f"  ✅ Correlación válida")
            else:
                print(f"  ⚠️  Correlación débil")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en workflow de correlación: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Ejecuta todos los tests de integración"""
    print("\n" + "🔬" * 40)
    print("TEST DE INTEGRACIÓN: Modelo ML en Correlation Engine")
    print("🔬" * 40 + "\n")
    
    results = {
        'model_loading': False,
        'feature_engineering': False,
        'ml_prediction': False,
        'full_workflow': False
    }
    
    # Test 1: Cargar modelo
    correlator, model_loaded = test_model_loading()
    results['model_loading'] = model_loaded
    
    if correlator is None:
        print("\n❌ Tests abortados: no se pudo inicializar el correlator")
        return
    
    # Test 2: Feature engineering (solo si el modelo está cargado)
    if model_loaded:
        results['feature_engineering'] = test_feature_engineering(correlator)
        
        # Test 3: Predicción ML (solo si feature engineering funciona)
        if results['feature_engineering']:
            results['ml_prediction'] = test_ml_prediction(correlator)
    else:
        print("\n⚠️  Saltando tests de ML (modelo no disponible)")
    
    # Test 4: Workflow completo (siempre ejecutar)
    results['full_workflow'] = test_full_correlation_workflow(correlator)
    
    # Resumen final
    print("\n" + "=" * 80)
    print("RESUMEN DE TESTS")
    print("=" * 80)
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} | {test_name.replace('_', ' ').title()}")
    
    print(f"\nResultado: {passed_tests}/{total_tests} tests pasados")
    
    if passed_tests == total_tests:
        print("🎉 ¡Todos los tests pasaron exitosamente!")
    elif passed_tests >= total_tests * 0.75:
        print("⚠️  Mayoría de tests pasaron, revisar fallos menores")
    else:
        print("❌ Tests fallaron, revisar implementación")
    
    print("\n" + "🔬" * 40 + "\n")

if __name__ == "__main__":
    main()
