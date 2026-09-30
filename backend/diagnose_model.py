"""
Script de diagnóstico para verificar calidad del modelo ML
HybridSecScan - UNMSM FISI

Este script verifica posibles problemas de:
- Data leakage
- Overfitting
- Features sospechosas
- Separabilidad artificial de clases
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


def diagnose_training_data():
    """Verifica si hay problemas en los datos de entrenamiento"""

    data_path = Path("data/processed")

    print("=" * 70)
    print("🔍 DIAGNÓSTICO DE DATOS DE ENTRENAMIENTO")
    print("=" * 70)

    # 1. Cargar datos
    try:
        train_df = pd.read_csv(data_path / "training_set.csv")
        test_df = pd.read_csv(data_path / "test_set.csv")
    except FileNotFoundError as e:
        print("\n❌ Error: No se encontraron los archivos de datos")
        print(f"   {e}")
        print(f"\n   Archivos esperados en: {data_path.absolute()}")
        print("   - training_set.csv")
        print("   - test_set.csv")
        return

    print("\n📊 Tamaño de datasets:")
    print(f"   Train: {len(train_df):,} muestras")
    print(f"   Test:  {len(test_df):,} muestras")

    # 2. Verificar columnas disponibles
    print("\n📋 Columnas disponibles:")
    print(f"   {list(train_df.columns)}")

    # 3. Verificar distribución de clases
    if "is_correlated" in train_df.columns:
        print("\n📈 Distribución de clases (Train):")
        dist_train = train_df["is_correlated"].value_counts(normalize=True)
        print(f"   Correlacionadas (1):     {dist_train.get(1, 0)*100:.2f}%")
        print(f"   No Correlacionadas (0):  {dist_train.get(0, 0)*100:.2f}%")

        print("\n📈 Distribución de clases (Test):")
        dist_test = test_df["is_correlated"].value_counts(normalize=True)
        print(f"   Correlacionadas (1):     {dist_test.get(1, 0)*100:.2f}%")
        print(f"   No Correlacionadas (0):  {dist_test.get(0, 0)*100:.2f}%")

        # Verificar desbalanceo
        imbalance = abs(dist_train.get(1, 0) - dist_train.get(0, 0))
        if imbalance > 0.3:
            print(f"   ⚠️  Dataset desbalanceado: {imbalance*100:.1f}% diferencia")

    # 4. Verificar unicidad de vulnerabilidades
    if "sast_vuln_id" in train_df.columns and "dast_vuln_id" in train_df.columns:
        print("\n🔑 Unicidad de vulnerabilidades:")
        print(f"   IDs únicos SAST (train): {train_df['sast_vuln_id'].nunique():,}")
        print(f"   IDs únicos DAST (train): {train_df['dast_vuln_id'].nunique():,}")

        unique_pairs = len(train_df.drop_duplicates(["sast_vuln_id", "dast_vuln_id"]))
        print(f"   Pares únicos: {unique_pairs:,} de {len(train_df):,} ({unique_pairs/len(train_df)*100:.1f}%)")

        if unique_pairs < len(train_df) * 0.5:
            print("   🚨 ¡MUCHAS DUPLICACIONES! Más del 50% son pares repetidos")

    # 5. Verificar si hay overlap entre train y test (DATA LEAKAGE)
    if "sast_vuln_id" in train_df.columns and "dast_vuln_id" in train_df.columns:
        train_pairs = set(zip(train_df["sast_vuln_id"], train_df["dast_vuln_id"]))
        test_pairs = set(zip(test_df["sast_vuln_id"], test_df["dast_vuln_id"]))
        overlap = train_pairs.intersection(test_pairs)

        print("\n⚠️  Overlap Train-Test (DATA LEAKAGE):")
        print(f"   Pares en común: {len(overlap):,} ({len(overlap)/len(test_pairs)*100:.2f}%)")

        if len(overlap) > 0:
            print("   🚨 ¡DATA LEAKAGE DETECTADO! Hay datos de test en train")
            print("   Esto explica el 100% de accuracy - el modelo ya vio los datos")
        else:
            print("   ✅ No hay overlap directo de pares")

    # 6. Verificar features sospechosas que revelan la respuesta
    print("\n🔍 Verificando features sospechosas:")

    suspicious_patterns = ["match", "same", "equal", "identical", "corr"]
    suspicious_cols = [
        col for col in train_df.columns if any(pattern in col.lower() for pattern in suspicious_patterns)
    ]

    if suspicious_cols:
        print("   ⚠️  Columnas con nombres sospechosos:")
        for col in suspicious_cols:
            if col in train_df.columns and col != "is_correlated":
                try:
                    corr = train_df[col].corr(train_df["is_correlated"])
                    print(f"   - {col}: correlación = {corr:.4f}")
                    if abs(corr) > 0.95:
                        print("     🚨 ¡CORRELACIÓN PERFECTA! Esta feature da la respuesta")
                except Exception:
                    pass
    else:
        print("   ✅ No se encontraron columnas con nombres sospechosos")

    # 7. Verificar variabilidad de features numéricas
    print("\n📊 Variabilidad de features numéricas:")
    numeric_cols = train_df.select_dtypes(include=[np.number]).columns
    low_variance = []

    for col in numeric_cols:
        if col != "is_correlated":
            variance = train_df[col].var()
            if variance < 0.01 and not pd.isna(variance):
                low_variance.append((col, variance))

    if low_variance:
        print("   ⚠️  Features con baja varianza (casi constantes):")
        for col, var in low_variance[:5]:
            print(f"   - {col}: varianza = {var:.6f}")
    else:
        print("   ✅ Todas las features tienen varianza adecuada")

    # 8. Verificar separabilidad de clases
    if "is_correlated" in train_df.columns:
        print("\n🎯 Análisis de separabilidad de clases:")

        corr_samples = train_df[train_df["is_correlated"] == 1]
        no_corr_samples = train_df[train_df["is_correlated"] == 0]

        numeric_features = train_df.select_dtypes(include=[np.number]).columns
        numeric_features = numeric_features.drop("is_correlated", errors="ignore")

        if len(numeric_features) > 0:
            try:
                corr_mean = corr_samples[numeric_features].mean()
                no_corr_mean = no_corr_samples[numeric_features].mean()

                distance = np.linalg.norm(corr_mean - no_corr_mean)
                print(f"   Distancia euclidiana entre centroides: {distance:.4f}")

                if distance > 100:
                    print("   🚨 Las clases están EXTREMADAMENTE separadas")
                    print("   Esto sugiere que el problema es artificialmente fácil")
                elif distance > 50:
                    print("   ⚠️  Las clases están muy separadas")
                    print("   El modelo puede estar memorizando patrones simples")
                else:
                    print("   ✅ Separación normal entre clases")
            except Exception as e:
                print(f"   ⚠️  No se pudo calcular distancia: {e}")

    # 9. Verificar valores idénticos entre train y test
    print("\n🔄 Verificando similitud Train-Test:")

    numeric_cols = train_df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 1:
        train_means = train_df[numeric_cols].mean()
        test_means = test_df[numeric_cols].mean()

        mean_diff = abs(train_means - test_means).mean()
        print(f"   Diferencia promedio de medias: {mean_diff:.4f}")

        if mean_diff < 0.01:
            print("   🚨 Train y Test son prácticamente idénticos")
            print("   Posible split inadecuado o datos sintéticos homogéneos")

    print("\n" + "=" * 70)


def test_model_robustness():
    """Prueba la robustez del modelo con datos sintéticos"""

    print("\n🧪 PRUEBA DE ROBUSTEZ DEL MODELO")
    print("=" * 70)

    model_path = Path("data/models")

    # Verificar si existe el modelo
    model_file = model_path / "rf_correlator_v1.pkl"
    if not model_file.exists():
        print(f"\n❌ No se encontró el modelo en: {model_file.absolute()}")
        return

    try:
        # Cargar modelo y transformadores
        model_data = joblib.load(model_file)
        model = model_data["classifier"]
        vectorizer = model_data["tfidf_vectorizer"]
        label_encoders = model_data["label_encoders"]

        print("\n✅ Modelo cargado exitosamente")
        print(f"   Tipo: {type(model).__name__}")
        print(f"   Features esperadas: {model.n_features_in_}")

    except Exception as e:
        print(f"\n❌ Error al cargar el modelo: {e}")
        return

    # Crear casos de prueba realistas
    print("\n🎯 Casos de prueba sintéticos:\n")

    test_cases = [
        {
            "name": "Caso 1: SQL Injection idéntica (debería correlacionar)",
            "sast_type": "SQL Injection",
            "dast_type": "SQL Injection",
            "sast_severity": "High",
            "dast_severity": "High",
            "sast_cwe": "CWE-89",
            "dast_cwe": "CWE-89",
            "sast_owasp": "API8:2023",
            "dast_owasp": "API8:2023",
            "sast_description": "SQL injection vulnerability in user authentication query",
            "dast_description": "SQL injection detected in login endpoint parameter",
            "expected": "CORRELACIONADAS",
        },
        {
            "name": "Caso 2: Vulnerabilidades completamente diferentes",
            "sast_type": "Cross-Site Scripting",
            "dast_type": "CSRF Token Missing",
            "sast_severity": "Medium",
            "dast_severity": "High",
            "sast_cwe": "CWE-79",
            "dast_cwe": "CWE-352",
            "sast_owasp": "API8:2023",
            "dast_owasp": "API2:2023",
            "sast_description": "Reflected XSS in search form output",
            "dast_description": "Missing anti-CSRF token in POST request",
            "expected": "NO CORRELACIONADAS",
        },
        {
            "name": "Caso 3: Misma familia, contexto diferente",
            "sast_type": "Broken Authentication",
            "dast_type": "Broken Authentication",
            "sast_severity": "Low",
            "dast_severity": "Critical",
            "sast_cwe": "CWE-287",
            "dast_cwe": "CWE-798",
            "sast_owasp": "API2:2023",
            "dast_owasp": "API2:2023",
            "sast_description": "Weak password policy allows simple passwords",
            "dast_description": "Hardcoded credentials found in configuration file",
            "expected": "AMBIGUO (puede variar)",
        },
        {
            "name": "Caso 4: Injection similar pero diferente tecnología",
            "sast_type": "SQL Injection",
            "dast_type": "NoSQL Injection",
            "sast_severity": "High",
            "dast_severity": "High",
            "sast_cwe": "CWE-89",
            "dast_cwe": "CWE-943",
            "sast_owasp": "API8:2023",
            "dast_owasp": "API8:2023",
            "sast_description": "SQL injection in MySQL database query",
            "dast_description": "NoSQL injection in MongoDB query",
            "expected": "NO CORRELACIONADAS",
        },
    ]

    for i, case in enumerate(test_cases, 1):
        print(f"\n{'─'*70}")
        print(f"{i}. {case['name']}")
        print(f"{'─'*70}")
        print(f"   SAST: {case['sast_type']} ({case['sast_severity']}) - {case['sast_cwe']}")
        print(f"   DAST: {case['dast_type']} ({case['dast_severity']}) - {case['dast_cwe']}")

        try:
            # Preparar features de texto (TF-IDF)
            combined_text = f"{case['sast_description']} {case['dast_description']}"
            text_features = vectorizer.transform([combined_text])

            # Preparar features categóricas
            categorical_data = {}
            for feature_name, le in label_encoders.items():
                if feature_name == "sast_vulnerability_type":
                    value = case["sast_type"]
                elif feature_name == "dast_vulnerability_type":
                    value = case["dast_type"]
                elif feature_name == "sast_severity":
                    value = case["sast_severity"]
                elif feature_name == "dast_severity":
                    value = case["dast_severity"]
                elif feature_name == "sast_cwe_id":
                    value = case["sast_cwe"]
                elif feature_name == "dast_cwe_id":
                    value = case["dast_cwe"]
                elif feature_name == "sast_owasp_category":
                    value = case["sast_owasp"]
                elif feature_name == "dast_owasp_category":
                    value = case["dast_owasp"]
                else:
                    continue

                # Codificar (usar -1 si no está en el vocabulario)
                try:
                    encoded = le.transform([value])[0]
                except ValueError:
                    encoded = -1

                categorical_data[feature_name] = encoded

            # Crear array de features categóricas en el orden correcto
            categorical_features = np.array(
                [
                    [
                        categorical_data.get("sast_vulnerability_type", 0),
                        categorical_data.get("dast_vulnerability_type", 0),
                        categorical_data.get("sast_severity", 0),
                        categorical_data.get("dast_severity", 0),
                        categorical_data.get("sast_cwe_id", 0),
                        categorical_data.get("dast_cwe_id", 0),
                        categorical_data.get("sast_owasp_category", 0),
                        categorical_data.get("dast_owasp_category", 0),
                    ]
                ]
            )

            # Features numéricas simples
            numeric_features = np.array(
                [
                    [
                        len(case["sast_description"]),
                        len(case["dast_description"]),
                        1 if case["sast_type"] == case["dast_type"] else 0,
                        1 if case["sast_severity"] == case["dast_severity"] else 0,
                        1 if case["sast_cwe"] == case["dast_cwe"] else 0,
                        1 if case["sast_owasp"] == case["dast_owasp"] else 0,
                        0,  # endpoint_similarity
                        0,  # parameter_similarity
                        0,  # location_proximity
                    ]
                ]
            )

            # Combinar todas las features
            X = np.hstack([text_features.toarray(), categorical_features, numeric_features])

            # Predecir
            prediction = model.predict(X)[0]
            probability = model.predict_proba(X)[0]

            result = "✅ CORRELACIONADAS" if prediction == 1 else "❌ NO CORRELACIONADAS"
            confidence = probability[1] if prediction == 1 else probability[0]

            print(f"\n   Predicción: {result}")
            print(f"   Confianza: {confidence*100:.2f}%")
            print(f"   Probabilidad Correlación: {probability[1]*100:.2f}%")
            print(f"   Probabilidad No Correlación: {probability[0]*100:.2f}%")
            print(f"   Resultado esperado: {case['expected']}")

            # Verificar coherencia
            if confidence < 0.6:
                print("   ⚠️  BAJA CONFIANZA - El modelo está inseguro")
            elif confidence > 0.99:
                print("   🚨 CONFIANZA EXCESIVA - Posible sobreajuste")

        except Exception as e:
            print(f"   ❌ Error en predicción: {e}")

    print("\n" + "=" * 70)


def analyze_feature_importance():
    """Analiza qué features está usando el modelo"""

    print("\n📊 ANÁLISIS DE IMPORTANCIA DE FEATURES")
    print("=" * 70)

    model_path = Path("data/models")
    model_file = model_path / "rf_correlator_v1.pkl"

    if not model_file.exists():
        print("\n❌ No se encontró el modelo")
        return

    try:
        model_data = joblib.load(model_file)
        model = model_data["classifier"]

        # Obtener importancias
        importances = model.feature_importances_

        print("\n🔝 Estadísticas de importancia de features:")
        print(f"   Total de features: {len(importances)}")
        print(f"   Importancia máxima: {importances.max():.4f}")
        print(f"   Importancia mínima: {importances.min():.4f}")
        print(f"   Importancia promedio: {importances.mean():.4f}")
        print(f"   Desviación estándar: {importances.std():.4f}")

        # Top features
        top_indices = np.argsort(importances)[-20:][::-1]

        print("\n🏆 Top 20 features más importantes:")
        for idx in top_indices:
            print(f"   Feature {idx}: {importances[idx]:.4f} ({importances[idx]*100:.2f}%)")

        # Verificar concentración
        top_10_sum = importances[np.argsort(importances)[-10:]].sum()
        print("\n📈 Concentración de importancia:")
        print(f"   Top 10 features acumulan: {top_10_sum*100:.2f}% de importancia")

        if top_10_sum > 0.8:
            print("   🚨 ¡MUY CONCENTRADO! Solo 10 features dominan el modelo")
            print("   Esto puede indicar que el modelo usa 'atajos' en lugar de aprender")

    except Exception as e:
        print(f"\n❌ Error: {e}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    print("\n" + "🔬 DIAGNÓSTICO COMPLETO DEL MODELO ML".center(70))
    print("HybridSecScan - UNMSM FISI\n")

    # Ejecutar todos los diagnósticos
    diagnose_training_data()
    analyze_feature_importance()
    test_model_robustness()

    print("\n" + "=" * 70)
    print("✅ DIAGNÓSTICO COMPLETADO")
    print("=" * 70)
    print("\n💡 Recomendaciones:")
    print("   1. Revisa los resultados arriba para identificar problemas")
    print("   2. Si hay data leakage, rehacer el split train/test")
    print("   3. Si hay features sospechosas, eliminarlas del entrenamiento")
    print("   4. Si el modelo es demasiado confiado, agregar regularización")
    print("   5. Validar con datos reales de APIs en producción")
    print("\n")
