"""
Script para entrenar el modelo de Machine Learning de correlación SAST-DAST

Autor: Oscar Isaac Laguna Santa Cruz
Universidad Nacional Mayor de San Marcos
Fecha: Noviembre 2025

Requisitos:
    pip install scikit-learn pandas numpy joblib

Uso:
    python backend/train_ml_model.py
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve
)
import joblib
import json
from datetime import datetime


class CorrelationMLTrainer:
    """Entrenador del modelo de ML para correlación de vulnerabilidades"""
    
    def __init__(self, data_dir: Path = Path("data/processed"), model_dir: Path = Path("data/models")):
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Modelos
        self.rf_classifier = None
        self.tfidf_vectorizer = None
        self.label_encoders = {}
        
        # Datos
        self.X_train = None
        self.y_train = None
        self.X_val = None
        self.y_val = None
        self.X_test = None
        self.y_test = None
        
        # Métricas
        self.training_metrics = {}
        
    def load_datasets(self):
        """Carga los datasets de entrenamiento, validación y prueba"""
        print("\n📂 Cargando datasets...")
        
        train_file = self.data_dir / "training_set.csv"
        val_file = self.data_dir / "validation_set.csv"
        test_file = self.data_dir / "test_set.csv"
        
        if not train_file.exists():
            raise FileNotFoundError(f"❌ No se encontró {train_file}")
        
        self.train_df = pd.read_csv(train_file)
        self.val_df = pd.read_csv(val_file)
        self.test_df = pd.read_csv(test_file)
        
        print(f"   ✅ Training:   {len(self.train_df):,} muestras")
        print(f"   ✅ Validation: {len(self.val_df):,} muestras")
        print(f"   ✅ Test:       {len(self.test_df):,} muestras")
        
        # Estadísticas de clases
        print(f"\n📊 Distribución de clases (Training):")
        print(f"   Correlacionadas:     {self.train_df['is_correlated'].sum():,} ({self.train_df['is_correlated'].sum()/len(self.train_df)*100:.1f}%)")
        print(f"   No correlacionadas:  {len(self.train_df) - self.train_df['is_correlated'].sum():,} ({(len(self.train_df) - self.train_df['is_correlated'].sum())/len(self.train_df)*100:.1f}%)")
    
    def engineer_features(self, df: pd.DataFrame, fit: bool = False) -> np.ndarray:
        """
        Genera features para el modelo de ML
        
        Args:
            df: DataFrame con los datos
            fit: Si es True, ajusta los encoders/vectorizers
        
        Returns:
            Feature matrix (numpy array)
        """
        features_list = []
        
        # 1. Features textuales (TF-IDF)
        print("   🔤 Vectorizando descripciones con TF-IDF...")
        combined_descriptions = (
            df['sast_description'].fillna('') + ' ' + 
            df['dast_description'].fillna('')
        )
        
        if fit:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=500,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=2
            )
            tfidf_features = self.tfidf_vectorizer.fit_transform(combined_descriptions).toarray()
        else:
            tfidf_features = self.tfidf_vectorizer.transform(combined_descriptions).toarray()
        
        features_list.append(tfidf_features)
        
        # 2. Features categóricas (Label Encoding)
        print("   🏷️  Codificando features categóricas...")
        categorical_cols = ['sast_type', 'dast_type', 'sast_severity', 'dast_severity', 
                           'sast_cwe', 'dast_cwe', 'sast_tool', 'dast_tool']
        
        for col in categorical_cols:
            if fit:
                le = LabelEncoder()
                encoded = le.fit_transform(df[col].fillna('UNKNOWN'))
                self.label_encoders[col] = le
            else:
                le = self.label_encoders[col]
                # Manejar valores no vistos en training
                encoded = df[col].fillna('UNKNOWN').apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                ).values
            
            # encoded ya es numpy array si viene de fit_transform
            if isinstance(encoded, np.ndarray):
                features_list.append(encoded.reshape(-1, 1))
            else:
                features_list.append(encoded.values.reshape(-1, 1))
        
        # 3. Features numéricas
        print("   🔢 Extrayendo features numéricas...")
        numeric_features = []
        
        # Similitud de tipos
        type_match = (df['sast_type'] == df['dast_type']).astype(int).values.reshape(-1, 1)
        numeric_features.append(type_match)
        
        # Similitud de CWE
        cwe_match = (df['sast_cwe'] == df['dast_cwe']).astype(int).values.reshape(-1, 1)
        numeric_features.append(cwe_match)
        
        # Similitud de severidad
        severity_match = (df['sast_severity'] == df['dast_severity']).astype(int).values.reshape(-1, 1)
        numeric_features.append(severity_match)
        
        # Similitud de herramienta (SAST vs DAST)
        same_tool_vendor = ((df['sast_tool'] == 'bandit') & (df['dast_tool'] == 'zap')).astype(int).values.reshape(-1, 1)
        numeric_features.append(same_tool_vendor)
        
        # Longitud de descripciones
        sast_desc_len = df['sast_description'].fillna('').str.len().values.reshape(-1, 1)
        dast_desc_len = df['dast_description'].fillna('').str.len().values.reshape(-1, 1)
        numeric_features.extend([sast_desc_len, dast_desc_len])
        
        # Línea de código (SAST)
        sast_line = df['sast_line'].fillna(0).values.reshape(-1, 1)
        numeric_features.append(sast_line)
        
        # Longitud de path/endpoint
        sast_file_depth = df['sast_file'].fillna('').str.count('/').values.reshape(-1, 1)
        dast_endpoint_depth = df['dast_endpoint'].fillna('').str.count('/').values.reshape(-1, 1)
        numeric_features.extend([sast_file_depth, dast_endpoint_depth])
        
        features_list.extend(numeric_features)
        
        # Concatenar todas las features
        X = np.hstack(features_list)
        
        print(f"   ✅ Feature matrix: {X.shape[0]:,} muestras × {X.shape[1]} features")
        
        return X
    
    def train_model(self):
        """Entrena el modelo Random Forest"""
        print("\n🤖 Entrenando modelo Random Forest...")
        
        # Ingeniería de features
        print("\n🔧 Ingeniería de features (Training)...")
        self.X_train = self.engineer_features(self.train_df, fit=True)
        self.y_train = self.train_df['is_correlated'].values
        
        print("\n🔧 Ingeniería de features (Validation)...")
        self.X_val = self.engineer_features(self.val_df, fit=False)
        self.y_val = self.val_df['is_correlated'].values
        
        print("\n🔧 Ingeniería de features (Test)...")
        self.X_test = self.engineer_features(self.test_df, fit=False)
        self.y_test = self.test_df['is_correlated'].values
        
        # Configurar Random Forest
        print("\n🌲 Configurando Random Forest Classifier...")
        self.rf_classifier = RandomForestClassifier(
            n_estimators=200,           # Número de árboles
            max_depth=20,               # Profundidad máxima
            min_samples_split=10,       # Mínimo de muestras para split
            min_samples_leaf=5,         # Mínimo de muestras en hoja
            max_features='sqrt',        # Features a considerar en cada split
            random_state=42,            # Reproducibilidad
            n_jobs=-1,                  # Usar todos los cores
            verbose=1,                  # Mostrar progreso
            class_weight='balanced'     # Balancear clases
        )
        
        # Entrenar
        print("\n📚 Entrenando modelo...")
        self.rf_classifier.fit(self.X_train, self.y_train)
        print("   ✅ Entrenamiento completado")
        
    def evaluate_model(self):
        """Evalúa el modelo en los conjuntos de validación y prueba"""
        print("\n📊 Evaluando modelo...")
        
        # Predicciones
        y_val_pred = self.rf_classifier.predict(self.X_val)
        y_val_proba = self.rf_classifier.predict_proba(self.X_val)[:, 1]
        
        y_test_pred = self.rf_classifier.predict(self.X_test)
        y_test_proba = self.rf_classifier.predict_proba(self.X_test)[:, 1]
        
        # Métricas de Validación
        print("\n🎯 Métricas en Validation Set:")
        val_accuracy = accuracy_score(self.y_val, y_val_pred)
        val_precision, val_recall, val_f1, _ = precision_recall_fscore_support(
            self.y_val, y_val_pred, average='binary'
        )
        val_auc = roc_auc_score(self.y_val, y_val_proba)
        
        print(f"   Accuracy:  {val_accuracy:.4f}")
        print(f"   Precision: {val_precision:.4f}")
        print(f"   Recall:    {val_recall:.4f}")
        print(f"   F1-Score:  {val_f1:.4f}")
        print(f"   ROC-AUC:   {val_auc:.4f}")
        
        # Métricas de Test
        print("\n🎯 Métricas en Test Set:")
        test_accuracy = accuracy_score(self.y_test, y_test_pred)
        test_precision, test_recall, test_f1, _ = precision_recall_fscore_support(
            self.y_test, y_test_pred, average='binary'
        )
        test_auc = roc_auc_score(self.y_test, y_test_proba)
        
        print(f"   Accuracy:  {test_accuracy:.4f}")
        print(f"   Precision: {test_precision:.4f}")
        print(f"   Recall:    {test_recall:.4f}")
        print(f"   F1-Score:  {test_f1:.4f}")
        print(f"   ROC-AUC:   {test_auc:.4f}")
        
        # Matriz de confusión
        print("\n📋 Matriz de Confusión (Test Set):")
        cm = confusion_matrix(self.y_test, y_test_pred)
        print(f"   TN: {cm[0,0]:,}  |  FP: {cm[0,1]:,}")
        print(f"   FN: {cm[1,0]:,}  |  TP: {cm[1,1]:,}")
        
        # Reporte de clasificación
        print("\n📝 Reporte de Clasificación (Test Set):")
        print(classification_report(self.y_test, y_test_pred, 
                                   target_names=['No Correlacionadas', 'Correlacionadas']))
        
        # Guardar métricas
        self.training_metrics = {
            "validation": {
                "accuracy": float(val_accuracy),
                "precision": float(val_precision),
                "recall": float(val_recall),
                "f1_score": float(val_f1),
                "roc_auc": float(val_auc)
            },
            "test": {
                "accuracy": float(test_accuracy),
                "precision": float(test_precision),
                "recall": float(test_recall),
                "f1_score": float(test_f1),
                "roc_auc": float(test_auc)
            },
            "confusion_matrix": {
                "TN": int(cm[0,0]),
                "FP": int(cm[0,1]),
                "FN": int(cm[1,0]),
                "TP": int(cm[1,1])
            },
            "training_info": {
                "n_train_samples": int(len(self.train_df)),
                "n_val_samples": int(len(self.val_df)),
                "n_test_samples": int(len(self.test_df)),
                "n_features": int(self.X_train.shape[1]),
                "trained_at": datetime.now().isoformat()
            }
        }
        
        # Feature importance
        print("\n🔝 Top 15 Features Más Importantes:")
        feature_importance = self.rf_classifier.feature_importances_
        top_indices = np.argsort(feature_importance)[-15:][::-1]
        
        for idx in top_indices:
            print(f"   Feature {idx}: {feature_importance[idx]:.4f}")
    
    def save_model(self):
        """Guarda el modelo entrenado y metadatos"""
        print("\n💾 Guardando modelo...")
        
        # Guardar modelo
        model_file = self.model_dir / "rf_correlator_v1.pkl"
        model_package = {
            'classifier': self.rf_classifier,
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'label_encoders': self.label_encoders,
            'feature_count': self.X_train.shape[1],
            'version': '1.0.0',
            'trained_at': datetime.now().isoformat()
        }
        
        joblib.dump(model_package, model_file)
        print(f"   ✅ Modelo guardado: {model_file}")
        
        # Guardar métricas
        metrics_file = self.model_dir / "metadata.json"
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(self.training_metrics, f, indent=2)
        print(f"   ✅ Métricas guardadas: {metrics_file}")
        
        print("\n✅ ¡Modelo entrenado y guardado exitosamente!")
        print("\n📝 Resumen para tu tesis:")
        print(f"   - Dataset: {len(self.train_df) + len(self.val_df) + len(self.test_df):,} muestras")
        print(f"   - Accuracy: {self.training_metrics['test']['accuracy']:.1%}")
        print(f"   - Precision: {self.training_metrics['test']['precision']:.1%}")
        print(f"   - Recall: {self.training_metrics['test']['recall']:.1%}")
        print(f"   - F1-Score: {self.training_metrics['test']['f1_score']:.1%}")
        print(f"   - ROC-AUC: {self.training_metrics['test']['roc_auc']:.4f}")
    
    def run_full_pipeline(self):
        """Ejecuta el pipeline completo de entrenamiento"""
        print("=" * 70)
        print("  ML Correlation Model Trainer - HybridSecScan")
        print("  Universidad Nacional Mayor de San Marcos")
        print("=" * 70)
        
        try:
            self.load_datasets()
            self.train_model()
            self.evaluate_model()
            self.save_model()
            
            print("\n" + "=" * 70)
            print("  ✅ ENTRENAMIENTO COMPLETADO EXITOSAMENTE")
            print("=" * 70)
            
        except Exception as e:
            print(f"\n❌ Error durante el entrenamiento: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Función principal"""
    trainer = CorrelationMLTrainer()
    trainer.run_full_pipeline()


if __name__ == "__main__":
    main()
