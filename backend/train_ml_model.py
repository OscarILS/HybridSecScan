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
    roc_curve,
    precision_recall_curve,
    average_precision_score
)
import joblib
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Bibliotecas de visualización
import matplotlib.pyplot as plt
import seaborn as sns

# Configurar estilo visual profesional
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")
sns.set_context("notebook", font_scale=1.2)
import warnings
warnings.filterwarnings('ignore')

# Bibliotecas de visualización
import matplotlib.pyplot as plt
import seaborn as sns

# Configurar estilo visual profesional
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")
sns.set_context("notebook", font_scale=1.2)


class TrainingVisualizer:
    """Genera visualizaciones profesionales tipo Colab/Jupyter del entrenamiento ML"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir / "visualizations"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.colors = {
            'primary': '#2E86AB',
            'secondary': '#A23B72',
            'success': '#06A77D',
            'warning': '#F18F01',
            'danger': '#C73E1D'
        }
    
    def plot_class_distribution(self, y_train, y_test):
        """Gráfica de barras: Distribución de clases"""
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        
        for idx, (title, data) in enumerate([('Training Set', y_train), ('Test Set', y_test)]):
            unique, counts = np.unique(data, return_counts=True)
            bars = axes[idx].bar(
                ['No Correlacionada', 'Correlacionada'],
                counts,
                color=[self.colors['success'], self.colors['danger']],
                edgecolor='black', linewidth=1.5
            )
            for bar in bars:
                height = bar.get_height()
                axes[idx].text(bar.get_x() + bar.get_width()/2., height,
                             f'{int(height)}\n({height/sum(counts)*100:.1f}%)',
                             ha='center', va='bottom', fontweight='bold', fontsize=10)
            axes[idx].set_title(title, fontsize=14, fontweight='bold')
            axes[idx].set_ylabel('Cantidad de Muestras', fontsize=12)
            axes[idx].grid(axis='y', alpha=0.3)
        
        plt.suptitle('Distribución de Clases en Datasets', fontsize=16, fontweight='bold', y=1.02)
        plt.tight_layout()
        plt.savefig(self.output_dir / '01_class_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: 01_class_distribution.png")
    
    def plot_feature_importance(self, importances, top_n=20):
        """Gráfica de barras: Top N features más importantes"""
        indices = np.argsort(importances)[::-1][:top_n]
        top_importances = importances[indices]
        top_features = [f'Feature {i}' for i in indices]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        colors_gradient = plt.cm.viridis(np.linspace(0.3, 0.9, len(top_features)))
        bars = ax.barh(range(len(top_features)), top_importances,
                      color=colors_gradient, edgecolor='black', linewidth=1)
        
        ax.set_yticks(range(len(top_features)))
        ax.set_yticklabels(top_features, fontsize=10)
        ax.set_xlabel('Importancia (Gini Impurity)', fontsize=12, fontweight='bold')
        ax.set_title(f'Top {top_n} Features Más Importantes', fontsize=14, fontweight='bold', pad=20)
        
        for idx, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2, f' {width:.4f}',
                   ha='left', va='center', fontsize=9, fontweight='bold')
        
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        ax.invert_yaxis()
        plt.tight_layout()
        plt.savefig(self.output_dir / '02_feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: 02_feature_importance.png")
    
    def plot_confusion_matrix(self, cm):
        """Heatmap de matriz de confusión"""
        fig, ax = plt.subplots(figsize=(10, 8))
        cm_percent = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis] * 100
        
        sns.heatmap(cm, annot=False, fmt='d', cmap='Blues',
                   cbar_kws={'label': 'Cantidad'}, ax=ax,
                   linewidths=2, linecolor='black')
        
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                text = f'{cm[i, j]}\n({cm_percent[i, j]:.1f}%)'
                ax.text(j + 0.5, i + 0.5, text, ha='center', va='center',
                       color='white' if cm[i, j] > cm.max()/2 else 'black',
                       fontsize=14, fontweight='bold')
        
        ax.set_xticklabels(['No Correlacionada', 'Correlacionada'], fontsize=12)
        ax.set_yticklabels(['No Correlacionada', 'Correlacionada'], fontsize=12, rotation=0)
        ax.set_xlabel('Predicción', fontsize=13, fontweight='bold')
        ax.set_ylabel('Valor Real', fontsize=13, fontweight='bold')
        ax.set_title('Matriz de Confusión', fontsize=15, fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / '03_confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: 03_confusion_matrix.png")
    
    def plot_roc_curve(self, fpr, tpr, roc_auc):
        """Curva ROC con área bajo la curva"""
        fig, ax = plt.subplots(figsize=(10, 8))
        
        ax.plot(fpr, tpr, color=self.colors['primary'], linewidth=3,
               label=f'ROC Curve (AUC = {roc_auc:.4f})')
        ax.fill_between(fpr, tpr, alpha=0.3, color=self.colors['primary'])
        ax.plot([0, 1], [0, 1], 'k--', linewidth=2, label='Random Classifier')
        
        ax.set_xlabel('False Positive Rate', fontsize=13, fontweight='bold')
        ax.set_ylabel('True Positive Rate', fontsize=13, fontweight='bold')
        ax.set_title('Receiver Operating Characteristic (ROC) Curve',
                    fontsize=15, fontweight='bold', pad=20)
        ax.legend(loc='lower right', fontsize=11, frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.set_xlim([-0.02, 1.02])
        ax.set_ylim([-0.02, 1.02])
        
        plt.tight_layout()
        plt.savefig(self.output_dir / '04_roc_curve.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: 04_roc_curve.png")
    
    def plot_precision_recall_curve(self, y_test, y_proba):
        """Curva Precision-Recall"""
        precision, recall, _ = precision_recall_curve(y_test, y_proba)
        avg_precision = average_precision_score(y_test, y_proba)
        
        fig, ax = plt.subplots(figsize=(10, 8))
        ax.plot(recall, precision, color=self.colors['secondary'], linewidth=3,
               label=f'PR Curve (AP = {avg_precision:.4f})')
        ax.fill_between(recall, precision, alpha=0.3, color=self.colors['secondary'])
        
        ax.set_xlabel('Recall', fontsize=13, fontweight='bold')
        ax.set_ylabel('Precision', fontsize=13, fontweight='bold')
        ax.set_title('Precision-Recall Curve', fontsize=15, fontweight='bold', pad=20)
        ax.legend(loc='lower left', fontsize=11, frameon=True, shadow=True)
        ax.grid(True, alpha=0.3, linestyle='--')
        ax.set_xlim([-0.02, 1.02])
        ax.set_ylim([-0.02, 1.02])
        
        plt.tight_layout()
        plt.savefig(self.output_dir / '05_precision_recall_curve.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: 05_precision_recall_curve.png")
    
    def plot_metrics_comparison(self, metrics):
        """Gráfica comparativa de métricas"""
        fig, ax = plt.subplots(figsize=(12, 6))
        
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        metric_values = [metrics['accuracy'], metrics['precision'],
                        metrics['recall'], metrics['f1_score']]
        colors = [self.colors['primary'], self.colors['success'],
                 self.colors['warning'], self.colors['danger']]
        
        bars = ax.bar(metric_names, metric_values, color=colors,
                     edgecolor='black', linewidth=2, alpha=0.8)
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.4f}\n({height*100:.2f}%)',
                   ha='center', va='bottom', fontsize=12, fontweight='bold')
        
        ax.axhline(y=0.8, color='red', linestyle='--', linewidth=2,
                  alpha=0.5, label='Threshold (0.80)')
        ax.set_ylabel('Score', fontsize=13, fontweight='bold')
        ax.set_title('Métricas de Evaluación del Modelo',
                    fontsize=15, fontweight='bold', pad=20)
        ax.set_ylim([0, 1.1])
        ax.legend(loc='upper right', fontsize=11)
        ax.grid(axis='y', alpha=0.3, linestyle='--')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / '06_metrics_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: 06_metrics_comparison.png")
    
    def plot_correlation_heatmap(self, X_train, feature_names, top_n=20):
        """Mapa de calor de correlación entre features principales"""
        # Seleccionar las top_n features más importantes (últimas features que son las categóricas/numéricas)
        # Las features 500-516 son las más interpretables
        start_idx = max(0, len(feature_names) - top_n)
        selected_features = feature_names[start_idx:]
        X_subset = X_train[:, start_idx:]
        
        # Calcular matriz de correlación
        df = pd.DataFrame(X_subset, columns=selected_features)
        correlation_matrix = df.corr()
        
        # Crear el heatmap
        fig, ax = plt.subplots(figsize=(14, 12))
        
        # Generar mapa de calor
        sns.heatmap(
            correlation_matrix,
            annot=True,
            fmt='.2f',
            cmap='RdYlBu_r',
            center=0,
            square=True,
            linewidths=0.5,
            cbar_kws={"shrink": 0.8, "label": "Correlación de Pearson"},
            vmin=-1,
            vmax=1,
            ax=ax
        )
        
        ax.set_title('Mapa de Calor de Correlación entre Features Principales',
                    fontsize=16, fontweight='bold', pad=20)
        ax.set_xlabel('Features', fontsize=12, fontweight='bold')
        ax.set_ylabel('Features', fontsize=12, fontweight='bold')
        
        # Rotar etiquetas para mejor legibilidad
        plt.xticks(rotation=45, ha='right', fontsize=9)
        plt.yticks(rotation=0, fontsize=9)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'correlation_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: correlation_heatmap.png")
    
    def plot_feature_distribution_by_class(self, X_train, y_train, feature_names, top_n=8):
        """Boxplots comparativos de distribución de features por clase"""
        # Seleccionar las últimas features (categóricas/numéricas más interpretables)
        start_idx = max(0, len(feature_names) - top_n)
        selected_features = feature_names[start_idx:]
        X_subset = X_train[:, start_idx:]
        
        # Crear DataFrame con features y target
        df = pd.DataFrame(X_subset, columns=selected_features)
        df['Correlación'] = ['Correlacionadas' if y == 1 else 'No Correlacionadas' for y in y_train]
        
        # Crear figura con subplots
        n_features = len(selected_features)
        n_cols = 2
        n_rows = (n_features + n_cols - 1) // n_cols
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(14, 4 * n_rows))
        axes = axes.flatten() if n_features > 1 else [axes]
        
        # Colores para las clases
        colors = [self.colors['success'], self.colors['danger']]
        
        # Crear boxplot para cada feature
        for idx, feature in enumerate(selected_features):
            ax = axes[idx]
            
            # Preparar datos
            data_to_plot = [
                df[df['Correlación'] == 'No Correlacionadas'][feature].values,
                df[df['Correlación'] == 'Correlacionadas'][feature].values
            ]
            
            # Crear boxplot
            bp = ax.boxplot(
                data_to_plot,
                labels=['No Correlacionadas', 'Correlacionadas'],
                patch_artist=True,
                widths=0.6,
                showmeans=True,
                meanprops=dict(marker='D', markerfacecolor='yellow', markeredgecolor='black', markersize=8)
            )
            
            # Colorear las cajas
            for patch, color in zip(bp['boxes'], colors):
                patch.set_facecolor(color)
                patch.set_alpha(0.7)
            
            # Estilo
            ax.set_title(feature, fontsize=11, fontweight='bold')
            ax.set_ylabel('Valor de Feature', fontsize=10)
            ax.grid(axis='y', alpha=0.3, linestyle='--')
            ax.tick_params(axis='x', rotation=15)
        
        # Ocultar axes sobrantes si n_features es impar
        for idx in range(n_features, len(axes)):
            axes[idx].set_visible(False)
        
        plt.suptitle('Distribución de Features Numéricas Principales por Clase de Correlación',
                    fontsize=16, fontweight='bold', y=1.00)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'feature_distribution_boxplots.png', dpi=300, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Gráfica guardada: feature_distribution_boxplots.png")


class CorrelationMLTrainer:
    """Entrenador del modelo de ML para correlación de vulnerabilidades"""
    
    def __init__(self, data_dir: Path = Path("data/processed"), model_dir: Path = Path("data/models")):
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Inicializar visualizador
        self.visualizer = TrainingVisualizer(self.model_dir)
        
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
        
        # Generar visualizaciones
        print("\n📊 Generando visualizaciones...")
        try:
            # 1. Distribución de clases
            self.visualizer.plot_class_distribution(self.y_train, self.y_test)
            
            # 2. Mapa de calor de correlación
            feature_names_list = [f"Feature_{i}" for i in range(self.X_train.shape[1])]
            self.visualizer.plot_correlation_heatmap(self.X_train, feature_names_list, top_n=20)
            
            # 3. Distribución de features por clase (boxplots)
            self.visualizer.plot_feature_distribution_by_class(self.X_train, self.y_train, feature_names_list, top_n=8)
            
            # 4. Importancia de features
            self.visualizer.plot_feature_importance(feature_importance)
            
            # 5. Matriz de confusión
            self.visualizer.plot_confusion_matrix(cm)
            
            # 6. Curva ROC
            fpr, tpr, _ = roc_curve(self.y_test, y_test_proba)
            self.visualizer.plot_roc_curve(fpr, tpr, test_auc)
            
            # 7. Curva Precision-Recall
            self.visualizer.plot_precision_recall_curve(self.y_test, y_test_proba)
            
            # 8. Comparación de métricas
            metrics_dict = {
                'accuracy': test_accuracy,
                'precision': test_precision,
                'recall': test_recall,
                'f1_score': test_f1
            }
            self.visualizer.plot_metrics_comparison(metrics_dict)
            
            print(f"\n   ✅ Todas las visualizaciones guardadas en: {self.visualizer.output_dir}/")
        except Exception as e:
            print(f"\n   ⚠️  Error al generar visualizaciones: {e}")
            print("   (El modelo se guardará de todas formas)")
    
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
