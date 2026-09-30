"""
Algoritmo de Correlación Inteligente de Vulnerabilidades
Correlaciona hallazgos SAST y DAST para identificar los que ambas técnicas confirman
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ── Semantic similarity (sentence-transformers) ───────────────────────────────
# Si sentence-transformers está instalado, se usa para similitud semántica entre
# descripciones de distintas herramientas (resuelve el domain shift del TF-IDF).
# Si no está disponible, se cae automáticamente a similitud de Jaccard.

_semantic_model = None
_SEMANTIC_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    from sentence_transformers import util as st_util

    def _load_semantic_model():
        """Carga el modelo de embeddings semánticos (lazy, solo la primera vez)."""
        global _semantic_model, _SEMANTIC_AVAILABLE
        if _semantic_model is None:
            logger.info("[Correlator] Cargando sentence-transformers/all-MiniLM-L6-v2...")
            _semantic_model = SentenceTransformer("all-MiniLM-L6-v2")
            _SEMANTIC_AVAILABLE = True
            logger.info("[Correlator] Modelo semántico cargado.")
        return _semantic_model

    def semantic_similarity(text1: str, text2: str) -> float:
        """
        Similitud semántica entre dos textos usando embeddings de oraciones.

        Ventaja sobre TF-IDF:
          "SQL injection via string formatting"
          "SQL error response on parameter"
        → alta similitud (~0.82) aunque no compartan palabras exactas.

        El modelo all-MiniLM-L6-v2 es ligero (80 MB) y corre en CPU sin GPU.
        """
        if not text1 or not text2:
            return 0.0
        model = _load_semantic_model()
        emb1 = model.encode(text1, convert_to_tensor=True)
        emb2 = model.encode(text2, convert_to_tensor=True)
        score = float(st_util.cos_sim(emb1, emb2)[0][0])
        return max(0.0, min(1.0, score))

    _SEMANTIC_AVAILABLE = True
    logger.debug("[Correlator] sentence-transformers disponible — usando similitud semántica.")

except ImportError:
    _SEMANTIC_AVAILABLE = False
    logger.debug("[Correlator] sentence-transformers no disponible — usando Jaccard como fallback.")


class VulnerabilityType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    BROKEN_ACCESS = "broken_access_control"
    SECURITY_MISCONFIG = "security_misconfiguration"
    INSUFFICIENT_LOGGING = "insufficient_logging"


# Etiquetas de tipo usadas en el dataset de entrenamiento (scripts/generate_training_dataset.py).
# Tipos sin equivalente en el dataset se codifican como -1 (valor no visto).
_TRAINING_TYPE_LABELS = {
    VulnerabilityType.SQL_INJECTION: "SQL_INJECTION",
    VulnerabilityType.XSS: "XSS",
    VulnerabilityType.BROKEN_AUTH: "BROKEN_AUTH",
    VulnerabilityType.SENSITIVE_DATA: "SENSITIVE_DATA_EXPOSURE",
    VulnerabilityType.SECURITY_MISCONFIG: "SECURITY_MISCONFIG",
}


class ConfidenceLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Vulnerability:
    id: str
    type: VulnerabilityType
    severity: ConfidenceLevel
    file_path: str
    line_number: int
    endpoint: str
    description: str
    cwe_id: str
    owasp_category: str
    source_tool: str  # 'bandit', 'semgrep', 'zap'


# Pesos de la confianza de correlación (decisión de diseño; suman 1.0).
CONFIDENCE_WEIGHTS: Dict[str, float] = {
    "endpoint": 0.40,
    "type": 0.35,
    "semantic": 0.10,
    "ml": 0.10,
    "severity": 0.05,
}
RELATED_TYPE_CREDIT = 0.20  # aporte del factor "type" cuando los tipos están relacionados


class VulnerabilityCorrelator:
    """
    Correlaciona vulnerabilidades encontradas por herramientas SAST y DAST
    usando una suma ponderada de factores y un modelo Random Forest.

    - Confianza: ver _calculate_correlation_confidence (pesos por diseño).
    - Modelo: Random Forest entrenado con 1,300 pares sintéticos
      (scripts/generate_training_dataset.py); métricas reales en
      data/models/metadata.json.
    - Marco de referencia: OWASP API Security Top 10 (2023).
    """

    def __init__(self):
        self.sast_findings: List[Vulnerability] = []
        self.dast_findings: List[Vulnerability] = []
        self.correlation_rules = self._load_correlation_rules()
        # Métricas del modelo: las rellena _initialize_ml_model desde metadata.json.
        # Queda vacío si no hay modelo entrenado; nunca se hardcodean.
        self.model_metrics: Dict = {}
        self.ml_model = self._initialize_ml_model()

    def _load_correlation_rules(self) -> Dict:
        """Carga las reglas de correlación por tipo (indicadores SAST y DAST)."""
        return {
            "sql_injection": {
                "sast_indicators": ["execute", "query", "cursor.execute", "raw SQL"],
                "dast_indicators": ["SQL syntax error", "database error", "UNION SELECT"],
                "correlation_weight": 0.9,
            },
            "xss": {
                "sast_indicators": ["innerHTML", "document.write", "eval(", "dangerouslySetInnerHTML"],
                "dast_indicators": ["<script>", "javascript:", "onerror="],
                "correlation_weight": 0.8,
            },
            "broken_authentication": {
                "sast_indicators": ["password", "session", "token", "jwt"],
                "dast_indicators": ["401 Unauthorized", "403 Forbidden", "session"],
                "correlation_weight": 0.85,
            },
        }

    def _initialize_ml_model(self):
        """
        Inicializa el modelo de Machine Learning para correlación.

        Modelo: Random Forest Classifier
        Justificación:
        - Interpretabilidad: Permite feature importance analysis
        - Robustez: Maneja bien datos mixtos (categóricos + numéricos)
        - Métricas reales en metadata.json (umbral de decisión por defecto, 0.5)

        Returns:
            bool: True si se inicializó correctamente, False en caso contrario
        """
        try:
            from pathlib import Path

            import joblib

            # Resolver ruta del modelo de forma absoluta desde este archivo
            _base = Path(__file__).resolve().parent.parent
            model_path = _base / "data" / "models" / "rf_correlator_v1.pkl"
            metadata_path = _base / "data" / "models" / "metadata.json"

            if model_path.exists():
                print(f"📥 Cargando modelo entrenado desde {model_path}...")
                model_package = joblib.load(model_path)

                self.ml_classifier = model_package["classifier"]
                self.tfidf_vectorizer = model_package["tfidf_vectorizer"]
                self.label_encoders = model_package.get("label_encoders", {})

                # Cargar métricas reales desde metadata.json — nunca hardcodear
                if metadata_path.exists():
                    with open(metadata_path, "r") as f:
                        stored = json.load(f)
                    test_m = stored.get("test", {})
                    train_info = stored.get("training_info", {})
                    self.model_metrics = {
                        "test_accuracy": test_m.get("accuracy", 0.0),
                        "test_precision": test_m.get("precision", 0.0),
                        "test_recall": test_m.get("recall", 0.0),
                        "test_f1": test_m.get("f1_score", 0.0),
                        "test_roc_auc": test_m.get("roc_auc", 0.0),
                        "training_samples": train_info.get("n_train_samples", 0),
                        "validation_samples": train_info.get("n_val_samples", 0),
                        "test_samples": train_info.get("n_test_samples", 0),
                        "n_features": model_package.get("feature_count", train_info.get("n_features", 517)),
                        "version": model_package.get("version", "1.0.0"),
                        "trained_at": model_package.get("trained_at", "unknown"),
                    }
                else:
                    # metadata.json no encontrado — valores conservadores
                    self.model_metrics = {
                        "test_accuracy": 0.0,
                        "test_precision": 0.0,
                        "test_recall": 0.0,
                        "test_f1": 0.0,
                        "test_roc_auc": 0.0,
                        "n_features": model_package.get("feature_count", 517),
                        "version": model_package.get("version", "1.0.0"),
                        "trained_at": model_package.get("trained_at", "unknown"),
                        "warning": "metadata.json no encontrado — re-entrena el modelo",
                    }

                print("✅ Modelo ML cargado exitosamente")
                print(f"   Versión:   {self.model_metrics['version']}")
                print(f"   Features:  {self.model_metrics['n_features']}")
                print(f"   Precision: {self.model_metrics['test_precision']:.2%}")
                print(f"   Recall:    {self.model_metrics['test_recall']:.2%}")
                print(f"   F1-Score:  {self.model_metrics['test_f1']:.2%}")
                print(f"   ROC-AUC:   {self.model_metrics['test_roc_auc']:.4f}")
                return True
            else:
                print(f"⚠️  Modelo no encontrado en {model_path}")
                print("💡 Para entrenar el modelo ejecuta: python backend/train_ml_model.py")
                print("🔄 Usando correlación determinística como fallback")

                # Inicializar con None para usar fallback determinístico
                self.ml_classifier = None
                self.tfidf_vectorizer = None
                self.label_encoders = {}
                return False

        except ImportError as e:
            print(f"⚠️  Dependencias no disponibles: {e}")
            print("💡 Instala con: pip install scikit-learn joblib")
            print("🔄 Usando correlación determinística como fallback")
            self.ml_classifier = None
            return False
        except Exception as e:
            print(f"❌ Error cargando modelo ML: {str(e)}")
            print("🔄 Usando correlación determinística como fallback")
            self.ml_classifier = None
            return False

    def _encode_categorical(self, column: str, value: str) -> int:
        """Codifica con el LabelEncoder del entrenamiento; -1 si no existe o el valor no se vio."""
        encoder = getattr(self, "label_encoders", {}).get(column)
        if encoder is None or value not in encoder.classes_:
            return -1
        return int(encoder.transform([value])[0])

    @staticmethod
    def _training_tool_label(tool: str) -> str:
        """Normaliza el nombre de herramienta al vocabulario del dataset ('http_scanner' → 'http-scanner')."""
        tool = (tool or "").lower().replace("_", "-")
        return {"zap": "owasp-zap"}.get(tool, tool)

    def _engineer_features_for_prediction(self, sast_vuln: Vulnerability, dast_vuln: Vulnerability) -> np.array:
        """
        Genera vector de features para predicción usando el modelo entrenado.
        Debe coincidir exactamente con el proceso de feature engineering del entrenamiento.

        Args:
            sast_vuln: Vulnerabilidad SAST
            dast_vuln: Vulnerabilidad DAST

        Returns:
            Feature vector numpy array
        """
        features_list = []

        # 1. Features textuales (TF-IDF)
        if self.tfidf_vectorizer is not None:
            combined_text = f"{sast_vuln.description} {dast_vuln.description}"
            tfidf_features = self.tfidf_vectorizer.transform([combined_text]).toarray()[0]
            features_list.append(tfidf_features)

        # 2. Features categóricas: mismos LabelEncoder que en el entrenamiento
        # (guardados en rf_correlator_v1.pkl). Valores no vistos → -1, igual que
        # hace train_ml_model.py al transformar validación/test.
        sast_tool = self._training_tool_label(sast_vuln.source_tool)
        dast_tool = self._training_tool_label(dast_vuln.source_tool)
        categorical_values = [
            self._encode_categorical("sast_type", _TRAINING_TYPE_LABELS.get(sast_vuln.type, "")),
            self._encode_categorical("dast_type", _TRAINING_TYPE_LABELS.get(dast_vuln.type, "")),
            self._encode_categorical("sast_severity", sast_vuln.severity.name),
            self._encode_categorical("dast_severity", dast_vuln.severity.name),
            self._encode_categorical("sast_cwe", sast_vuln.cwe_id),
            self._encode_categorical("dast_cwe", dast_vuln.cwe_id),
            self._encode_categorical("sast_tool", sast_tool),
            self._encode_categorical("dast_tool", dast_tool),
        ]
        features_list.append(np.array(categorical_values))

        # 3. Features numéricas
        numeric_features = []

        # Type match
        type_match = 1 if sast_vuln.type == dast_vuln.type else 0
        numeric_features.append(type_match)

        # CWE match
        cwe_match = 1 if sast_vuln.cwe_id == dast_vuln.cwe_id else 0
        numeric_features.append(cwe_match)

        # Severity match
        severity_match = 1 if sast_vuln.severity == dast_vuln.severity else 0
        numeric_features.append(severity_match)

        # Misma definición que en el entrenamiento: sast_tool == 'bandit' y dast_tool == 'zap'
        same_tool_vendor = int(sast_tool == "bandit" and dast_tool == "zap")
        numeric_features.append(same_tool_vendor)

        # Longitud de descripciones
        sast_desc_len = len(sast_vuln.description)
        dast_desc_len = len(dast_vuln.description)
        numeric_features.extend([sast_desc_len, dast_desc_len])

        # Línea de código
        sast_line = sast_vuln.line_number
        numeric_features.append(sast_line)

        # Profundidad de path/endpoint
        sast_file_depth = sast_vuln.file_path.replace("\\", "/").count("/") if sast_vuln.file_path else 0
        dast_endpoint_depth = dast_vuln.endpoint.count("/") if dast_vuln.endpoint else 0
        numeric_features.extend([sast_file_depth, dast_endpoint_depth])

        # Agregar features numéricas como array 1D
        features_list.append(np.array(numeric_features))

        # Concatenar todas las features
        try:
            feature_vector = np.concatenate(features_list)
            return feature_vector
        except Exception as e:
            print(f"⚠️ Error concatenando features: {e}")
            # Retornar vector de features simplificado
            return np.array(
                [
                    type_match,
                    cwe_match,
                    severity_match,
                    self._calculate_endpoint_similarity(sast_vuln.endpoint, dast_vuln.endpoint),
                ]
            )

    def _extract_ml_features(self, sast_vuln: Vulnerability, dast_vuln: Vulnerability) -> np.array:
        """
        Extrae características para el modelo ML basado en feature engineering validado.

        Features Categories:
        1. Textual: TF-IDF de descripciones combinadas
        2. Structural: Métricas de código y endpoints
        3. Semantic: Similitudes calculadas
        4. Categorical: Matches de tipo, CWE, OWASP

        Returns:
            np.array: Feature vector para el modelo ML
        """
        features = []

        # 1. Características Textuales (TF-IDF)
        combined_text = f"{sast_vuln.description} {dast_vuln.description}"
        if hasattr(self, "tfidf_vectorizer") and self.tfidf_vectorizer:
            text_features = self.tfidf_vectorizer.transform([combined_text]).toarray()[0]
            features.extend(text_features)

        # 2. Características Estructurales
        structural_features = [
            len(sast_vuln.file_path.split("/")),  # Profundidad archivo
            sast_vuln.line_number,  # Línea en código
            len(dast_vuln.endpoint.split("/")),  # Profundidad endpoint
            len(sast_vuln.description.split()),  # Longitud descripción SAST
            len(dast_vuln.description.split()),  # Longitud descripción DAST
        ]
        features.extend(structural_features)

        # 3. Características Semánticas
        semantic_features = [
            self._calculate_endpoint_similarity(sast_vuln.endpoint, dast_vuln.endpoint),
            self._jaccard_similarity(sast_vuln.description, dast_vuln.description),
            self._calculate_severity_similarity(sast_vuln.severity, dast_vuln.severity),
        ]
        features.extend(semantic_features)

        # 4. Características Categóricas (One-hot encoded)
        categorical_features = [
            1.0 if sast_vuln.type == dast_vuln.type else 0.0,
            1.0 if sast_vuln.cwe_id == dast_vuln.cwe_id else 0.0,
            1.0 if sast_vuln.owasp_category == dast_vuln.owasp_category else 0.0,
            1.0 if sast_vuln.severity == dast_vuln.severity else 0.0,
        ]
        features.extend(categorical_features)

        return np.array(features)

    def _description_similarity(self, text1: str, text2: str) -> float:
        """
        Similitud entre descripciones de vulnerabilidades.

        Usa sentence-transformers si está disponible (resuelve domain shift
        entre distintas herramientas SAST/DAST).  Cae a Jaccard si no.
        """
        if _SEMANTIC_AVAILABLE:
            try:
                return semantic_similarity(text1, text2)
            except Exception as exc:
                logger.warning(f"[Correlator] semantic_similarity falló ({exc}), usando Jaccard")

        # Fallback: Jaccard sobre tokens
        set1 = set(text1.lower().split())
        set2 = set(text2.lower().split())
        union = set1 | set2
        return len(set1 & set2) / len(union) if union else 0.0

    def _jaccard_similarity(self, text1: str, text2: str) -> float:
        """Mantiene compatibilidad con código existente."""
        return self._description_similarity(text1, text2)

    def add_sast_findings(self, findings: List[Vulnerability]):
        """Añade hallazgos de herramientas SAST"""
        self.sast_findings.extend(findings)

    def add_dast_findings(self, findings: List[Vulnerability]):
        """Añade hallazgos de herramientas DAST"""
        self.dast_findings.extend(findings)

    def correlate_vulnerabilities(self, threshold: float = 0.7) -> List[Tuple[Vulnerability, Vulnerability, float]]:
        """
        Correlaciona vulnerabilidades SAST y DAST.

        Args:
            threshold: Mínima confianza para incluir una correlación [0,1].
                       Default 0.7 cuando el modelo ML está disponible.
                       Reducir a ~0.45 cuando se usa fallback determinístico
                       y los endpoints son de diferente naturaleza (file paths vs HTTP URLs).

        Returns: Lista de tuplas (vuln_sast, vuln_dast, confidence_score)
        """
        correlations = []

        for sast_vuln in self.sast_findings:
            for dast_vuln in self.dast_findings:
                confidence = self._calculate_correlation_confidence(sast_vuln, dast_vuln)
                if confidence > threshold:
                    correlations.append((sast_vuln, dast_vuln, confidence))

        return sorted(correlations, key=lambda x: x[2], reverse=True)

    def _calculate_correlation_confidence(self, sast_vuln: Vulnerability, dast_vuln: Vulnerability) -> float:
        """
        Calcula la confianza de correlación como suma ponderada de factores.

        Los pesos son una decisión de diseño, no el resultado de una optimización
        empírica: se priorizan las señales más directas de que ambos hallazgos son
        el mismo problema (mismo lugar y mismo tipo) sobre las señales auxiliares.

        Factores (suman 1.0):
        - Similitud de endpoint (40%): señal más fuerte; mismo lugar de la API.
        - Tipo de vulnerabilidad (35%): mismo tipo, o 20% si son tipos relacionados.
        - Similitud semántica de descripciones (10%): embeddings (sentence-transformers)
          o Jaccard si no están disponibles.
        - Probabilidad del Random Forest (10%): ver data/models/metadata.json.
        - Similitud de severidad (5%): señal débil de apoyo.

        El umbral de 0.70 (con modelo ML) también es un criterio de diseño.

        Returns:
            float: Confidence score en [0, 1].
        """
        return self.confidence_breakdown(sast_vuln, dast_vuln)["confidence"]

    def confidence_breakdown(self, sast_vuln: Vulnerability, dast_vuln: Vulnerability) -> Dict:
        """
        Desglose de la confianza: valor de cada factor, su peso y su aporte.
        _calculate_correlation_confidence devuelve exactamente el total de este desglose.
        """
        endpoint = self._calculate_endpoint_similarity(sast_vuln.endpoint, dast_vuln.endpoint)

        if sast_vuln.type == dast_vuln.type:
            type_value = 1.0
        elif self._are_related_vulnerabilities(sast_vuln.type, dast_vuln.type):
            type_value = RELATED_TYPE_CREDIT / CONFIDENCE_WEIGHTS["type"]  # tipos relacionados: aporte 0.20
        else:
            type_value = 0.0

        semantic = self._description_similarity(sast_vuln.description, dast_vuln.description)

        ml_source = "random_forest"
        ml_value = None
        if getattr(self, "ml_classifier", None) is not None:
            try:
                feature_vector = self._engineer_features_for_prediction(sast_vuln, dast_vuln)
                expected = self.model_metrics.get("n_features", 517)
                if len(feature_vector) != expected:
                    raise ValueError(f"Feature dimension mismatch: {len(feature_vector)} vs {expected}")
                ml_value = float(self.ml_classifier.predict_proba(feature_vector.reshape(1, -1))[0][1])
            except Exception as e:
                logger.warning(f"Error en predicción ML, usando fallback: {e}")
        if ml_value is None:
            ml_source = "context_fallback"
            ml_value = float(self._analyze_context_patterns(sast_vuln, dast_vuln))

        severity = self._calculate_severity_similarity(sast_vuln.severity, dast_vuln.severity)

        values = {
            "endpoint": float(endpoint),
            "type": float(type_value),
            "semantic": float(semantic),
            "ml": ml_value,
            "severity": float(severity),
        }
        factors = {
            name: {
                "weight": CONFIDENCE_WEIGHTS[name],
                "value": round(values[name], 4),
                "contribution": round(CONFIDENCE_WEIGHTS[name] * values[name], 4),
            }
            for name in CONFIDENCE_WEIGHTS
        }
        factors["ml"]["source"] = ml_source
        factors["semantic"]["method"] = "embeddings" if _SEMANTIC_AVAILABLE else "jaccard"
        total = min(sum(CONFIDENCE_WEIGHTS[n] * values[n] for n in CONFIDENCE_WEIGHTS), 1.0)
        return {"confidence": total, "factors": factors}

    def _are_related_vulnerabilities(self, type1: VulnerabilityType, type2: VulnerabilityType) -> bool:
        """Determina si dos tipos de vulnerabilidades están relacionados"""
        related_pairs = [
            (VulnerabilityType.BROKEN_AUTH, VulnerabilityType.BROKEN_ACCESS),
            (VulnerabilityType.SQL_INJECTION, VulnerabilityType.SENSITIVE_DATA),
            (VulnerabilityType.XSS, VulnerabilityType.SECURITY_MISCONFIG),
        ]

        return (type1, type2) in related_pairs or (type2, type1) in related_pairs

    @staticmethod
    def _normalize_endpoint(raw: str) -> str:
        """
        Normalizes an endpoint for comparison.

        Handles both SAST inputs (file paths like 'backend/api/users.py') and
        DAST inputs (full URLs like 'http://localhost:8000/api/users').
        Both are reduced to a comparable path-like token list.
        """
        if not raw:
            return ""
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        # If it has a scheme it's a URL — use only the path
        if parsed.scheme in ("http", "https"):
            path = parsed.path
        else:
            path = raw
        # Separador único '/' (las rutas de Windows llegan con '\')
        path = path.replace("\\", "/").strip("/")
        if not path:
            return ""
        # Strip extension (e.g. .py) so 'users.py' == 'users'.
        # PurePosixPath: str() conserva '/' también en Windows.
        from pathlib import PurePosixPath

        try:
            path = str(PurePosixPath(path).with_suffix(""))
        except ValueError:
            pass  # path like "." or root — keep as-is
        return path.strip("/").lower()

    def _calculate_endpoint_similarity(self, endpoint1: str, endpoint2: str) -> float:
        """
        Calculates similarity between two endpoints.

        Escala (de más a menos evidencia):
          1.0          rutas idénticas tras normalizar
          0.70–0.85    una ruta es sufijo completo de la otra, por segmentos
          0.70         solo coincide el último segmento
          Levenshtein  resto de casos

        Both SAST file paths and DAST URLs are first normalized to their
        path-only, extension-stripped form before comparison, so that
        'backend/api/users.py'  vs  'http://localhost:8000/api/users'
        compares 'backend/api/users' vs 'api/users' instead of comparing
        the raw strings which share almost no characters.
        """
        ep1 = self._normalize_endpoint(endpoint1)
        ep2 = self._normalize_endpoint(endpoint2)

        if not ep1 or not ep2:
            return 0.0

        # Exact match after normalization
        if ep1 == ep2:
            return 1.0

        segs1 = ep1.split("/")
        segs2 = ep2.split("/")

        # Partial match por segmentos: una ruta es sufijo completo de la otra
        # (caso típico: 'api/users' es sufijo de 'backend/api/users').
        # Es más evidencia que coincidir solo el último segmento, así que
        # puntúa en [0.70, 0.85]: nunca por debajo del caso de último segmento.
        shorter, longer = sorted((segs1, segs2), key=len)
        offset = len(longer) - len(shorter)
        if longer[offset:] == shorter:
            return 0.70 + 0.15 * (len(shorter) / len(longer))

        # Last-segment match (e.g. both end with 'users')
        if segs1[-1] and segs1[-1] == segs2[-1]:
            return 0.70

        # Levenshtein on the normalized paths
        distance = self._levenshtein_distance(ep1, ep2)
        max_len = max(len(ep1), len(ep2))
        return 1.0 - (distance / max_len) if max_len > 0 else 0.0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Implementación de distancia de Levenshtein"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _calculate_severity_similarity(self, sev1: ConfidenceLevel, sev2: ConfidenceLevel) -> float:
        """Calcula similitud entre niveles de severidad"""
        diff = abs(sev1.value - sev2.value)
        # Obtener valores máximo y mínimo de ConfidenceLevel
        all_severity_values = [level.value for level in ConfidenceLevel]
        max_diff = max(all_severity_values) - min(all_severity_values)
        return 1.0 - (diff / max_diff) if max_diff > 0 else 1.0

    def _analyze_context_patterns(self, sast_vuln: Vulnerability, dast_vuln: Vulnerability) -> float:
        """Analiza patrones contextuales específicos"""
        score = 0.0

        # Buscar patrones en descripciones
        sast_desc = sast_vuln.description.lower()
        dast_desc = dast_vuln.description.lower()

        # Palabras clave comunes
        common_keywords = len(set(sast_desc.split()) & set(dast_desc.split()))
        if common_keywords > 2:
            score += 0.3

        # CWE IDs coincidentes
        if sast_vuln.cwe_id == dast_vuln.cwe_id and sast_vuln.cwe_id:
            score += 0.4

        # Categoría OWASP coincidente
        if sast_vuln.owasp_category == dast_vuln.owasp_category:
            score += 0.3

        return min(score, 1.0)

    def generate_correlation_report(self, threshold: float = 0.7) -> Dict:
        """Genera reporte detallado de correlaciones.

        Args:
            threshold: Mínima confianza para incluir una correlación.
                       Se pasa directamente a correlate_vulnerabilities().
        """
        correlations = self.correlate_vulnerabilities(threshold=threshold)

        # Calcular distribución de severidad combinada (SAST + DAST)
        all_vulns = self.sast_findings + self.dast_findings
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vuln in all_vulns:
            # ConfidenceLevel guarda enteros (1-4) en .value; el nombre es el que dice la severidad
            sev = str(vuln.severity.name if hasattr(vuln.severity, "name") else vuln.severity).lower()
            if "critical" in sev:
                severity_counts["critical"] += 1
            elif "high" in sev:
                severity_counts["high"] += 1
            elif "medium" in sev:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1

        report = {
            "summary": {
                "total_sast_findings": len(self.sast_findings),
                "total_dast_findings": len(self.dast_findings),
                "high_confidence_correlations": len([c for c in correlations if c[2] > 0.8]),
                "medium_confidence_correlations": len([c for c in correlations if 0.6 <= c[2] <= 0.8]),
                "low_confidence_correlations": len([c for c in correlations if c[2] < 0.6]),
                "sast_uncorroborated_pct": self._sast_uncorroborated_percentage(correlations),
                # Agregar distribución de severidad
                "critical_issues": severity_counts["critical"],
                "high_severity_findings": severity_counts["high"],
                "medium_severity_findings": severity_counts["medium"],
                "low_severity_findings": severity_counts["low"],
            },
            "correlations": [
                {
                    "sast_vulnerability": {
                        "id": corr[0].id,
                        "type": corr[0].type.value,
                        "file": corr[0].file_path,
                        "line": corr[0].line_number,
                        "severity": (
                            corr[0].severity.name if hasattr(corr[0].severity, "name") else str(corr[0].severity)
                        ),
                        "tool": corr[0].source_tool,
                    },
                    "dast_vulnerability": {
                        "id": corr[1].id,
                        "type": corr[1].type.value,
                        "endpoint": corr[1].endpoint,
                        "severity": (
                            corr[1].severity.name if hasattr(corr[1].severity, "name") else str(corr[1].severity)
                        ),
                        "tool": corr[1].source_tool,
                    },
                    "confidence_score": corr[2],
                    "correlation_factors": self._get_correlation_factors(corr[0], corr[1]),
                }
                for corr in correlations[:50]  # Top 50 correlaciones
            ],
        }

        return report

    def _sast_uncorroborated_percentage(self, correlations: List) -> float:
        """
        Porcentaje de hallazgos SAST que ninguna evidencia DAST corrobora:

            (SAST sin correlación / SAST total) * 100

        Es un indicador descriptivo, no una reducción de falsos positivos: sin
        ground truth no se sabe si un hallazgo no corroborado es falso. Con cero
        correlaciones vale 100 %, así que un valor alto no indica mejora.
        """
        if not self.sast_findings:
            return 0.0

        corroborated_sast_ids = {c[0].id for c in correlations}
        uncorroborated = len(self.sast_findings) - len(corroborated_sast_ids)
        return round(uncorroborated / len(self.sast_findings) * 100, 2)

    def _get_correlation_factors(self, sast_vuln: Vulnerability, dast_vuln: Vulnerability) -> Dict:
        """Obtiene factores que contribuyen a la correlación, con el desglose ponderado de la confianza."""
        return {
            "type_match": sast_vuln.type == dast_vuln.type,
            "endpoint_similarity": self._calculate_endpoint_similarity(sast_vuln.endpoint, dast_vuln.endpoint),
            "severity_similarity": self._calculate_severity_similarity(sast_vuln.severity, dast_vuln.severity),
            "cwe_match": sast_vuln.cwe_id == dast_vuln.cwe_id,
            "owasp_category_match": sast_vuln.owasp_category == dast_vuln.owasp_category,
            "confidence_breakdown": self.confidence_breakdown(sast_vuln, dast_vuln)["factors"],
        }


# Ejemplo de uso
if __name__ == "__main__":
    correlator = VulnerabilityCorrelator()

    # Simular hallazgos SAST
    sast_findings = [
        Vulnerability(
            id="SAST_001",
            type=VulnerabilityType.SQL_INJECTION,
            severity=ConfidenceLevel.HIGH,
            file_path="/api/users.py",
            line_number=45,
            endpoint="/api/users",
            description="Potential SQL injection in user query",
            cwe_id="CWE-89",
            owasp_category="API3-2023",
            source_tool="bandit",
        )
    ]

    # Simular hallazgos DAST
    dast_findings = [
        Vulnerability(
            id="DAST_001",
            type=VulnerabilityType.SQL_INJECTION,
            severity=ConfidenceLevel.HIGH,
            file_path="",
            line_number=0,
            endpoint="/api/users",
            description="SQL error response detected",
            cwe_id="CWE-89",
            owasp_category="API3-2023",
            source_tool="zap",
        )
    ]

    correlator.add_sast_findings(sast_findings)
    correlator.add_dast_findings(dast_findings)

    # Generar reporte
    report = correlator.generate_correlation_report()
    print(json.dumps(report, indent=2))
