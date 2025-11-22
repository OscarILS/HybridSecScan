"""
Gestor de modelos de Machine Learning para persistencia y versionado.
Permite guardar, cargar y gestionar modelos entrenados del sistema de correlación.
"""

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
import pickle
import json
import os
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer


class MLModelManager:
    """
    Gestor centralizado de modelos ML.
    Maneja persistencia, versionado y metadatos de modelos.
    """
    
    def __init__(self, models_dir: str = "./models"):
        """
        Inicializa el gestor de modelos.
        
        Args:
            models_dir: Directorio base para almacenar modelos
        """
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self._current_version = self._load_current_version()
    
    def _load_current_version(self) -> int:
        """Carga el número de versión actual desde metadata."""
        metadata_file = self.models_dir / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
                return metadata.get("current_version", 0)
        return 0
    
    def _save_metadata(self, version: int, info: Dict[str, Any]) -> None:
        """
        Guarda metadata del modelo.
        
        Args:
            version: Número de versión
            info: Información adicional (métricas, fecha, etc.)
        """
        metadata_file = self.models_dir / "metadata.json"
        
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {"versions": {}, "current_version": 0}
        
        metadata["versions"][str(version)] = {
            **info,
            "saved_at": datetime.now(timezone.utc).isoformat()
        }
        metadata["current_version"] = version
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def save_model(
        self,
        classifier: RandomForestClassifier,
        vectorizer: TfidfVectorizer,
        metrics: Optional[Dict[str, float]] = None,
        description: str = ""
    ) -> int:
        """
        Guarda un modelo entrenado con su vectorizador.
        
        Args:
            classifier: Modelo Random Forest entrenado
            vectorizer: Vectorizador TF-IDF entrenado
            metrics: Métricas de evaluación del modelo
            description: Descripción del modelo
            
        Returns:
            Número de versión asignado
        """
        version = self._current_version + 1
        version_dir = self.models_dir / f"v{version}"
        version_dir.mkdir(parents=True, exist_ok=True)
        
        # Guardar classifier
        classifier_path = version_dir / "classifier.pkl"
        with open(classifier_path, 'wb') as f:
            pickle.dump(classifier, f)
        
        # Guardar vectorizer
        vectorizer_path = version_dir / "vectorizer.pkl"
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f)
        
        # Guardar metadata
        model_info = {
            "version": version,
            "description": description,
            "classifier_type": type(classifier).__name__,
            "vectorizer_type": type(vectorizer).__name__,
            "n_features": vectorizer.max_features if hasattr(vectorizer, 'max_features') else None,
            "metrics": metrics or {}
        }
        
        with open(version_dir / "info.json", 'w') as f:
            json.dump(model_info, f, indent=2)
        
        self._save_metadata(version, model_info)
        self._current_version = version
        
        return version
    
    def load_model(
        self,
        version: Optional[int] = None
    ) -> Tuple[RandomForestClassifier, TfidfVectorizer, Dict[str, Any]]:
        """
        Carga un modelo guardado.
        
        Args:
            version: Versión específica a cargar (None = última versión)
            
        Returns:
            Tupla con (classifier, vectorizer, info)
            
        Raises:
            FileNotFoundError: Si la versión no existe
        """
        if version is None:
            version = self._current_version
        
        if version == 0:
            raise FileNotFoundError("No hay modelos guardados")
        
        version_dir = self.models_dir / f"v{version}"
        if not version_dir.exists():
            raise FileNotFoundError(f"Versión {version} no encontrada")
        
        # Cargar classifier
        with open(version_dir / "classifier.pkl", 'rb') as f:
            classifier = pickle.load(f)
        
        # Cargar vectorizer
        with open(version_dir / "vectorizer.pkl", 'rb') as f:
            vectorizer = pickle.load(f)
        
        # Cargar info
        with open(version_dir / "info.json", 'r') as f:
            info = json.load(f)
        
        return classifier, vectorizer, info
    
    def list_versions(self) -> Dict[str, Any]:
        """
        Lista todas las versiones disponibles con su metadata.
        
        Returns:
            Diccionario con información de versiones
        """
        metadata_file = self.models_dir / "metadata.json"
        if not metadata_file.exists():
            return {"current_version": 0, "versions": {}}
        
        with open(metadata_file, 'r') as f:
            return json.load(f)
    
    def delete_version(self, version: int) -> bool:
        """
        Elimina una versión específica del modelo.
        
        Args:
            version: Número de versión a eliminar
            
        Returns:
            True si se eliminó, False si no existía
        """
        version_dir = self.models_dir / f"v{version}"
        if not version_dir.exists():
            return False
        
        # Eliminar directorio
        import shutil
        shutil.rmtree(version_dir)
        
        # Actualizar metadata
        metadata_file = self.models_dir / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            if str(version) in metadata["versions"]:
                del metadata["versions"][str(version)]
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        return True
    
    def get_current_version(self) -> int:
        """Obtiene el número de versión actual."""
        return self._current_version
    
    def set_current_version(self, version: int) -> bool:
        """
        Establece una versión como actual.
        
        Args:
            version: Número de versión
            
        Returns:
            True si se estableció, False si no existe
        """
        version_dir = self.models_dir / f"v{version}"
        if not version_dir.exists():
            return False
        
        metadata_file = self.models_dir / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            metadata["current_version"] = version
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        self._current_version = version
        return True


# Instancia global del gestor
ml_model_manager = MLModelManager()
