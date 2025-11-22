"""
Sistema de caché en memoria para resultados de escaneos.
Reduce carga en base de datos y mejora rendimiento de consultas frecuentes.
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import json
import hashlib


class CacheManager:
    """
    Gestor de caché en memoria con TTL (Time To Live).
    Almacena resultados de escaneos para acceso rápido.
    """
    
    def __init__(self, default_ttl_seconds: int = 3600):
        """
        Inicializa el gestor de caché.
        
        Args:
            default_ttl_seconds: Tiempo de vida predeterminado para entradas (1 hora por defecto)
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._default_ttl = default_ttl_seconds
        self._hits = 0
        self._misses = 0
    
    def _generate_key(self, prefix: str, identifier: str) -> str:
        """
        Genera una clave única para el caché.
        
        Args:
            prefix: Prefijo de la clave (ej: "scan", "result")
            identifier: Identificador único (ej: scan_id, hash de parámetros)
            
        Returns:
            Clave hash SHA256
        """
        key_string = f"{prefix}:{identifier}"
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def get(self, prefix: str, identifier: str) -> Optional[Any]:
        """
        Obtiene un valor del caché.
        
        Args:
            prefix: Prefijo de la clave
            identifier: Identificador único
            
        Returns:
            Valor almacenado o None si no existe o expiró
        """
        key = self._generate_key(prefix, identifier)
        
        if key not in self._cache:
            self._misses += 1
            return None
        
        entry = self._cache[key]
        
        # Verificar expiración
        if datetime.now(timezone.utc) > entry["expires_at"]:
            del self._cache[key]
            self._misses += 1
            return None
        
        self._hits += 1
        return entry["value"]
    
    def set(self, prefix: str, identifier: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """
        Almacena un valor en el caché.
        
        Args:
            prefix: Prefijo de la clave
            identifier: Identificador único
            value: Valor a almacenar (debe ser serializable a JSON)
            ttl_seconds: Tiempo de vida personalizado (usa default si es None)
        """
        key = self._generate_key(prefix, identifier)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        
        self._cache[key] = {
            "value": value,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=ttl)
        }
    
    def delete(self, prefix: str, identifier: str) -> bool:
        """
        Elimina una entrada del caché.
        
        Args:
            prefix: Prefijo de la clave
            identifier: Identificador único
            
        Returns:
            True si se eliminó, False si no existía
        """
        key = self._generate_key(prefix, identifier)
        
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    def clear(self) -> int:
        """
        Limpia todas las entradas del caché.
        
        Returns:
            Número de entradas eliminadas
        """
        count = len(self._cache)
        self._cache.clear()
        return count
    
    def clear_expired(self) -> int:
        """
        Elimina todas las entradas expiradas.
        
        Returns:
            Número de entradas eliminadas
        """
        now = datetime.now(timezone.utc)
        expired_keys = [
            key for key, entry in self._cache.items()
            if now > entry["expires_at"]
        ]
        
        for key in expired_keys:
            del self._cache[key]
        
        return len(expired_keys)
    
    def exists(self, prefix: str, identifier: str) -> bool:
        """
        Verifica si una clave existe y no ha expirado.
        
        Args:
            prefix: Prefijo de la clave
            identifier: Identificador único
            
        Returns:
            True si existe y es válida, False en caso contrario
        """
        return self.get(prefix, identifier) is not None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del caché.
        
        Returns:
            Diccionario con estadísticas (hits, misses, size, hit_rate)
        """
        total_requests = self._hits + self._misses
        hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total_requests": total_requests,
            "hit_rate_percent": round(hit_rate, 2),
            "cache_size": len(self._cache),
            "default_ttl_seconds": self._default_ttl
        }
    
    def reset_stats(self) -> None:
        """Reinicia las estadísticas de hits/misses."""
        self._hits = 0
        self._misses = 0


# Instancia global del caché
cache_manager = CacheManager(default_ttl_seconds=3600)
