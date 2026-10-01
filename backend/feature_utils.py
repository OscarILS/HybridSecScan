"""
Utilidades de features compartidas entre el entrenamiento (train_ml_model.py) y la
inferencia (correlation_engine.py). Ambos deben calcular las features EXACTAMENTE
igual, así que la lógica vive en un solo sitio.

`module_match` compara el módulo/componente del archivo SAST con el del endpoint DAST:
es la señal que distingue un positivo limpio (misma vulnerabilidad en el mismo
componente, confirmada por ambas técnicas) de un negativo difícil (misma vulnerabilidad
pero en componentes distintos y sin relación).
"""

from pathlib import PurePosixPath


def module_of_file(path: str) -> str:
    """Módulo a partir de una ruta de archivo: nombre base sin extensión, en minúsculas.

    'api/controllers/payments.py' -> 'payments'
    'ProgramasPruebas/vulnerable_app.py' -> 'vulnerable_app'
    """
    if not path:
        return ""
    name = PurePosixPath(str(path).replace("\\", "/")).name
    if not name:
        return ""
    return name.rsplit(".", 1)[0].lower()


def module_of_endpoint(endpoint: str) -> str:
    """Módulo a partir de un endpoint: último segmento de la ruta, en minúsculas.

    '/api/v1/payments' -> 'payments'
    '/login' -> 'login'
    """
    if not endpoint:
        return ""
    segments = [s for s in str(endpoint).replace("\\", "/").split("/") if s]
    return segments[-1].lower() if segments else ""


def module_match(file_path: str, endpoint: str) -> int:
    """1 si el archivo SAST y el endpoint DAST se refieren al mismo módulo; 0 si no."""
    a = module_of_file(file_path)
    b = module_of_endpoint(endpoint)
    return int(bool(a) and a == b)
