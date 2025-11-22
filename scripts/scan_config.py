"""
Configuración de Directorios Relevantes para Análisis SAST
===========================================================

Define qué directorios analizar en cada aplicación vulnerable
para optimizar el tiempo de escaneo.
"""

# Directorios a incluir/excluir por aplicación
APP_SCAN_CONFIG = {
    "owasp_webgoat": {
        "include": [
            "src/main/java/org/owasp/webgoat",
            "src/main/resources"
        ],
        "exclude": [
            "**/*Test.java",
            "**/test/**",
            "**/tests/**",
            "**/.git/**",
            "**/node_modules/**",
            "**/target/**",
            "**/build/**",
            "**/.m2/**"
        ],
        "max_depth": 10
    },
    "dvwa": {
        "include": [
            "vulnerabilities/**/*.php",
            "includes/**/*.php",
            "*.php"
        ],
        "exclude": [
            "**/tests/**",
            "**/vendor/**",
            "**/.git/**",
            "**/node_modules/**"
        ],
        "max_depth": 8
    },
    "nodegoat": {
        "include": [
            "app/**/*.js",
            "config/**/*.js",
            "routes/**/*.js",
            "*.js"
        ],
        "exclude": [
            "**/node_modules/**",
            "**/test/**",
            "**/tests/**",
            "**/.git/**",
            "**/public/**",
            "**/assets/**"
        ],
        "max_depth": 8
    },
    "juice-shop": {
        "include": [
            "routes/**/*.ts",
            "routes/**/*.js",
            "lib/**/*.ts",
            "models/**/*.ts",
            "data/**/*.js"
        ],
        "exclude": [
            "**/node_modules/**",
            "**/test/**",
            "**/tests/**",
            "**/.git/**",
            "**/frontend/**",
            "**/dist/**",
            "**/build/**"
        ],
        "max_depth": 8
    }
}

def get_scan_paths(app_name: str, base_path: str):
    """Retorna las rutas específicas a escanear para una aplicación"""
    from pathlib import Path
    
    config = APP_SCAN_CONFIG.get(app_name.lower().replace(" ", "_"), {})
    include_patterns = config.get("include", ["**/*"])
    
    base = Path(base_path)
    scan_paths = []
    
    for pattern in include_patterns:
        matches = list(base.glob(pattern))
        scan_paths.extend([str(p) for p in matches if p.is_dir() or p.is_file()])
    
    # Si no encontró nada, escanear todo
    if not scan_paths:
        scan_paths = [str(base)]
    
    return scan_paths

def get_exclude_patterns(app_name: str):
    """Retorna los patrones de exclusión para una aplicación"""
    config = APP_SCAN_CONFIG.get(app_name.lower().replace(" ", "_"), {})
    return config.get("exclude", [])
