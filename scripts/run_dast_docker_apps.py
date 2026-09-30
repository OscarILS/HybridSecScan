"""
Lanza DVWA y NodeGoat en Docker, ejecuta DAST activo contra cada uno,
y guarda los resultados en data/experiments/results/ para la evaluación a escala.

Uso:
    py -3.11 scripts/run_dast_docker_apps.py

Prerequisito: Docker Desktop corriendo.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "data" / "experiments" / "results"
OUT.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO))
from backend.dast_scanner import run_active_probe_scan  # noqa: E402 — requiere sys.path

APPS = [
    {
        "name": "DVWA",
        "image": "vulnerables/web-dvwa",
        "host_port": 8080,
        "container_port": 80,
        "url": "http://localhost:8080",
        "wait_path": "/",
        "out_prefix": "dast_active_dvwa",
        "stop_after": True,
    },
    {
        "name": "NodeGoat",
        "image": "1njected/nodegoat",
        "host_port": 4000,
        "container_port": 4000,
        "url": "http://localhost:4000",
        "wait_path": "/login",
        "out_prefix": "dast_active_nodegoat",
        "stop_after": True,
    },
]


def docker_run(image: str, host_port: int, container_port: int) -> str:
    """Lanza el contenedor y devuelve su ID. Hace pull primero si la imagen no existe localmente."""
    # Pull explícito con timeout largo (imágenes grandes pueden tardar)
    pull = subprocess.run(
        ["docker", "pull", image],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if pull.returncode != 0:
        raise RuntimeError(f"docker pull falló: {pull.stderr.strip()[:300]}")

    result = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", f"{host_port}:{container_port}", image],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker run falló: {result.stderr.strip()}")
    return result.stdout.strip()


def wait_ready(url: str, timeout: int = 60) -> bool:
    """Espera hasta que el servicio responde HTTP."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def docker_stop(container_id: str):
    subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=30)


def scan_app(cfg: dict) -> dict:
    print(f"\n{'='*60}")
    print(f"  {cfg['name']} — {cfg['url']}")
    print(f"{'='*60}")

    # Lanzar contenedor
    print(f"  Descargando/lanzando {cfg['image']} (puede tardar varios minutos la primera vez)...")
    try:
        cid = docker_run(cfg["image"], cfg["host_port"], cfg["container_port"])
        print(f"  Contenedor ID: {cid[:12]}")
    except RuntimeError as e:
        # Puede que ya esté corriendo
        print(f"  Advertencia: {e}")
        cid = None

    # Esperar que responda
    print(f"  Esperando que {cfg['name']} responda (hasta 90s)...")
    ready = wait_ready(cfg["url"] + cfg["wait_path"], timeout=90)
    if not ready:
        print(f"  ⚠ {cfg['name']} no respondió en 90s — saltando")
        if cid:
            docker_stop(cid)
        return {}

    print(f"  ✓ {cfg['name']} listo")

    # Ejecutar DAST activo
    print(f"  Ejecutando DAST activo contra {cfg['url']}...")
    try:
        result = run_active_probe_scan(cfg["url"])
    except Exception as e:
        print(f"  Error en DAST: {e}")
        result = {"vulnerabilities": [], "summary": {}}

    vulns = result.get("vulnerabilities", [])
    summary = result.get("summary", {})
    print(
        f"  Hallazgos: {len(vulns)} (passive={summary.get('passive_checks',0)}, "
        f"active={summary.get('active_probes',0)}, idor={summary.get('idor_checks',0)}, "
        f"auth={summary.get('auth_checks',0)})"
    )

    for v in vulns:
        sev = v.get("severity", "?")
        t = v.get("type", "?")[:40]
        url = v.get("url", "?")[-30:]
        print(f"    [{sev:8}] {t:40} {url}")

    # Guardar resultado
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = OUT / f"{cfg['out_prefix']}_{ts}.json"
    out_data = {
        "scan_type": "DAST",
        "tool": "HTTP Security Scanner (Active Probe)",
        "target_url": cfg["url"],
        "app": cfg["name"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    out_file.write_text(json.dumps(out_data, indent=2))
    print(f"  Guardado: {out_file.name}")

    # Detener contenedor
    if cid and cfg.get("stop_after"):
        print(f"  Deteniendo {cfg['name']}...")
        docker_stop(cid)

    return out_data


def main():
    print("\nHybridSecScan — DAST Docker Apps")
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Verificar Docker
    check = subprocess.run(["docker", "ps"], capture_output=True, text=True)
    if check.returncode != 0:
        print("ERROR: Docker no está corriendo. Abre Docker Desktop primero.")
        sys.exit(1)
    print("Docker OK\n")

    results = {}
    for cfg in APPS:
        try:
            results[cfg["name"]] = scan_app(cfg)
        except Exception as e:
            print(f"ERROR con {cfg['name']}: {e}")
            results[cfg["name"]] = {}

    print("\n" + "=" * 60)
    print("  RESUMEN")
    print("=" * 60)
    for name, r in results.items():
        n = len(r.get("vulnerabilities", []))
        print(f"  {name}: {n} hallazgos")

    print("\nAhora ejecuta:")
    print("  py -3.11 scripts/run_scale_evaluation.py --save")
    print("para ver los resultados actualizados con DAST.\n")


if __name__ == "__main__":
    main()
