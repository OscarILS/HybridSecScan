1# Guion de Demo — Examen de Titulación HybridSecScan

**Tiempo estimado:** 15-20 minutos  
**Audiencia:** Jurado académico UNMSM

---

## Preparación (10 min antes del examen)

Abre **3 terminales** y déjalas listas:

**Terminal A — Backend:**
```powershell
cd C:\Users\OSCAR\Documents\GitHub\HybridSecScan
cd backend
py -3.11 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal B — Frontend:**
```powershell
cd C:\Users\OSCAR\Documents\GitHub\HybridSecScan\frontend
npm run dev
```

**Terminal C — Lista para experimentos** (no ejecutar nada aún)

**Abre también:**
- Navegador en `http://localhost:5173` (frontend)
- Navegador en `http://localhost:8000/docs` (API interactiva)

---

## Paso 1 — Mostrar la arquitectura (2 min)

Di: *"El sistema tiene tres capas: un frontend React para el usuario, un backend FastAPI con 5 routers especializados, y un motor de correlación Machine Learning. Voy a demostrar el flujo completo."*

Muestra brevemente:
- `backend/main.py` — thin factory, 75 líneas
- `backend/routers/` — 5 routers separados
- `backend/correlation_engine.py` — el aporte central

---

## Paso 2 — SAST: subir y escanear código (3 min)

**En el frontend** (`http://localhost:5173`):

1. Ve a la sección de análisis SAST
2. Sube el archivo `ProgramasPruebas/vulnerable_app.py`
3. Selecciona herramienta: **Bandit**
4. Haz clic en "Analizar"

**Resultado esperado:**
```
12 vulnerabilidades encontradas
- B608 (SQL Injection) línea 25
- B605 (Command Injection) línea 34
- B201 (Flask Debug) línea 80
...
```

Di: *"Bandit encontró 12 vulnerabilidades en el código estático. Pero esto son hallazgos potenciales — algunos pueden ser falsos positivos. Necesitamos confirmarlos dinámicamente."*

---

## Paso 3 — DAST: probing activo (3 min)

**En Terminal C:**
```powershell
cd C:\Users\OSCAR\Documents\GitHub\HybridSecScan
py -3.11 ProgramasPruebas\vulnerable_app.py
```
*(Deja la app corriendo en puerto 5000)*

Di: *"Lanzo la aplicación vulnerable localmente. Noten que tiene debug=True — lo detectaremos."*

**En la Terminal C (nueva):**
```powershell
cd C:\Users\OSCAR\Documents\GitHub\HybridSecScan
py -3.11 -c "
from backend.dast_scanner import run_active_probe_scan
import json
result = run_active_probe_scan('http://localhost:5000')
for v in result['vulnerabilities']:
    print(f\"  [{v['severity']:8}] {v['type'][:40]} @ {v.get('url','?')[-20:]}\")
print(f\"TOTAL: {result['summary']['total_issues']}\")
"
```

**Resultado esperado:**
```
  [HIGH    ] SQL Injection                @ localhost:5000/login
  [HIGH    ] Path Traversal              @ localhost:5000/read_file
  [HIGH    ] Error Disclosure - Debug    @ localhost:5000/deserialize
  [HIGH    ] Missing Security Header     @ localhost:5000/
  ...
TOTAL: 12
```

Di: *"El DAST activo enviuó payloads reales y confirmó vulnerabilidades. Ahora la pieza clave: la correlación."*

---

## Paso 4 — Correlación ML (5 min — el momento central)

**En Terminal C:**
```powershell
cd C:\Users\OSCAR\Documents\GitHub\HybridSecScan
py -3.11 scripts\run_vulnerable_app_experiment.py
```

Mientras corre, explica:

*"El motor de correlación toma los 12 hallazgos SAST y los 12 DAST, forma los 144 pares posibles, y para cada par calcula una confianza basada en: similitud de endpoint (40%), coincidencia de tipo de vulnerabilidad (35%), predicción del modelo Random Forest (15%), y similitud de severidad (10%)."*

**Resultado esperado (al terminar):**
```
CORRELACIONES CONFIRMADAS:
  [0.894] sql_injection @ /login  <->  sql_injection @ /login
    SAST: Bandit B608, línea 25, CWE-89
    DAST: POST /login con payload SQL → respuesta contiene "SELECT WHERE"

RESUMEN:
  SAST: 12 | DAST: 12 | TOTAL: 24 | CORRELACIONES: 1 (conf. 0.894)
```

Di: *"La confianza de 0.894 supera nuestro threshold de 0.70. El hallazgo B608 de Bandit —que podría ser un falso positivo porque Bandit solo ve el código sin ejecutarlo— queda CONFIRMADO por el DAST. Esto es exactamente lo que propone la tesis: usar la evidencia dinámica para validar los hallazgos estáticos."*

---

## Paso 5 — Métricas del modelo ML (2 min)

**Abre `http://localhost:8000/api/model-metrics`** en el navegador.

**Resultado:**
```json
{
  "model_available": true,
  "metrics": {
    "accuracy": 0.769,
    "precision": 0.663,
    "recall": 0.965,
    "f1_score": 0.786,
    "roc_auc": 0.785
  }
}
```

Di: *"El modelo fue entrenado con 1,300 pares de correlaciones etiquetados. El recall de 96.5% es intencional: en seguridad, perder una vulnerabilidad real (falso negativo) es más costoso que una falsa alarma. El modelo prioriza no perderse nada."*

---

## Paso 6 — Reporte PDF (1 min)

**En el frontend**, muestra el botón de descarga del reporte PDF del escaneo híbrido.

Di: *"El sistema genera reportes PDF profesionales con la lista completa de hallazgos, las correlaciones, y las métricas del análisis."*

---

## Preguntas frecuentes del jurado — respuestas preparadas

**¿Por qué 0 correlaciones con Juice Shop?**
> "Juice Shop en TypeScript fue analizado con Semgrep que detecta patrones de código, y nuestro HTTP Scanner que detecta misconfiguraciones HTTP. Son capas distintas que no producen el mismo tipo de hallazgo. En el experimento 2 con la app Python, donde tanto el SAST como el DAST pueden detectar SQL injection, la correlación funciona con confianza 0.894."

**¿Por qué el F1 es 78% y no más alto?**
> "El F1 de 78.6% resulta de una decisión deliberada: priorizamos recall (96.5%) sobre precision (66.3%). En seguridad informática, es preferible generar una alerta innecesaria a pasar por alto una vulnerabilidad real. Esta es la práctica estándar en herramientas como Bandit y Semgrep."

**¿Qué valor agrega vs usar Bandit y un scanner por separado?**
> "Tres cosas. Primero, cobertura: juntos detectan 3.6× más que SAST solo. Segundo, confirmación: la correlación reduce el área de duda de los hallazgos estáticos — B608 pasa de 'posible SQL injection' a 'SQL injection confirmado por evidencia dinámica'. Tercero, integración: el sistema unifica el flujo completo en una sola interfaz web con reportes descargables."

**¿El modelo está overfitted?**
> "No. El modelo fue evaluado en un test set separado que no vio durante el entrenamiento. Los valores en metadata.json —Accuracy 76.9%, F1 0.786— son las métricas del test set. El overfitting se detectaría si el training accuracy fuera significativamente mayor que el test accuracy."

**¿Por qué usar Random Forest y no una red neuronal?**
> "Random Forest tiene tres ventajas para este problema: interpretabilidad (podemos ver qué features usa), robustez con datos mixtos (numéricos + categóricos + texto TF-IDF), y no requiere grandes datasets. Con 1,300 muestras, un transformer habría overfitteado. El Random Forest es la elección correcta para este tamaño de dataset."

---

## Si algo falla durante la demo

**Si el backend no levanta:**
```powershell
# Verificar
curl http://localhost:8000/health
# Si falla, mostrar directamente los resultados guardados:
py -3.11 -c "
import json; from pathlib import Path
f = sorted(Path('data/experiments/results').glob('hybrid_vulnerable_*.json'))[-1]
r = json.loads(f.read_text())
print(json.dumps(r['summary'], indent=2))
"
```

**Si la app vulnerable no levanta:**
```powershell
# Instalar flask primero
py -3.11 -m pip install flask --quiet
py -3.11 ProgramasPruebas\vulnerable_app.py
```

**Si el experimento no encuentra correlaciones:**
Muestra el resultado guardado en `data/experiments/results/hybrid_vulnerable_*.json` — los resultados del experimento ya ejecutado están ahí.

---

## Frase de cierre

*"HybridSecScan demuestra que la integración inteligente de SAST y DAST, coordinada por un motor de correlación Machine Learning, no solo detecta más vulnerabilidades que cualquier herramienta individual, sino que también valida automáticamente qué hallazgos estáticos tienen evidencia dinámica —reduciendo la carga de revisión manual de los equipos de seguridad."*
