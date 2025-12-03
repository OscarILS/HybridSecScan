from fastapi.testclient import TestClient
from backend import main
import json

client = TestClient(main.app)
base = ''

print('Comprobando /scan-results...')
res = client.get('/scan-results')
if res.status_code != 200:
    print('Error obteniendo scan-results:', res.status_code, res.text)
    raise SystemExit(1)
results = res.json()
print('Scan-results count:', len(results))

if len(results) > 0:
    scan_id = results[-1]['id']
    print('Usando último scan id:', scan_id)
else:
    print('No hay resultados, creando DAST...')
    r = client.post('/scan/dast', data={'target_url': 'http://testphp.vulnweb.com/'})
    print('POST /scan/dast ->', r.status_code)
    if r.status_code != 200:
        print('Error creando DAST:', r.text)
        raise SystemExit(1)
    body = r.json()
    scan_id = body.get('id')
    print('Scan creado id:', scan_id)

# Descargar PDF
print('Intentando descargar PDF para id=', scan_id)
r = client.get(f'/download/pdf/{scan_id}')
print('GET /download/pdf ->', r.status_code)
if r.status_code == 200:
    fn = f'scan_{scan_id}.pdf'
    with open(fn, 'wb') as f:
        f.write(r.content)
    print('PDF guardado como', fn)
else:
    try:
        print('Error body:', r.json())
    except Exception:
        print('Error body (raw):', r.text)

# Descargar JSON
print('Intentando descargar JSON para id=', scan_id)
r = client.get(f'/download/json/{scan_id}')
print('GET /download/json ->', r.status_code)
if r.status_code == 200:
    fn = f'scan_{scan_id}.json'
    with open(fn, 'wb') as f:
        f.write(r.content)
    print('JSON guardado como', fn)
else:
    try:
        print('Error body:', r.json())
    except Exception:
        print('Error body (raw):', r.text)

print('Fin del test')
