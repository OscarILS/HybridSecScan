import requests

# Ejecutar escaneo híbrido
response = requests.post(
    'http://127.0.0.1:8000/scan/hybrid',
    data={'sast_scan_id': 54, 'dast_scan_id': 55}
)

data = response.json()
summary = data['summary']

print(f"\n✅ HYBRID ID: {data['id']}")
print(f"\n📊 SUMMARY:")
print(f"SAST findings: {summary['total_sast_findings']}")
print(f"DAST findings: {summary['total_dast_findings']}")
print(f"Critical: {summary.get('critical_issues', 0)}")
print(f"High: {summary.get('high_severity_findings', 0)}")
print(f"Medium: {summary.get('medium_severity_findings', 0)}")
print(f"Low: {summary.get('low_severity_findings', 0)}")
print(f"\nHybrid ID guardado: {data['id']}")
