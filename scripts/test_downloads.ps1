$base='http://127.0.0.1:8000'
Write-Host "Comprobando $base/scan-results..."
try{
    $res=Invoke-RestMethod -Uri "$base/scan-results" -Method GET -ErrorAction Stop
    Write-Host "OK - scan-results obtenidos. Count: $($res.Count)"
} catch {
    Write-Host "Fallo al obtener scan-results: $_"
    exit 1
}

if ($res -and $res.Count -gt 0) {
    $id = $res[-1].id
    Write-Host "Usando último scan id: $id"
} else {
    Write-Host "No hay resultados. Lanzando DAST de prueba..."
    $body = @{ target_url='http://testphp.vulnweb.com/'; tool='owasp_zap' }
    try {
        $scan = Invoke-RestMethod -Uri "$base/scan/dast" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        $id = $scan.id
        Write-Host "DAST creado, id: $id"
    } catch {
        Write-Host "Fallo al crear DAST: $_"
        exit 1
    }
}

Write-Host "Intentando descargar PDF para id=$id..."
try {
    Invoke-WebRequest -Uri "$base/download/pdf/$id" -OutFile "scan_${id}.pdf" -ErrorAction Stop
    Write-Host "PDF guardado: scan_${id}.pdf"
} catch {
    Write-Host "Error descargando PDF: $_"
}

Write-Host "Intentando descargar JSON para id=$id..."
try {
    Invoke-WebRequest -Uri "$base/download/json/$id" -OutFile "scan_${id}.json" -ErrorAction Stop
    Write-Host "JSON guardado: scan_${id}.json"
} catch {
    Write-Host "Error descargando JSON: $_"
}

Write-Host "Script finalizado."