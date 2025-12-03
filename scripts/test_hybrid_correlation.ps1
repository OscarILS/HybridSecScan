# Script de prueba para verificar el flujo completo de correlación híbrida
# Este script ejecuta SAST, luego DAST, y finalmente la correlación

$base = "http://127.0.0.1:8000"
$ErrorActionPreference = "Stop"

Write-Host "`n🔬 HybridSecScan - Test de Correlación Completo" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

# Paso 1: Ejecutar SAST
Write-Host "`n📊 Paso 1: Ejecutando análisis SAST con Bandit..." -ForegroundColor Yellow
$targetFile = "C:\Users\oscar\OneDrive\Documentos\GitHub\HybridSecScan\ProgramasPruebas\vulnerable_app.py"

if (-not (Test-Path $targetFile)) {
    Write-Host "❌ Error: Archivo vulnerable_app.py no encontrado" -ForegroundColor Red
    exit 1
}

$sastBody = @{
    target_path = $targetFile
    tool = "bandit"
}

try {
    $sastResponse = Invoke-RestMethod -Uri "$base/scan/sast" -Method Post -Form $sastBody
    $sastId = $sastResponse.id
    Write-Host "✅ SAST completado - ID: $sastId" -ForegroundColor Green
    Write-Host "   Vulnerabilidades encontradas: $($sastResponse.vulnerabilities_found)" -ForegroundColor White
    Write-Host "   Reporte: $($sastResponse.report_path)" -ForegroundColor Gray
} catch {
    Write-Host "❌ Error ejecutando SAST: $_" -ForegroundColor Red
    exit 1
}

# Paso 2: Ejecutar DAST
Write-Host "`n📊 Paso 2: Ejecutando análisis DAST con ZAP..." -ForegroundColor Yellow
$targetUrl = "https://api.ejemplo.com/v1/users"

$dastBody = @{
    target_url = $targetUrl
}

try {
    $dastResponse = Invoke-RestMethod -Uri "$base/scan/dast" -Method Post -Form $dastBody
    $dastId = $dastResponse.id
    Write-Host "✅ DAST completado - ID: $dastId" -ForegroundColor Green
    Write-Host "   Vulnerabilidades encontradas: $($dastResponse.summary.total_issues)" -ForegroundColor White
    Write-Host "   Reporte: $($dastResponse.report_path)" -ForegroundColor Gray
} catch {
    Write-Host "❌ Error ejecutando DAST: $_" -ForegroundColor Red
    exit 1
}

# Paso 3: Ejecutar Correlación Híbrida
Write-Host "`n🔗 Paso 3: Ejecutando análisis híbrido con motor de correlación..." -ForegroundColor Yellow
$hybridBody = @{
    sast_scan_id = $sastId
    dast_scan_id = $dastId
}

try {
    $hybridResponse = Invoke-RestMethod -Uri "$base/scan/hybrid" -Method Post -Form $hybridBody
    $hybridId = $hybridResponse.id
    Write-Host "✅ Correlación completada - ID: $hybridId" -ForegroundColor Green
    Write-Host "`n📈 Resultados de Correlación:" -ForegroundColor Cyan
    Write-Host "   Total hallazgos SAST: $($hybridResponse.summary.total_sast_findings)" -ForegroundColor White
    Write-Host "   Total hallazgos DAST: $($hybridResponse.summary.total_dast_findings)" -ForegroundColor White
    Write-Host "   Correlaciones alta confianza: $($hybridResponse.summary.high_confidence_correlations)" -ForegroundColor Green
    Write-Host "   Correlaciones media confianza: $($hybridResponse.summary.medium_confidence_correlations)" -ForegroundColor Yellow
    Write-Host "   Reducción FP estimada: $([math]::Round($hybridResponse.summary.potential_false_positives_reduced, 1))%" -ForegroundColor Magenta
    
    Write-Host "`n🤖 Métricas del Modelo ML:" -ForegroundColor Cyan
    if ($hybridResponse.model_metrics) {
        Write-Host "   F1-Score: $([math]::Round($hybridResponse.model_metrics.test_f1 * 100, 1))%" -ForegroundColor White
        Write-Host "   Accuracy: $([math]::Round($hybridResponse.model_metrics.test_accuracy * 100, 1))%" -ForegroundColor White
        Write-Host "   Samples entrenamiento: $($hybridResponse.model_metrics.training_samples)" -ForegroundColor Gray
    }
    
    Write-Host "`n📋 Top 5 Correlaciones:" -ForegroundColor Cyan
    $topCorrelations = $hybridResponse.correlations | Select-Object -First 5
    foreach ($corr in $topCorrelations) {
        Write-Host "`n   🔸 Correlación (Confianza: $([math]::Round($corr.confidence_score * 100, 1))%)" -ForegroundColor Yellow
        Write-Host "      SAST: $($corr.sast_vulnerability.type) - $($corr.sast_vulnerability.file):$($corr.sast_vulnerability.line)" -ForegroundColor Gray
        Write-Host "      DAST: $($corr.dast_vulnerability.type) - $($corr.dast_vulnerability.endpoint)" -ForegroundColor Gray
    }
    
    Write-Host "`n   Reporte completo: $($hybridResponse.report_path)" -ForegroundColor Gray
    
} catch {
    Write-Host "❌ Error ejecutando correlación híbrida: $_" -ForegroundColor Red
    exit 1
}

# Paso 4: Descargar PDF del reporte híbrido
Write-Host "`n📥 Paso 4: Descargando reporte PDF..." -ForegroundColor Yellow
try {
    $pdfPath = ".\HybridSecScan_Report_HYBRID_$hybridId.pdf"
    Invoke-WebRequest -Uri "$base/download/pdf/$hybridId" -OutFile $pdfPath -ErrorAction Stop
    Write-Host "✅ PDF descargado: $pdfPath" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Advertencia: No se pudo descargar PDF: $_" -ForegroundColor Yellow
}

Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "✅ Flujo completo de correlación híbrida verificado exitosamente!" -ForegroundColor Green
Write-Host "`n💡 IDs generados:" -ForegroundColor Cyan
Write-Host "   SAST ID: $sastId" -ForegroundColor White
Write-Host "   DAST ID: $dastId" -ForegroundColor White
Write-Host "   HYBRID ID: $hybridId" -ForegroundColor White
Write-Host "`n🌐 Puedes ver el reporte híbrido en el frontend o descargar el JSON:" -ForegroundColor Cyan
Write-Host "   curl $base/download/json/$hybridId -o hybrid_report.json`n" -ForegroundColor Gray
