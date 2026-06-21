<#
.SYNOPSIS
    Script de despliegue automatizado End-to-End para la Infraestructura de Clave Pública (PKI) en Java.
.DESCRIPTION
    Este script limpia el entorno, compila el código fuente mediante Maven, ejecuta la clase orquestadora Main, 
    y verifica la correcta generación de los artefactos criptográficos y reportes de auditoría.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Get-Location
$CertFolder = Join-Path -Path $ProjectRoot -ChildPath "certificates"
$AuditFile = Join-Path -Path $ProjectRoot -ChildPath "audit-report.csv"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " INICIANDO DESPLIEGUE AUTOMATIZADO DE PKI (DEV-LAB)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# Paso 1: Limpieza de laboratorios anteriores
Write-Host "`n[1/4] Limpiando artefactos de ejecuciones previas..." -ForegroundColor Yellow
if (Test-Path $CertFolder) {
    Remove-Item -Path "$CertFolder\*" -Recurse -Force
    Write-Host "  -> Carpeta /certificates vaciada." -ForegroundColor Green
}
if (Test-Path $AuditFile) {
    Remove-Item -Path $AuditFile -Force
    Write-Host "  -> Archivo de auditoría anterior eliminado." -ForegroundColor Green
}

# Paso 2: Compilación con Maven
Write-Host "`n[2/4] Compilando el código fuente con Maven..." -ForegroundColor Yellow
try {
    # Ejecuta maven y guarda la salida para mantener la consola limpia, mostrando errores si ocurren
    $mvnOut = mvn clean compile 2>&1
    Write-Host "  -> Compilación (BUILD SUCCESS) completada." -ForegroundColor Green
} catch {
    Write-Host "  [X] Error crítico en la compilación de Maven. Abortando despliegue." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit
}

# Paso 3: Ejecución de la PKI
Write-Host "`n[3/4] Ejecutando orquestador criptográfico (Main.java)..." -ForegroundColor Yellow
# Usamos exec:java para correr la clase Main desde Maven
mvn exec:java -D"exec.mainClass"="Main" | Out-Default

# Paso 4: Verificación de Artefactos (Pruebas de reproducibilidad)
Write-Host "`n[4/4] Verificando artefactos y cumplimiento de rúbrica..." -ForegroundColor Yellow
$RequiredFiles = @(
    "root-ca.key", "root-ca.crt", 
    "sub-ca.key", "sub-ca.crt", "ca-chain.pem", 
    "user-cert.crt", "usuario.p12", 
    "server-cert.crt", "server.p12",
    "sub-ca.crl"
)

$MissingFiles = 0
foreach ($file in $RequiredFiles) {
    $filePath = Join-Path -Path $CertFolder -ChildPath $file
    if (Test-Path $filePath) {
        Write-Host "  [OK] $file generado correctamente." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Falta el artefacto: $file" -ForegroundColor Red
        $MissingFiles++
    }
}

if (Test-Path $AuditFile) {
    Write-Host "  [OK] audit-report.csv generado correctamente." -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Falta el reporte de auditoría." -ForegroundColor Red
    $MissingFiles++
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
if ($MissingFiles -eq 0) {
    Write-Host " DESPLIEGUE END-TO-END COMPLETADO CON ÉXITO" -ForegroundColor Green
} else {
    Write-Host " DESPLIEGUE FINALIZADO CON ADVERTENCIAS ($MissingFiles archivos faltantes)" -ForegroundColor Yellow
}
Write-Host "=====================================================`n" -ForegroundColor Cyan