param($timer)

# Comprueba si el timer está retrasado
if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

# Muestra el inicio de la ejecución en hora UTC
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function started at: $currentUTCtime"

# Cargar variables de entorno necesarias para la API de RunZero y Azure Log Analytics
$rumbleApiKey = $ENV:rumbleApiKey      # Token de acceso de RunZero
$workspaceId = $ENV:workspaceId        # ID de Azure Log Analytics
$workspaceKey = $ENV:workspaceKey      # Clave compartida para autenticación

Write-Host "[DEBUG] rumbleApiKey: $rumbleApiKey"
Write-Host "[DEBUG] workspaceId: $workspaceId"
Write-Host "[DEBUG] workspaceKey length: $($workspaceKey.Length)"

# Validación básica
if (-not $rumbleApiKey -or -not $workspaceId -or -not $workspaceKey) {
    throw "❌ ERROR: Variables de entorno faltantes o vacías. Verifica rumbleApiKey, workspaceId y workspaceKey."
}

# Configuración para RunZero API
$baseUri = 'https://console.runzero.com/api/v1.0/export/org/assets.json'
$orgId = '73882991-7869-40f0-903a-a617405dca48'  # ← Este valor lo obtienes desde el portal o te lo da soporte
$pageSize = 100                      # Tamaño de página: cuántos assets traer por página
$startKey = $null                    # Clave de paginación para continuar con el siguiente lote

# Validar URI base y orgId
if (-not $baseUri -or -not $orgId) {
    throw "❌ ERROR: baseUri u orgId no están definidos correctamente."
}

# Asegura que no hay espacios ocultos o caracteres invisibles
$baseUri = $baseUri.Trim()
$orgId = $orgId.Trim()

# Lógica para paginar los resultados y enviarlos en bloques (batches) de tamaño máximo
$maxBatchSize = 2.5MB
$currentBatch = @()
$currentSize = 0

do {
    # Construir la URL con parámetros de paginación
    $uri = "$baseUri?_oid=$orgId&page_size=$pageSize"
    if ($startKey) {
        $uri += "&start_key=$startKey"
    }

    Write-Host "[DEBUG] URI construida: $uri"

    try {
        # Obtener la página actual de resultados
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $headers -ErrorAction Stop
        Write-Host "[+] Fetched page of asset data"
    }
    catch {
        Write-Error "❌ ERROR en la llamada a RunZero: $($_.Exception.Message)"
        break
    }

    $assets = $response.assets         # Extraer array de assets
    $startKey = $response.next_key     # Guardar el start_key para la próxima página

    # Procesar cada asset individualmente
    foreach ($obj in $assets) {
        $json = $obj | ConvertTo-Json -Depth 100 -Compress
        $size = [System.Text.Encoding]::UTF8.GetByteCount($json)

        # Si el tamaño supera el límite permitido, se envía el batch actual
        if (($currentSize + $size) -gt $maxBatchSize) {
            $jsonBody = "[" + ($currentBatch -join ",") + "]"
            $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $jsonBody -logType $logType
            Write-Host "[Batch enviado] con $($currentBatch.Count) registros, status: $statusCode"
            Start-Sleep -Milliseconds 500

            $currentBatch = @()
            $currentSize = 0
        }

        $currentBatch += $json
        $currentSize += $size
    }

} while ($startKey)  # Continuar mientras haya más páginas

# Enviar el último batch restante si hay
if ($currentBatch.Count -gt 0) {
    $jsonBody = "[" + ($currentBatch -join ",") + "]"
    $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $jsonBody -logType $logType
    Write-Host "[Último batch enviado] con $($currentBatch.Count) registros, status: $statusCode"
}

# Verifica el resultado final
if ($statusCode -eq 200) {
    Write-Host "[+] Successfully sent POST request to the Log Analytics API"
} else {
    Write-Host "[-] Failed to send POST request to the Log Analytics API with status code: $statusCode"
}

# Muestra el final de la ejecución
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
