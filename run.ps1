using namespace System.Net

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

# Configuración para RunZero API
$baseUri = 'https://console.runzero.com/api/v1.0/export/org/assets.json'
$orgId = '73882991-7869-40f0-903a-a617405dca48'  # ← Este valor lo obtienes desde el portal o te lo da soporte
$pageSize = 100                      # Tamaño de página: cuántos assets traer por página
$startKey = $null                    # Clave de paginación para continuar con el siguiente lote

# Parámetros para Log Analytics
$logType = "RumbleAssets"
$timeGeneratedField = ""

# Cabeceras para la autenticación en RunZero
$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

# Función que construye la firma requerida por la API de Log Analytics
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = "$method`n$contentLength`n$contentType`n$xHeaders`n$resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    return 'SharedKey {0}:{1}' -f $customerId, $encodedHash
}

# Función para enviar los datos a Azure Log Analytics
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource

    $uri = "https://${customerId}.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature
        "Log-Type" = $logType
        "x-ms-date" = $rfc1123date
        "time-generated-field" = $timeGeneratedField
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

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

    # Obtener la página actual de resultados
    $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $headers -ErrorAction Stop
    Write-Host "[+] Fetched page of asset data"

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
