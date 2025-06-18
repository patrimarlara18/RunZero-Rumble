using namespace System.Net

# Input bindings are passed in via param block.
param($timer)

# Check if the current function invocation is running later than scheduled
if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

# Parámetros de entorno (ajústalos según tu entorno o ponlos fijos)
$rumbleApiKey = $ENV:rumbleApiKey
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

# URI y nombre del Log Type
$rumbleAssetsUri = 'https://console.rumble.run/api/v1.0/export/org/assets.json?fields=id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products'
$logType = "RumbleAssets"
$timeGeneratedField = ""

# Headers para Rumble API
$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

# Obtener assets
$response = Invoke-RestMethod -Method 'Get' -Uri $rumbleAssetsUri -Headers $headers -ErrorAction Stop
$responseObjects = $response | ConvertFrom-Json -AsHashtable

# Filtrar por site_name = ARGENTINA
$argentinaAssets = $responseObjects | Where-Object { $_.site_name -eq "ARGENTINA" }

Write-Host "[+] Se encontraron $($argentinaAssets.Count) assets para ARGENTINA"

# Función para firma de autenticación
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

# Función para enviar datos a Log Analytics
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature $customerId $sharedKey $rfc1123date $contentLength $method $contentType $resource
    $uri = "https://$customerId.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature
        "Log-Type" = $logType
        "x-ms-date" = $rfc1123date
        "time-generated-field" = $timeGeneratedField
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# Enviar en lotes de hasta 2.5 MB
$maxBatchSize = 2.5MB
$currentBatch = @()
$currentSize = 0

foreach ($obj in $argentinaAssets) {
    $json = $obj | ConvertTo-Json -Depth 100 -Compress
    $size = [System.Text.Encoding]::UTF8.GetByteCount($json)

    if (($currentSize + $size) -gt $maxBatchSize) {
        $jsonBody = "[" + ($currentBatch -join ",") + "]"
        $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $jsonBody -logType $logType
        Write-Host "    [Batch enviado] con $($currentBatch.Count) registros, status: $statusCode"
        Start-Sleep -Milliseconds 500
        $currentBatch = @()
        $currentSize = 0
    }

    $currentBatch += $json
    $currentSize += $size
}

if ($currentBatch.Count -gt 0) {
    $jsonBody = "[" + ($currentBatch -join ",") + "]"
    $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $jsonBody -logType $logType
    Write-Host "    [Último batch enviado] con $($currentBatch.Count) registros, status: $statusCode"
}

Write-Host "[+] Proceso finalizado"

