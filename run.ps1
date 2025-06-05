using namespace System.Net

param($timer)

if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function started at: $currentUTCtime"

# === Cargar variables de entorno
$rumbleApiKey = $ENV:rumbleApiKey
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

Write-Host "[DEBUG] rumbleApiKey: $rumbleApiKey"
Write-Host "[DEBUG] workspaceId: $workspaceId"
Write-Host "[DEBUG] workspaceKey length: $($workspaceKey.Length)"

# === URL de Rumble
$rumbleAssetsUri = 'https://console.rumble.run/api/v1.0/export/org/assets.json?fields=id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products'

# === Configuración Log Analytics
$logType = "RumbleAssets"
$timeGeneratedField = ""

# === Headers para API de Rumble
$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

# === Obtener datos desde Rumble directamente como objeto
try {
    $response = Invoke-RestMethod -Method 'Get' -Uri $rumbleAssetsUri -Headers $headers -ErrorAction Stop
    Write-Host "[+] Fetched asset information from the Rumble API"
    Write-Host "[DEBUG] Tipo de objeto después de parsing: $($response.GetType().FullName)"
} catch {
    Write-Error "[-] Error al obtener datos de Rumble: $_"
    return
}

# === Firma para Log Analytics
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

# === POST hacia Log Analytics
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = [Text.Encoding]::UTF8.GetByteCount($body)
    $signature = Build-Signature $customerId $sharedKey $rfc1123date $contentLength $method $contentType $resource

    $uri = "https://$customerId.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    $headers = @{
        "Authorization"         = $signature
        "Log-Type"              = $logType
        "x-ms-date"             = $rfc1123date
        "time-generated-field"  = $timeGeneratedField
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# === Envío por lotes de 2.5 MB (2,621,440 bytes)
$maxBatchSize = 2621440
$currentBatch = @()
$currentSize = 0
$totalSent = 0

foreach ($obj in $response) {
    $json = $obj | ConvertTo-Json -Depth 100 -Compress
    $size = [Text.Encoding]::UTF8.GetByteCount($json)

    if (($currentSize + $size) -gt $maxBatchSize) {
        $jsonBody = "[" + ($currentBatch -join ",") + "]"
        $statusCode = Post-LogAnalyticsData $workspaceId $workspaceKey $jsonBody $logType
        Write-Host "[Batch enviado] Registros: $($currentBatch.Count), Size: $currentSize bytes, Status: $statusCode"
        $totalSent += $currentBatch.Count
        $currentBatch = @()
        $currentSize = 0
        Start-Sleep -Milliseconds 500
    }

    $currentBatch += $json
    $currentSize += $size
}

# Último batch
if ($currentBatch.Count -gt 0) {
    $jsonBody = "[" + ($currentBatch -join ",") + "]"
    $statusCode = Post-LogAnalyticsData $workspaceId $workspaceKey $jsonBody $logType
    Write-Host "[Último batch enviado] Registros: $($currentBatch.Count), Size: $currentSize bytes, Status: $statusCode"
    $totalSent += $currentBatch.Count
}

Write-Host "[+] Total de registros enviados: $totalSent"

if ($statusCode -eq 200) {
    Write-Host "[+] Successfully sent POST request to the Log Analytics API"
} else {
    Write-Host "[-] Failed to send POST request to the Log Analytics API with status code: $statusCode"
}

$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
