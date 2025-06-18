using namespace System.Net

param($timer)

if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

# Parámetros de entorno
$rumbleApiKey = $ENV:rumbleApiKey
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

# Parámetros de API
$orgId = '73882991-7869-40f0-903a-a617405dca48'
$pageSize = 500
$startKey = $null
$logType = "RumbleAssets"
$timeGeneratedField = ""

# Headers
$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

# Función para firma
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = "$methodn$contentLengthn$contentTypen$xHeadersn$resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    return 'SharedKey {0}:{1}' -f $customerId, $encodedHash
}

# Función para enviar datos
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature $customerId $sharedKey $rfc1123date $contentLength $method $contentType $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature
        "Log-Type" = $logType
        "x-ms-date" = $rfc1123date
        "time-generated-field" = $timeGeneratedField
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# Envío paginado
do {
    $uri = "https://console.rumble.run/api/v1.0/export/org/assets.json?_oid=$orgId&fields=id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products&page_size=$pageSize"
    if ($startKey) {
        $uri += "&start_key=$startKey"
    }

    Write-Host "[DEBUG] Llamando a URI: $uri"

    try {
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $headers -ErrorAction Stop

        # Convertir a array si es necesario
        $responseObjects = if ($response -is [System.Collections.IEnumerable]) { $response } else { @($response) }

        # Filtrar por site_name = ARGENTINA
        $argentinaAssets = $responseObjects | Where-Object { $_.site_name -eq "ARGENTINA" }
        Write-Host "[+] Se encontraron $($argentinaAssets.Count) assets para ARGENTINA en esta página."

        # Envío por lotes
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

        # Obtener siguiente start_key
        $startKey = $null
        if ($response.PSObject.Properties.Name -contains 'next_key') {
            $startKey = $response.next_key
        }

    } catch {
        Write-Error "❌ ERROR: $($_.Exception.Message)"
        break
    }

} while ($startKey)

Write-Host "[+] Proceso finalizado"
