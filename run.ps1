using namespace System.Net

param($timer)

if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function started at: $currentUTCtime"

$rumbleApiKey = $ENV:rumbleApiKey
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

$orgId = '73882991-7869-40f0-903a-a617405dca48'
$pageSize = 100
$startKey = $null
$logType = "RumbleAssets"
$timeGeneratedField = ""

Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = "$method`n$contentLength`n$contentType`n$xHeaders`n$resource"

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    return 'SharedKey {0}:{1}' -f $customerId,$encodedHash
}

Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature $customerId $sharedKey $rfc1123date $contentLength $method $contentType $resource

    $uri = "https://$customerId.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $timeGeneratedField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

$baseUrl = "https://console.rumble.run/api/v1.0/export/org/assets.json"
$fields = "id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products"

$maxBatchSize = 2.5MB
$page = 1

do {
    $url = "$baseUrl?org=$orgId&fields=$fields&page_size=$pageSize"
    if ($startKey) {
        $url += "&start_key=$startKey"
    }

    Write-Host "[+] Fetching page $page from Rumble..."
    $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop

    $assets = $response.assets
    $startKey = $response.start_key  # null when there are no more pages

    if (-not $assets) {
        Write-Host "[-] No assets found on page $page"
        break
    }

    # Procesar los activos en lotes de tamaño controlado
    $currentBatch = @()
    $currentSize = 0

    foreach ($obj in $assets) {
        $json = $obj | ConvertTo-Json -Depth 10 -Compress
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

    # Enviar último lote si queda alguno
    if ($currentBatch.Count -gt 0) {
        $jsonBody = "[" + ($currentBatch -join ",") + "]"
        $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $jsonBody -logType $logType
        Write-Host "    [Último batch de página $page] enviado con $($currentBatch.Count) registros, status: $statusCode"
    }

    $page += 1

} while ($startKey)

$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
