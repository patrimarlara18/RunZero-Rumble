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

Write-Host "[DEBUG] rumbleApiKey: $rumbleApiKey"
Write-Host "[DEBUG] workspaceId: $workspaceId"
Write-Host "[DEBUG] workspaceKey length: $($workspaceKey.Length)"

$rumbleAssetsUri = 'https://console.rumble.run/api/v1.0/export/org/assets.json?fields=id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products'

$logType = "RumbleAssets"
$timeGeneratedField = ""

$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

$response = Invoke-RestMethod -Method 'Get' -Uri $rumbleAssetsUri -Headers $headers -ErrorAction Stop
Write-Host "[+] Fetched asset information from the Rumble API"
Write-Host "[DEBUG] Response object type: $($response.GetType().FullName)"

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
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource

    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $timeGeneratedField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

$responseObjects = $response | ConvertFrom-Json -AsHashtable

$maxBatchSize = 2.5MB

$currentBatch = @()
$currentSize = 0

foreach ($obj in $response) {
    # Convertir a JSON
    $json = $obj | ConvertTo-Json -Depth 10 -Compress
    $size = [Text.Encoding]::UTF8.GetByteCount($json)

    if (($currentSize + $size) -gt $maxBatchSize) {
        # Enviar batch
        $jsonBody = "[" + ($currentBatch -join ",") + "]"
        $statusCode = Post-LogAnalyticsData $workspaceId $workspaceKey $jsonBody $logType $timeGeneratedField
        Write-Host "[Batch enviado] Registros: $($currentBatch.Count), Status: $statusCode"

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
    $statusCode = Post-LogAnalyticsData $workspaceId $workspaceKey $jsonBody $logType $timeGeneratedField
    Write-Host "[Último batch enviado] Registros: $($currentBatch.Count), Status: $statusCode"
}

if ($statusCode -eq 200) {
    Write-Host "[+] Successfully sent POST request to the Log Analytics API"
} else {
    Write-Host "[-] Failed to send POST request to the Log Analytics API with status code: $statusCode"
}


$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
