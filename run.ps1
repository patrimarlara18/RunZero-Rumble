using namespace System.Net

# Input bindings are passed in via param block.
param($timer)

# Check if the current function invocation is running later than scheduled
if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

# Log the function start time
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function started at: $currentUTCtime"

# Get environment variables from the Azure Functions app
$rumbleApiKey = $ENV:rumbleApiKey
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

# Rumble assets export
$orgId = '73882991-7869-40f0-903a-a617405dca48'
$pageSize = 50
$startKey = $null
$logType = "RumbleAssets"
$timeGeneratedField = ""

# Fetch asset information from the Rumble API
$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}

# Helper function to build the authorization signature for the Log Analytics Data Connector API
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Helper function to build and invoke a POST request to the Log Analytics Data Connector API
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

# Inicializar contadores
$totalAssets = 0
$pageCount = 0

# Envío paginado
do {
    $uri = "https://console.runzero.com/api/v1.0/export/org/assets.json?_oid=$orgId&fields=id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products&page_size=$pageSize"

    if ($startKey) {
        $uri += "&start_key=$startKey"
    }

    Write-Host "[DEBUG] Llamando a URI: $uri"

    try {
        $pageCount += 1
        Write-Host "[DEBUG] Procesando página #$pageCount"

        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Headers $headers -ErrorAction Stop
        $assets = $response.assets  # ✅ Acceder al array de assets

        if (-not $assets) {
            Write-Host "[+] Página #$pageCount contiene 0 assets."
        } else {
            $totalAssets += $assets.Count
            Write-Host "[+] Página #$pageCount contiene $($assets.Count) assets. Total acumulado: $totalAssets"
        }

        # Envío por lotes
        $maxBatchSize = 2.5MB
        $currentBatch = @()
        $currentSize = 0

        foreach ($obj in $assets) {
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

        # Paginación
        if ($response.PSObject.Properties.Name -contains 'next_key') {
            $startKey = $response.next_key
            Write-Host "[DEBUG] Se encontró next_key. Continuando a la siguiente página..."
        } else {
            Write-Host "[DEBUG] No hay next_key. Fin de la paginación."
            $startKey = $null
        }

    } catch {
        Write-Error "❌ ERROR: $($_.Exception.Message)"
        break
    }

} while ($startKey)

Write-Host "[✔] Total de páginas procesadas: $pageCount"
Write-Host "[✔] Total de assets recibidos desde RunZero: $totalAssets"
Write-Host "[+] Proceso finalizado"
