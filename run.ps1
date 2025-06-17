using namespace System.Net

param($timer)

if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function started at: $currentUTCtime"

# Variables de entorno necesarias
$rumbleApiKey = ${ENV:rumbleApiKey}
$workspaceId = ${ENV:workspaceId}
$workspaceKey = ${ENV:workspaceKey}


# Configuraciones
$orgId = '73882991-7869-40f0-903a-a617405dca48'
$fields = "id,updated_at,site_name,alive,names,addresses,type,os,hw,service_ports_tcp,service_ports_udp,service_protocols,service_products"
$pageSize = 100
$logType = "RumbleAssets"
$timeGeneratedField = ""
$baseUri = "https://console.runzero.com/api/v1.0/export/org/assets.json"

# Función para construir firma
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = "$method`n$contentLength`n$contentType`n$xHeaders`n$resource"
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    return "SharedKey $customerId:$encodedHash"
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

# Loop de paginación
$startKey = $null

do {
    $queryParams = "_oid=$orgId&fields=$fields&page_size=$pageSize"
    if ($searchParam) { $queryParams += "&$searchParam" }
    if ($startKey) { $queryParams += "&start_key=$startKey" }

    $requestUri = "$baseUri?$queryParams"
    Write-Host "[DEBUG] Request URI: $requestUri"

    $headers = @{
        Accept = 'application/json'
        Authorization = "Bearer $rumbleApiKey"
    }

    try {
        $response = Invoke-RestMethod -Method 'GET' -Uri $requestUri -Headers $headers -ErrorAction Stop
        Write-Host "[+] Fetched a page of assets from the Rumble API"

        # Acceder al campo 'assets'
        $assets = $response.assets
        if (-not $assets) {
            Write-Host "[-] No assets found in response"
            break
        }

        # Serializar directamente los assets (sin convertir el objeto completo de nuevo)
        $jsonBody = $assets | ConvertTo-Json -Depth 10 -Compress
        
        Write-Host $assets
        Write-Host $jsonBody

        # Enviar a Log Analytics
        $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -logType $logType
        Write-Host "[+] Enviado lote con código: $statusCode"

        # Siguiente página
        $startKey = if ($response.PSObject.Properties.Name -contains "next_key") { $response.next_key } else { $null }
    } catch {
        Write-Error "❌ ERROR en la llamada a RunZero o Log Analytics: $($_.Exception.Message)"
        break
    }

} while ($startKey)

$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
