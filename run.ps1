using namespace System.Net

# Input bindings are passed in via param block.
param($timer)

# Comprueba si el timer está retrasado
if ($timer.IsPastDue) {
    Write-Host "[-] PowerShell timer is running late"
}

# Muestra el inicio de la ejecución en hora UTC
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function started at: $currentUTCtime"

# Cargar variables de entorno necesarias para la API de RunZero y Azure Log Analytics
$rumbleApiKey = $ENV:rumbleApiKey
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

Write-Host "[DEBUG] rumbleApiKey: $rumbleApiKey"
Write-Host "[DEBUG] workspaceId: $workspaceId"
Write-Host "[DEBUG] workspaceKey length: $($workspaceKey.Length)"

# Configuración inicial
$baseUrl = 'https://console.rumble.run/api/v1.0/export/org/assets.json?fields=id,updated_at,site_name,alive,names,addresses,type,os,hw,service_ports_tcp,service_ports_udp,service_protocols,service_products'
$orgId = '73882991-7869-40f0-903a-a617405dca48'
$pageSize = 100
$startKey = $null
$logType = "RumbleAssets"
$timeGeneratedField = ""

Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
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

Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
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

do {
    $uri = "https://console.rumble.run/api/v1.0/export/org/assets.json?fields=id,updated_at,site_name,alive,names,addresses,type,os,hw,service_ports_tcp,service_ports_udp,service_protocols,service_products?_oid=$orgId&page_size=$pageSize"
    if ($startKey) {
        $uri += "&start_key=$startKey"
    }

    Write-Host "[DEBUG] URI construida: $uri"

    $headers = @{
        Accept = 'application/json'
        Authorization = "Bearer $rumbleApiKey"
    }

    try {
        $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers -ErrorAction Stop
        Write-Host "[+] Fetched asset information from the Rumble API"

        # Convertir en array (aunque venga 1 solo objeto)
        $jsonObjects = if ($response -is [System.Collections.IEnumerable]) { $response } else { @($response) }

        # Convertir todos los objetos en un único array JSON para envío por lote
        $jsonBody = $jsonObjects | ConvertTo-Json -Depth 100

        $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $jsonBody -logType $logType
        Write-Host "[+] Enviado lote de $($jsonObjects.Count) assets con status: $statusCode"

        # Obtener next_key si existe
        $startKey = $null
if ($response.PSObject.Properties.Name -contains 'next_key') {
    $startKey = $response.next_key
}

    } catch {
        Write-Error "❌ ERROR en la llamada a RunZero o Log Analytics: $($_.Exception.Message)"
        break
    }

} while ($startKey)

# Fin de la ejecución
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
