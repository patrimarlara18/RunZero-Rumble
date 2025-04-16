using namespace System.Net

# Input bindings are passed in via param block.
param($request, $TriggerMetadata)

# Log the function start time
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell HTTP trigger function processed a POST request at: $currentUTCtime"

# Get environment variables from the Azure Functions app
$workspaceId = $ENV:workspaceId
$workspaceKey = $ENV:workspaceKey

# Name of the custom Log Analytics table upon which the Log Analytics Data Connector API will append '_CL'
$logType = "RumbleAlerts"

# Optional value that specifies the name of the field denoting the time the data was generated
# If unspecified, the Log Analytics Data Connector API assumes it was generated at ingestion time
$timeGeneratedField = ""

# Fetch the JSON content in the body of the HTTP POST request sent from Rumble via a webhook
$obj = $request.Body

Write-Host $obj

# Log the raw new assets received from Rumble (útil para debug)
Write-Host "Raw new assets: $($obj.'new_assets' | Out-String)"

# Procesar activos nuevos (si los hay)
if ($obj.new -ne 0){
    foreach ($asset in $obj.'new_assets'){
        # Limpiar formato de direcciones y nombres (elimina corchetes y separa por espacios)
        $asset.addresses = (ConvertFrom-Json $asset.addresses)
        $asset.names = (ConvertFrom-Json $asset.names)
        # Añadir campo que indica el tipo de evento
        $asset | Add-Member -MemberType NoteProperty -Name 'event_type' -value 'new-assets-found'
    }

    # Convertir los activos procesados a JSON
    $new_assets = @($obj.'new_assets') | ConvertTo-Json -Depth 5
    Write-Host "[+] Sending new asset payload to Log Analytics:"
    Write-Host $new_assets
}

Write-Host "Raw changed assets: $($obj.'changed_assets' | Out-String)"

# Procesar activos modificados (si los hay)
if ($obj.changed -ne 0){
    foreach ($asset in $obj.'changed_assets'){
        $asset.addresses = (ConvertFrom-Json $asset.addresses)
        $asset.names = (ConvertFrom-Json $asset.names)
        $asset | Add-Member -MemberType NoteProperty -Name 'event_type' -value 'assets-changed'
    }

    $changed_assets = @($obj.'changed_assets') | ConvertTo-Json -Depth 5
    Write-Host "[+] Sending changed asset payload to Log Analytics:"
    Write-Host $changed_assets
}

Write-Host "[+] Fetched new and changed information from Rumble alerts webhook"

# Función para construir la firma de autenticación HMAC requerida por la API de Azure Log Analytics
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

# Función para enviar datos a Azure Log Analytics mediante POST
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

    $uri = "https://$customerId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $timeGeneratedField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

# Enviar activos nuevos si existen
if ($obj.new -ne 0 -and $new_assets){
    Write-Host "[+] Sending new asset payload to Log Analytics:"
    Write-Host $new_assets

    $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $new_assets -logType $logType
    if ($statusCode -eq 200){
        Write-Host "[+] (New Assets) Successfully sent POST request to the Log Analytics API"
    } else {
        Write-Host "[-] (New Assets) Failed to send POST request to the Log Analytics API with status code: $statusCode"
    }
}

# Enviar activos modificados si existen
if ($obj.changed -ne 0 -and $changed_assets){
    Write-Host "[+] Sending changed asset payload to Log Analytics:"
    Write-Host $changed_assets

    $statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $changed_assets -logType $logType
    if ($statusCode -eq 200){
        Write-Host "[+] (Changed Assets) Successfully sent POST request to the Log Analytics API"
    } else {
        Write-Host "[-] (Changed Assets) Failed to send POST request to the Log Analytics API with status code: $statusCode"
    }
}

# Log the function end time
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
