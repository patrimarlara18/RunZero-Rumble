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

Write-Host "[DEBUG] rumbleApiKey: $rumbleApiKey"
Write-Host "[DEBUG] workspaceId: $workspaceId"
Write-Host "[DEBUG] workspaceKey length: $($workspaceKey.Length)"

# Rumble assets export URI
$rumbleAssetsUri = 'https://console.rumble.run/api/v1.0/export/org/assets.json?fields=id,created_at,updated_at,first_seen,last_seen,org_name,site_name,alive,scanned,agent_name,sources,detected_by,names,addresses,addresses_extra,domains,type,os_vendor,os_product,os_version,os,hw_vendor,hw_product,hw_version,hw,newest_mac,newest_mac_vendor,newest_mac_age,comments,tags,tag_descriptions,service_ports_tcp,service_ports_udp,service_protocols,service_products'

# Name of the custom Log Analytics table upon which the Log Analytics Data Connector API will append '_CL'
$logType = "RumbleAssets"

# Optional value that specifies the name of the field denoting the time the data was generated
# If unspecified, the Log Analytics Data Connector API assumes it was generated at ingestion time
$timeGeneratedField = ""

# Fetch asset information from the Rumble API
$headers = @{
    Accept = 'application/json'
    Authorization = "Bearer $rumbleApiKey"
}
$response = Invoke-RestMethod -Method 'Get' -Uri $rumbleAssetsUri -Headers $headers -ErrorAction Stop
Write-Host "[+] Fetched asset information from the Rumble API"
Write-Host "[DEBUG] Response object type: $($response.GetType().FullName)"

Write-Host $response

$json = $response | ConvertFrom-Json -AsHashTable
Write-Host "[DEBUG] JSON payload length (chars): $($json.Length)"
Write-Host "[DEBUG] JSON preview:`n$json".Substring(0, [Math]::Min(500, $json.Length))

# Helper function to build the authorization signature for the Log Analytics Data Connector API
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    Write-Host "[DEBUG] StringToHash:`n$stringToHash"

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash

    Write-Host "[DEBUG] Authorization header: $authorization"

    return $authorization
}

# Helper function to build and invoke a POST request to the Log Analytics Data Connector API
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")

    # CORREGIDO: Calcular content-length en bytes pero no usar eso como cuerpo, solo para la firma
    $contentLength = [System.Text.Encoding]::UTF8.GetByteCount($body)
    Write-Host "[DEBUG] Content-Length (bytes): $contentLength"

    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource

    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    Write-Host "[DEBUG] Log Analytics POST URI: $uri"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
    }

    if ($timeGeneratedField -ne "") {
        $headers["time-generated-field"] = $timeGeneratedField
    }

    Write-Host "[DEBUG] Headers:"
    $headers.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key): $($_.Value)" }

    try {
        # CORREGIDO: El body se pasa como string (JSON), no como array de bytes
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
        Write-Host "[DEBUG] Response status code: $($response.StatusCode)"
        return $response.StatusCode
    } catch {
        Write-Host "[-] Exception during POST to Log Analytics: $($_.Exception.Message)"
        return 0
    }
}

# POST the Rumble asset information to the Log Analytics Data Connector API
# CORREGIDO: Pasar el $json como está (string), no en otro formato
$statusCode = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceKey -body $json -logType $logType

# Check the status of the POST request
if ($statusCode -eq 200){
    Write-Host "[+] Successfully sent POST request to the Log Analytics API"
} else {
    Write-Host "[-] Failed to send POST request to the Log Analytics API with status code: $statusCode"
}

# Log the function end time
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "[+] PowerShell timer trigger function finished at: $currentUTCtime"
