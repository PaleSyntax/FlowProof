[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResultPath,
    [string]$ApplianceRoot,
    [string]$ArtifactPath,
    [string]$ArtifactSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ([string]::IsNullOrWhiteSpace($ApplianceRoot)) {
    $windowsRoot = Join-Path $root "productization\windows"
    $workflowRoot = Join-Path $root "workflows"
}
else {
    $windowsRoot = (Resolve-Path -LiteralPath $ApplianceRoot).Path
    $workflowRoot = Join-Path $windowsRoot "n8n-workflows"
}
$sourceCheckoutUsedForRuntime = $windowsRoot.StartsWith(
    $root, [StringComparison]::OrdinalIgnoreCase
)
if (-not [string]::IsNullOrWhiteSpace($ArtifactPath)) {
    if (-not [IO.File]::Exists($ArtifactPath) -or
        $ArtifactSha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Artifact path and lowercase SHA-256 are required together."
    }
    $actualArtifactSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath
    ).Hash.ToLowerInvariant()
    if ($actualArtifactSha256 -cne $ArtifactSha256) {
        throw "The n8n guided-connection artifact checksum does not match."
    }
}
else {
    $actualArtifactSha256 = $null
}
Import-Module (Join-Path $windowsRoot "FlowProof.Artifacts.psm1") -Force
Import-Module (Join-Path $windowsRoot "FlowProof.Runtime.psm1") -Force
Import-Module (Join-Path $windowsRoot "FlowProof.N8n.psm1") -Force

function New-RandomText {
    param([ValidateRange(32, 128)][int]$ByteCount = 48)
    $bytes = New-Object byte[] $ByteCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    finally {
        $rng.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Write-Evidence {
    param([Parameter(Mandatory)][object]$Value)
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        $ResultPath,
        (($Value | ConvertTo-Json -Depth 12) + "`n"),
        $encoding
    )
}

function Invoke-SessionJson {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet("GET", "POST", "DELETE")][string]$Method,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [hashtable]$Headers,
        [object]$Body
    )
    $parameters = @{
        Uri = $Uri
        Method = $Method
        UseBasicParsing = $true
        TimeoutSec = 20
    }
    if ($null -ne $Session) { $parameters.WebSession = $Session }
    if ($null -ne $Headers) { $parameters.Headers = $Headers }
    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }
    return Invoke-RestMethod @parameters
}

function Get-PublicPropertyShape {
    param([object]$Value, [string]$Prefix = "", [int]$Depth = 0)
    if ($null -eq $Value -or $Depth -ge 4 -or $Value -is [string]) { return @() }
    $shape = @()
    foreach ($property in @($Value.PSObject.Properties)) {
        $path = "$Prefix$($property.Name)"
        $shape += $path
        if ($null -ne $property.Value -and
            $property.Value -isnot [string] -and
            $property.Value -isnot [ValueType]) {
            $shape += Get-PublicPropertyShape $property.Value "$path." ($Depth + 1)
        }
    }
    return $shape
}

$startedAt = [DateTime]::UtcNow
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$dataRoot = Join-Path ([IO.Path]::GetTempPath()) "flowproof-guided-n8n-$suffix"
$containerName = "flowproof-guided-n8n-$suffix"
$volumeName = "flowproof-guided-n8n-data-$suffix"
$n8nImage = "n8nio/n8n:2.30.5@sha256:450853cd21a2ce36587c4c860eb26927c1ceba9496bf55f4c213b5d3a6dc8c6f"
$n8nBaseUrl = "http://127.0.0.1:5678"
$adminName = "guided-n8n-admin-$suffix"
$adminPasswordText = (New-RandomText 48) + "aA1!"
$adminPassword = ConvertTo-SecureString $adminPasswordText -AsPlainText -Force
$n8nOwnerPassword = (New-RandomText 32) + "aA1!"
$n8nEncryptionKey = New-RandomText 48
$n8nApiKeyText = $null
$n8nApiKey = $null
$n8nApiKeyId = $null
$installed = $false
$containerCreated = $false
$volumeCreated = $false
$caught = $null
$evidence = [ordered]@{
    schema_version = "1.0"
    started_at = $startedAt.ToString('o')
    completed_at = $null
    n8n_version = "2.30.5"
    evidence_classification = "LOCAL_REAL_N8N_TEST_FIXTURE_ONLY"
    runtime_scope = $(if ($sourceCheckoutUsedForRuntime) {
        "SOURCE_WORKTREE_LOCAL_QUALIFICATION"
    } else {
        "EXTRACTED_CANDIDATE_LOCAL_QUALIFICATION"
    })
    source_checkout_used_for_runtime = $sourceCheckoutUsedForRuntime
    artifact = $(if ([string]::IsNullOrWhiteSpace($ArtifactPath)) { $null } else {
        [ordered]@{
            filename = [IO.Path]::GetFileName($ArtifactPath)
            sha256 = $actualArtifactSha256
        }
    })
    real_n8n_execution_proven = $false
    real_provider_observation_proven = $false
    flowproof_connection = $null
    workflow_count = $null
    published_workflow_count = $null
    credential_count = $null
    public_api_exposed_credential_data = $null
    timeline_event_count = $null
    source_system = $null
    manual_flowproof_token_copying = $false
    n8n_api_key_persisted_by_flowproof = $false
    cleanup = [ordered]@{
        appliance_data_deleted = $false
        n8n_container_deleted = $false
        n8n_volume_deleted = $false
    }
    result = "NOT_RUN"
    blocker = $null
}

try {
    $prerequisite = Test-FlowProofPrerequisites
    if (-not $prerequisite.Ready) {
        throw "$($prerequisite.Code): $($prerequisite.Message)"
    }
    $status = Initialize-FlowProofAppliance $dataRoot $adminName $adminPassword
    $installed = $true
    if ($status.ServiceHealth -cne "READY") {
        throw "The FlowProof appliance did not reach READY."
    }

    & docker volume create $volumeName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Docker could not create the temporary n8n volume." }
    $volumeCreated = $true
    & docker run --detach --name $containerName `
        --publish "127.0.0.1:5678:5678" `
        --env "N8N_ENCRYPTION_KEY=$n8nEncryptionKey" `
        --env "N8N_DIAGNOSTICS_ENABLED=false" `
        --env "N8N_BLOCK_ENV_ACCESS_IN_NODE=true" `
        --env "N8N_SECURE_COOKIE=false" `
        --volume "${volumeName}:/home/node/.n8n" $n8nImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Docker could not start the temporary n8n instance." }
    $containerCreated = $true

    for ($attempt = 1; $attempt -le 60; $attempt++) {
        try {
            $health = Invoke-WebRequest -UseBasicParsing -Uri "$n8nBaseUrl/healthz" -TimeoutSec 3
            if ($health.StatusCode -eq 200) { break }
        }
        catch { }
        if ($attempt -eq 60) { throw "Temporary n8n did not reach healthz within 120 seconds." }
        Start-Sleep -Seconds 2
    }

    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $settingsResponse = Invoke-WebRequest -UseBasicParsing `
                -Uri "$n8nBaseUrl/rest/settings" -TimeoutSec 3
            $contentType = [string]$settingsResponse.Headers["Content-Type"]
            if ($settingsResponse.StatusCode -eq 200 -and
                $contentType -match 'application/json') { break }
        }
        catch { }
        if ($attempt -eq 30) { throw "Temporary n8n did not register its REST routes within 60 seconds." }
        Start-Sleep -Seconds 2
    }

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $ownerSetup = Invoke-SessionJson "$n8nBaseUrl/rest/owner/setup" "POST" $session $null @{
        firstName = "FlowProof"
        lastName = "Qualification"
        email = "flowproof-guided-$suffix@example.test"
        password = $n8nOwnerPassword
    }
    if ($ownerSetup -is [string]) {
        throw "n8n owner setup returned a non-JSON response."
    }
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $loginResponse = Invoke-SessionJson "$n8nBaseUrl/rest/login" "POST" $session $null @{
        emailOrLdapLoginId = "flowproof-guided-$suffix@example.test"
        password = $n8nOwnerPassword
    }
    if ($loginResponse -is [string]) {
        throw "n8n login returned a non-JSON response."
    }
    $requiredApiScopes = @(
        "credential:create",
        "credential:delete",
        "credential:list",
        "workflow:activate",
        "workflow:create",
        "workflow:delete",
        "workflow:list"
    )
    $apiKeyBody = @{
        label = "FlowProof guided qualification"
        scopes = $requiredApiScopes
        expiresAt = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()
    } | ConvertTo-Json -Depth 5 -Compress
    $apiKeyWebResponse = Invoke-WebRequest -UseBasicParsing `
        -Uri "$n8nBaseUrl/rest/api-keys" -Method POST -WebSession $session `
        -ContentType "application/json" -Body $apiKeyBody -TimeoutSec 20
    if ([string]::IsNullOrWhiteSpace([string]$apiKeyWebResponse.Content)) {
        throw "n8n API-key creation returned HTTP $($apiKeyWebResponse.StatusCode) with an empty response."
    }
    if ([string]$apiKeyWebResponse.Headers["Content-Type"] -notmatch 'application/json') {
        throw "n8n API-key creation returned a non-JSON response after REST readiness."
    }
    $apiKeyResponse = $apiKeyWebResponse.Content | ConvertFrom-Json
    $apiKeyPayload = $apiKeyResponse
    for ($envelopeDepth = 0; $envelopeDepth -lt 3; $envelopeDepth++) {
        if ($null -ne $apiKeyPayload.PSObject.Properties["rawApiKey"]) { break }
        if ($null -eq $apiKeyPayload.PSObject.Properties["data"]) { break }
        $apiKeyPayload = $apiKeyPayload.data
    }
    if ($null -eq $apiKeyPayload.PSObject.Properties["rawApiKey"] -or
        $null -eq $apiKeyPayload.PSObject.Properties["id"]) {
        $shape = @(Get-PublicPropertyShape $apiKeyResponse) -join ","
        throw "n8n returned an unsupported API-key response envelope (properties: $shape)."
    }
    $n8nApiKeyText = [string]$apiKeyPayload.rawApiKey
    $n8nApiKeyId = [string]$apiKeyPayload.id
    if ([string]::IsNullOrWhiteSpace($n8nApiKeyText)) {
        throw "n8n did not issue the temporary API key."
    }
    $n8nApiKey = ConvertTo-SecureString $n8nApiKeyText -AsPlainText -Force

    $connection = Connect-FlowProofN8n $dataRoot $n8nBaseUrl $n8nApiKey `
        "http://host.docker.internal:8000" -WorkflowRoot $workflowRoot
    $headers = @{ "X-N8N-API-KEY" = $n8nApiKeyText }
    $workflows = Invoke-SessionJson "$n8nBaseUrl/api/v1/workflows?limit=250" "GET" $null $headers $null
    $credentials = Invoke-SessionJson "$n8nBaseUrl/api/v1/credentials?limit=250" "GET" $null $headers $null
    $managed = @($workflows.data | Where-Object { $_.name -like "FlowProof*" })
    $managedCredentials = @($credentials.data | Where-Object {
        $_.name -ceq "FlowProof API service account"
    })
    if ($managed.Count -ne 4 -or @($managed | Where-Object active).Count -ne 3) {
        throw "The guided connection did not create exactly four workflows with three published."
    }
    if ($managedCredentials.Count -ne 1) {
        throw "The guided connection did not create exactly one n8n credential."
    }
    if ($null -ne $managedCredentials[0].PSObject.Properties["data"]) {
        throw "The n8n Public API unexpectedly exposed credential data."
    }

    $invoiceId = "INV-GUIDED-$suffix"
    $webhook = Invoke-SessionJson "$n8nBaseUrl/webhook/invoice-intake" "POST" $null $null @{
        delivery_id = "delivery-$suffix"
        correlation_id = "corr-$suffix"
        invoice = @{
            invoice_id = $invoiceId
            amount = 125.50
            currency = "EUR"
        }
    }
    if ($webhook.status -cne "pending_approval") {
        throw "The published n8n intake workflow did not return its expected response."
    }

    $flowproofSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login = Invoke-SessionJson "http://127.0.0.1:8000/api/v1/auth/login" "POST" `
        $flowproofSession $null @{ name = $adminName; password = $adminPasswordText }
    if ([string]::IsNullOrWhiteSpace([string]$login.csrf_token)) {
        throw "FlowProof login did not return CSRF state."
    }
    $timeline = Invoke-SessionJson (
        "http://127.0.0.1:8000/api/v1/entities/invoice/$invoiceId/timeline"
    ) "GET" $flowproofSession $null $null
    if (@($timeline.items).Count -lt 2 -or
        @($timeline.items | Where-Object { $_.source.system -ceq "n8n" }).Count -lt 2) {
        throw "FlowProof did not preserve the n8n-origin entity timeline."
    }

    $connectionProfile = Get-Content -Raw -Encoding UTF8 (
        Join-Path $dataRoot "n8n-connection.json"
    )
    if ($connectionProfile.Contains($n8nApiKeyText) -or $connectionProfile -match 'Bearer\s+') {
        throw "The secret-free connection profile contained credential material."
    }

    $evidence.flowproof_connection = [ordered]@{
        operation_id = $connection.operation_id
        service_scopes = $connection.service_scopes
        workflow_ids = $connection.workflow_ids
        api_key_persisted_by_flowproof = $connection.api_key_persisted_by_flowproof
        manual_flowproof_token_copying = $connection.manual_flowproof_token_copying
    }
    $evidence.workflow_count = $managed.Count
    $evidence.published_workflow_count = @($managed | Where-Object active).Count
    $evidence.credential_count = $managedCredentials.Count
    $evidence.public_api_exposed_credential_data = $false
    $evidence.timeline_event_count = @($timeline.items).Count
    $evidence.source_system = "n8n"
    $evidence.real_n8n_execution_proven = $true
    $evidence.result = "PASS"
}
catch {
    $caught = $_
    $evidence.result = "FAIL"
    $evidence.blocker = ($_.Exception.Message -replace '(?i)(password|token|authorization|secret|api key)\s*[:=]\s*\S+', '$1=[redacted]')
}
finally {
    $n8nApiKey = $null
    $n8nApiKeyText = $null
    $n8nOwnerPassword = $null
    $n8nEncryptionKey = $null
    $adminPasswordText = $null
    $adminPassword = $null
    if ($containerCreated) {
        & docker rm --force $containerName | Out-Null
        $evidence.cleanup.n8n_container_deleted = $LASTEXITCODE -eq 0
    }
    if ($volumeCreated) {
        & docker volume rm $volumeName | Out-Null
        $evidence.cleanup.n8n_volume_deleted = $LASTEXITCODE -eq 0
    }
    if ($installed -or [IO.Directory]::Exists($dataRoot)) {
        try {
            Uninstall-FlowProofAppliance $dataRoot -DeleteData `
                -DataDeletionConfirmation "DELETE FLOWPROOF DATA" | Out-Null
            $evidence.cleanup.appliance_data_deleted = -not [IO.Directory]::Exists($dataRoot)
        }
        catch { }
    }
    $evidence.completed_at = [DateTime]::UtcNow.ToString('o')
    Write-Evidence $evidence
}

if ($null -ne $caught) { throw $caught }
