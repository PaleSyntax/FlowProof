Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ModuleRoot = Split-Path -Parent $PSCommandPath
$script:RuntimeModule = Join-Path $script:ModuleRoot "FlowProof.Runtime.psm1"
Import-Module $script:RuntimeModule

$script:ManagedWorkflowNames = @(
    "FlowProof Technical Error Handler",
    "FlowProof Invoice Intake",
    "FlowProof Invoice Approval",
    "FlowProof Approved Invoice Recovery"
)
$script:PublishedWorkflowNames = @(
    "FlowProof Invoice Intake",
    "FlowProof Invoice Approval",
    "FlowProof Approved Invoice Recovery"
)
$script:ServiceScopes = @(
    "events:write",
    "recovery:execute",
    "recovery:verify"
)

function Resolve-FlowProofConnectionUrl {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][ValidateSet("n8n", "flowproof")][string]$Purpose
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Value.Trim(), [UriKind]::Absolute, [ref]$uri)) {
        throw "$Purpose URL must be an absolute HTTP or HTTPS URL."
    }
    if ($uri.Scheme -notin @("http", "https") -or
        -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        -not [string]::IsNullOrWhiteSpace($uri.Fragment)) {
        throw "$Purpose URL must not contain credentials, query parameters or fragments."
    }

    $localHttpHosts = @("127.0.0.1", "localhost", "host.docker.internal", "api")
    if ($uri.Scheme -eq "http" -and $uri.Host.ToLowerInvariant() -notin $localHttpHosts) {
        throw "$Purpose must use HTTPS unless it is a local-only address."
    }
    return $uri.AbsoluteUri.TrimEnd('/')
}

function Invoke-FlowProofN8nRequest {
    param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][Security.SecureString]$ApiKey,
        [Parameter(Mandatory)][ValidateSet("GET", "POST", "DELETE")][string]$Method,
        [Parameter(Mandatory)][ValidatePattern('^/')][string]$Path,
        [object]$Body
    )

    $pointer = [IntPtr]::Zero
    $plainApiKey = $null
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
        $plainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ([string]::IsNullOrWhiteSpace($plainApiKey)) {
            throw "n8n API key is required."
        }
        $parameters = @{
            Uri = "$BaseUrl/api/v1$Path"
            Method = $Method
            Headers = @{ "X-N8N-API-KEY" = $plainApiKey }
            TimeoutSec = 20
            MaximumRedirection = 0
            UseBasicParsing = $true
        }
        if ($null -ne $Body) {
            $parameters.ContentType = "application/json"
            $parameters.Body = $Body | ConvertTo-Json -Depth 30 -Compress
        }
        return Invoke-RestMethod @parameters
    }
    catch {
        if ($_.Exception.Message -eq "n8n API key is required.") { throw }
        $status = $null
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        $statusText = $(if ($null -eq $status) { "connection error" } else { "HTTP $status" })
        throw "n8n API request failed ($Method $Path): $statusText. Check the URL, API key scopes and n8n availability."
    }
    finally {
        $plainApiKey = $null
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Test-FlowProofN8nConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$N8nBaseUrl,
        [Parameter(Mandatory)][Security.SecureString]$N8nApiKey
    )

    $baseUrl = Resolve-FlowProofConnectionUrl $N8nBaseUrl "n8n"
    $response = Invoke-FlowProofN8nRequest $baseUrl $N8nApiKey "GET" "/workflows?limit=1"
    if ($null -eq $response -or $null -eq $response.data) {
        throw "n8n API returned an unexpected workflow-list response."
    }
    return [pscustomobject]@{
        Ready = $true
        BaseUrl = $baseUrl
        Authentication = "X-N8N-API-KEY accepted"
    }
}

function New-FlowProofServiceIssue {
    param([Parameter(Mandatory)][string]$DataRoot, [Parameter(Mandatory)][string]$OperationId)

    $createArguments = @(
        "exec", "-T", "api", "python", "-m", "flowproof.identity",
        "create-service-account", "--name", "n8n-flowproof"
    )
    foreach ($scope in $script:ServiceScopes) { $createArguments += @("--scope", $scope) }
    $createdRaw = @(Invoke-FlowProofCompose $DataRoot $createArguments)
    $created = ($createdRaw | Select-Object -Last 1).ToString() | ConvertFrom-Json
    if ($created.principal.kind -cne "service" -or
        (@($created.principal.allowed_scopes | Sort-Object) -join ',') -cne
        (@($script:ServiceScopes | Sort-Object) -join ',')) {
        throw "The existing n8n-flowproof principal does not match the fixed service scope envelope."
    }

    $issueArguments = @(
        "exec", "-T", "api", "python", "-m", "flowproof.identity",
        "issue-token", "--principal-id", [string]$created.principal.id,
        "--label", "n8n-guided-provision", "--operation-id", $OperationId
    )
    foreach ($scope in $script:ServiceScopes) { $issueArguments += @("--scope", $scope) }
    $issuedRaw = @(Invoke-FlowProofCompose $DataRoot $issueArguments)
    $issued = ($issuedRaw | Select-Object -Last 1).ToString() | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$issued.token) -or
        [string]::IsNullOrWhiteSpace([string]$issued.credential_id)) {
        throw "FlowProof did not issue a usable least-privilege n8n credential."
    }
    return $issued
}

function ConvertTo-FlowProofN8nWorkflow {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$FlowProofApiUrl,
        [Parameter(Mandatory)][string]$CredentialId
    )

    $raw = [IO.File]::ReadAllText($Path)
    $workflow = ($raw.Replace("http://api:8000", $FlowProofApiUrl) | ConvertFrom-Json)
    foreach ($node in @($workflow.nodes)) {
        if ($null -ne $node.PSObject.Properties["credentials"] -and
            $null -ne $node.credentials.PSObject.Properties["httpHeaderAuth"]) {
            $node.credentials.httpHeaderAuth.id = $CredentialId
            $node.credentials.httpHeaderAuth.name = "FlowProof API service account"
        }
    }
    $body = [ordered]@{
        name = [string]$workflow.name
        nodes = $workflow.nodes
        connections = $workflow.connections
        settings = $workflow.settings
    }
    foreach ($optional in @("staticData", "pinData")) {
        if ($null -ne $workflow.PSObject.Properties[$optional]) {
            $body[$optional] = $workflow.$optional
        }
    }
    return $body
}

function Connect-FlowProofN8n {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$N8nBaseUrl,
        [Parameter(Mandatory)][Security.SecureString]$N8nApiKey,
        [Parameter(Mandatory)][string]$FlowProofApiUrl,
        [string]$WorkflowRoot = (Join-Path $script:ModuleRoot "n8n-workflows")
    )

    $layout = Get-FlowProofLayout $DataRoot
    $connectionPath = Join-Path $layout.Root "n8n-connection.json"
    if ([IO.File]::Exists($connectionPath)) {
        throw "This appliance already has a completed n8n connection profile."
    }
    $status = Get-FlowProofStatus $layout.Root
    if ($status.ServiceHealth -cne "READY") {
        throw "FlowProof must be READY before connecting n8n."
    }
    $n8nUrl = Resolve-FlowProofConnectionUrl $N8nBaseUrl "n8n"
    $flowproofUrl = Resolve-FlowProofConnectionUrl $FlowProofApiUrl "flowproof"
    Test-FlowProofN8nConnection $n8nUrl $N8nApiKey | Out-Null

    $workflowFiles = @(Get-ChildItem -LiteralPath $WorkflowRoot -Filter "*.json" -File)
    if ($workflowFiles.Count -ne 4) {
        throw "The candidate must contain exactly four managed n8n workflow templates."
    }
    $existing = Invoke-FlowProofN8nRequest $n8nUrl $N8nApiKey "GET" "/workflows?limit=250"
    $collisions = @($existing.data | Where-Object { $_.name -cin $script:ManagedWorkflowNames })
    if ($collisions.Count -ne 0) {
        throw "n8n already contains a FlowProof-managed workflow. Remove the old guided connection before provisioning again."
    }

    $operationId = [guid]::NewGuid().ToString()
    $flowproofCredentialId = $null
    $serviceToken = $null
    $n8nCredentialId = $null
    $createdWorkflows = New-Object Collections.Generic.List[object]
    try {
        $issued = New-FlowProofServiceIssue $layout.Root $operationId
        $flowproofCredentialId = [string]$issued.credential_id
        $serviceToken = [string]$issued.token

        $n8nCredential = Invoke-FlowProofN8nRequest $n8nUrl $N8nApiKey "POST" "/credentials" @{
            name = "FlowProof API service account"
            type = "httpHeaderAuth"
            data = @{
                name = "Authorization"
                value = "Bearer $serviceToken"
            }
        }
        $n8nCredentialId = [string]$n8nCredential.id
        if ([string]::IsNullOrWhiteSpace($n8nCredentialId)) {
            throw "n8n did not return the created credential identifier."
        }
        $serviceToken = $null

        foreach ($file in $workflowFiles | Sort-Object Name) {
            $body = ConvertTo-FlowProofN8nWorkflow $file.FullName $flowproofUrl $n8nCredentialId
            if ([string]$body.name -cnotin $script:ManagedWorkflowNames) {
                throw "Unexpected workflow template name: $($body.name)"
            }
            $created = Invoke-FlowProofN8nRequest $n8nUrl $N8nApiKey "POST" "/workflows" $body
            $createdWorkflows.Add($created)
        }
        foreach ($workflow in $createdWorkflows) {
            if ([string]$workflow.name -cin $script:PublishedWorkflowNames) {
                Invoke-FlowProofN8nRequest $n8nUrl $N8nApiKey "POST" (
                    "/workflows/$($workflow.id)/activate"
                ) @{ versionId = [string]$workflow.versionId } | Out-Null
            }
        }

        $profile = [ordered]@{
            schema_version = "1.0"
            connected_at = [DateTime]::UtcNow.ToString('o')
            operation_id = $operationId
            n8n_base_url = $n8nUrl
            flowproof_api_url = $flowproofUrl
            n8n_credential_id = $n8nCredentialId
            flowproof_credential_id = $flowproofCredentialId
            workflow_ids = @($createdWorkflows | ForEach-Object { [string]$_.id })
            published_workflow_count = $script:PublishedWorkflowNames.Count
            api_key_persisted_by_flowproof = $false
            manual_flowproof_token_copying = $false
            service_scopes = $script:ServiceScopes
        }
        $encoding = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText(
            $connectionPath,
            (($profile | ConvertTo-Json -Depth 8) + "`n"),
            $encoding
        )
        return [pscustomobject]$profile
    }
    catch {
        $cleanupWorkflows = $createdWorkflows.ToArray()
        [array]::Reverse($cleanupWorkflows)
        foreach ($workflow in $cleanupWorkflows) {
            try {
                Invoke-FlowProofN8nRequest $n8nUrl $N8nApiKey "DELETE" (
                    "/workflows/$($workflow.id)"
                ) | Out-Null
            }
            catch { }
        }
        if (-not [string]::IsNullOrWhiteSpace($n8nCredentialId)) {
            try {
                Invoke-FlowProofN8nRequest $n8nUrl $N8nApiKey "DELETE" (
                    "/credentials/$n8nCredentialId"
                ) | Out-Null
            }
            catch { }
        }
        if (-not [string]::IsNullOrWhiteSpace($flowproofCredentialId)) {
            try {
                Invoke-FlowProofCompose $layout.Root @(
                    "exec", "-T", "api", "python", "-m", "flowproof.identity",
                    "revoke-token", "--credential-id", $flowproofCredentialId
                ) | Out-Null
            }
            catch { }
        }
        throw
    }
    finally {
        $serviceToken = $null
        $issued = $null
    }
}

Export-ModuleMember -Function @(
    "Test-FlowProofN8nConnection",
    "Connect-FlowProofN8n"
)
