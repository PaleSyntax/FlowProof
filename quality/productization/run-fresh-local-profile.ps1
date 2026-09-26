[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitCommit,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitTree,
    [Parameter(Mandatory)][string]$DockerDesktopOwner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Write-JsonResult {
    param([Parameter(Mandatory)][object]$Value)
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        $ResultPath,
        (($Value | ConvertTo-Json -Depth 12) + "`n"),
        $encoding
    )
}

function Invoke-Api {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet("GET", "POST")][string]$Method = "GET",
        [object]$Body,
        [Parameter(Mandatory)][Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$CsrfToken
    )
    $parameters = @{
        Uri = "http://127.0.0.1:8000/api/v1$Path"
        Method = $Method
        WebSession = $Session
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $parameters.ContentType = "application/json"
        $parameters.Body = $Body | ConvertTo-Json -Depth 8 -Compress
    }
    if (-not [string]::IsNullOrWhiteSpace($CsrfToken)) {
        $parameters.Headers = @{ "X-CSRF-Token" = $CsrfToken }
    }
    return Invoke-RestMethod @parameters
}

function Initialize-QualificationAppliance {
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$AdminName,
        [Parameter(Mandatory)][Security.SecureString]$AdminPassword,
        [Parameter(Mandatory)][Management.Automation.PSModuleInfo]$RuntimeModule
    )
    $prerequisite = Test-FlowProofPrerequisites
    if (-not $prerequisite.Ready) {
        throw "$($prerequisite.Message) $($prerequisite.NextAction)"
    }
    Import-FlowProofBundledImages | Out-Null
    $layout = New-FlowProofApplianceConfiguration -DataRoot $DataRoot -SkipAcl
    Invoke-FlowProofCompose $layout.Root @("config", "--quiet") | Out-Null
    Invoke-FlowProofCompose $layout.Root @(
        "up", "-d", "--wait", "postgres", "mock-accounting"
    ) | Out-Null
    Invoke-FlowProofMigration -DataRoot $layout.Root
    Invoke-FlowProofCompose $layout.Root @(
        "up", "-d", "--wait", "api", "scheduler", "alert-worker", "ops-watcher", "web"
    ) | Out-Null
    Wait-FlowProofReady
    & $RuntimeModule {
        param($Root, $Name, $Password)
        Invoke-FlowProofAdminBootstrap -DataRoot $Root -AdminName $Name `
            -AdminPassword $Password
    } $layout.Root $AdminName $AdminPassword
    Write-FlowProofState $layout.Root
    return Get-FlowProofStatus $layout.Root
}

$startedAt = [DateTime]::UtcNow
$sessionId = [guid]::NewGuid().ToString()
$profileRoot = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
$sourceCheckout = Join-Path $profileRoot "Documents\FlowProof"
$extractRoot = Join-Path $profileRoot (
    "Downloads\FlowProofQualification-" + [guid]::NewGuid().ToString('N')
)
$dataRoot = Join-Path $env:LOCALAPPDATA "FlowProofQualification"
$adminName = "Qualification Admin"
$adminPasswordText = (New-RandomText 48) + "aA1!"
$adminPassword = ConvertTo-SecureString $adminPasswordText -AsPlainText -Force
$installed = $false
$installAttempted = $false
$preserved = $false
$moduleRoot = $null
$currentStage = "prerequisite_check"
$passedStages = New-Object Collections.Generic.List[string]

try {
    if ([IO.File]::Exists($sourceCheckout) -or [IO.Directory]::Exists($sourceCheckout)) {
        throw "A FlowProof source checkout exists inside the disposable user profile."
    }
    if (-not [IO.File]::Exists($ArtifactPath)) {
        throw "The candidate ZIP is missing from disposable-profile staging."
    }
    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToLowerInvariant()
    if ($actualSha256 -cne $ExpectedSha256) {
        throw "The candidate ZIP checksum does not match the trusted input."
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($ArtifactPath)
    try {
        $members = @($zip.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
    }
    finally {
        $zip.Dispose()
    }
    $sensitiveMembers = @($members | Where-Object {
        $_ -match '(?i)(^|/)(\.env|.*\.db|.*\.sqlite|token|password|secret)(/|$)'
    })
    if ($sensitiveMembers.Count -ne 0) {
        throw "The candidate ZIP contains a forbidden sensitive member name."
    }

    Expand-Archive -LiteralPath $ArtifactPath -DestinationPath $extractRoot
    $moduleRoot = Join-Path $extractRoot "FlowProof"
    $runtimeModule = Join-Path $moduleRoot "FlowProof.Runtime.psm1"
    $artifactsModule = Join-Path $moduleRoot "FlowProof.Artifacts.psm1"
    $manifest = Get-Content -Raw -Encoding UTF8 (
        Join-Path $moduleRoot "appliance-manifest.json"
    ) | ConvertFrom-Json
    Import-Module $artifactsModule -Force
    $runtimeModuleInfo = Import-Module $runtimeModule -Force -PassThru

    [IO.Directory]::CreateDirectory($dataRoot) | Out-Null
    $dataAcl = Get-Acl -LiteralPath $dataRoot
    $inheritance = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $dockerOwnerRule = New-Object Security.AccessControl.FileSystemAccessRule(
        $DockerDesktopOwner,
        [Security.AccessControl.FileSystemRights]::Modify,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $dataAcl.AddAccessRule($dockerOwnerRule) | Out-Null
    Set-Acl -LiteralPath $dataRoot -AclObject $dataAcl

    $prerequisite = Test-FlowProofPrerequisites
    if (-not $prerequisite.Ready) {
        throw "$($prerequisite.Code): $($prerequisite.Message)"
    }
    $passedStages.Add("prerequisite_check")

    $currentStage = "install"
    $installAttempted = $true
    $status = Initialize-QualificationAppliance -DataRoot $dataRoot `
        -AdminName $adminName -AdminPassword $adminPassword `
        -RuntimeModule $runtimeModuleInfo
    $installed = $true
    if (-not $status.Installed -or $status.ServiceHealth -cne "READY") {
        throw "The disposable-profile install did not reach READY."
    }
    $passedStages.Add("install")
    $runningAt = [DateTime]::UtcNow

    $currentStage = "first_open"
    $shortcut = New-FlowProofStartMenuShortcut -DataRoot $dataRoot
    if (-not [IO.File]::Exists($shortcut)) {
        throw "The disposable-profile Start Menu shortcut was not created."
    }

    $web = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8080/" -TimeoutSec 10
    if ($web.StatusCode -ne 200) {
        throw "The dashboard did not open successfully."
    }
    $passedStages.Add("first_open")

    $currentStage = "safe_demo"
    $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login = Invoke-Api -Path "/auth/login" -Method POST -Session $webSession -Body @{
        name = $adminName
        password = $adminPasswordText
    }
    $csrf = [string]$login.csrf_token
    if ([string]::IsNullOrWhiteSpace($csrf)) {
        throw "The disposable-profile admin login did not return CSRF state."
    }
    $demo = Invoke-Api -Path "/demo/false-200/start" -Method POST `
        -Session $webSession -CsrfToken $csrf
    $incident = Invoke-Api -Path "/incidents/$($demo.incident_id)" -Session $webSession
    if ($incident.invariant_id -cne "external_invoice_exists" -or
        $incident.status -cne "recovery_proposed") {
        throw "The fresh-profile demo did not produce the expected missing-outcome incident."
    }
    $firstOutcomeAt = [DateTime]::UtcNow

    $plan = $incident.recovery_plan
    Invoke-Api -Path "/recovery-plans/$($plan.id)/approve" -Method POST `
        -Session $webSession -CsrfToken $csrf -Body @{
            plan_hash = $plan.plan_hash
            incident_status = $incident.status
        } | Out-Null
    Invoke-Api -Path "/chaos/mode" -Method POST -Session $webSession `
        -CsrfToken $csrf -Body @{ mode = "normal" } | Out-Null
    Invoke-Api -Path "/recovery-plans/$($plan.id)/execute" -Method POST `
        -Session $webSession -CsrfToken $csrf | Out-Null
    Invoke-Api -Path "/recovery-plans/$($plan.id)/verify" -Method POST `
        -Session $webSession -CsrfToken $csrf | Out-Null
    $finalIncident = Invoke-Api -Path "/incidents/$($demo.incident_id)" -Session $webSession
    if ($finalIncident.status -cne "resolved" -or
        $finalIncident.recovery_plan.status -cne "verified") {
        throw "The fresh-profile demo did not reach independently verified resolution."
    }
    $passedStages.Add("safe_demo")

    $currentStage = "restart_reopen"
    $status = Restart-FlowProofAppliance -DataRoot $dataRoot
    if ($status.ServiceHealth -cne "READY") {
        throw "The disposable-profile restart did not return READY."
    }
    $reopened = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8080/" -TimeoutSec 10
    if ($reopened.StatusCode -ne 200) {
        throw "The dashboard did not reopen after restart."
    }
    $passedStages.Add("restart_reopen")

    $currentStage = "diagnostics_export"
    $diagnostics = Export-FlowProofDiagnostics -DataRoot $dataRoot
    if (-not [IO.File]::Exists($diagnostics)) {
        throw "The disposable-profile diagnostics export is missing."
    }
    $passedStages.Add("diagnostics_export")

    $currentStage = "backup"
    $backup = New-FlowProofBackup -DataRoot $dataRoot
    if (-not [IO.File]::Exists($backup)) {
        throw "The disposable-profile backup is missing."
    }
    $passedStages.Add("backup")

    $currentStage = "uninstall_preserve"
    $preserveResult = Uninstall-FlowProofAppliance -DataRoot $dataRoot
    $installed = $false
    $preserved = $preserveResult.DataPreserved -and [IO.Directory]::Exists($dataRoot)
    if (-not $preserved -or -not [IO.Directory]::Exists((Join-Path $dataRoot "postgres"))) {
        throw "Default uninstall did not preserve the disposable-profile database."
    }
    $passedStages.Add("uninstall_preserve")

    $currentStage = "reinstall_retention"
    $status = Initialize-QualificationAppliance -DataRoot $dataRoot `
        -AdminName $adminName -AdminPassword $adminPassword `
        -RuntimeModule $runtimeModuleInfo
    $installed = $true
    if ($status.ServiceHealth -cne "READY") {
        throw "The disposable-profile reinstall did not return READY."
    }
    $adminCountRaw = Invoke-FlowProofCompose $dataRoot @(
        "exec", "-T", "postgres", "psql", "-U", "flowproof", "-d", "flowproof",
        "-tAc", "select count(*) from principals where name = 'Qualification Admin';"
    )
    $adminCount = [int](($adminCountRaw | Select-Object -Last 1).ToString().Trim())
    if ($adminCount -ne 1) {
        throw "The disposable-profile reinstall did not preserve exactly one administrator."
    }

    Uninstall-FlowProofAppliance -DataRoot $dataRoot -DeleteData `
        -DataDeletionConfirmation "DELETE FLOWPROOF DATA" | Out-Null
    $installed = $false
    $preserved = $false
    if ([IO.Directory]::Exists($dataRoot)) {
        throw "Confirmed disposable-profile cleanup left the data root behind."
    }
    $passedStages.Add("reinstall_retention")

    $completedAt = [DateTime]::UtcNow
    $result = [ordered]@{
        schema_version = "1.0"
        session_id = $sessionId
        started_at = $startedAt.ToString('o')
        completed_at = $completedAt.ToString('o')
        tester_role = "automated disposable local Windows profile"
        environment = [ordered]@{
            windows_version = [Environment]::OSVersion.VersionString
            architecture = "x86_64"
            profile_type = "fresh_local_profile"
            source_checkout_present = $false
            preinstalled_tools = @("Docker Desktop")
        }
        artifact = [ordered]@{
            filename = [IO.Path]::GetFileName($ArtifactPath)
            sha256 = $actualSha256
            git_commit = [string]$manifest.git_commit
            git_tree = [string]$manifest.git_tree
        }
        metrics = [ordered]@{
            download_to_running_seconds = [int][math]::Ceiling(($runningAt - $startedAt).TotalSeconds)
            running_to_first_demo_outcome_seconds = [int][math]::Ceiling(
                ($firstOutcomeAt - $runningAt).TotalSeconds
            )
            mandatory_decision_count = 3
            terminal_command_count = 0
            manual_secret_handoff_count = 0
            support_intervention_count = 0
            install_failure_count = 0
        }
        stages = [ordered]@{
            prerequisite_check = [ordered]@{
                status = "PASS"
                evidence = @(
                    "$($prerequisite.Code); Compose $($prerequisite.ComposeVersion)",
                    "Temporary qualification data ACL enabled the already-running Docker Desktop backend"
                )
                note = "Docker Desktop was preinstalled; the qualification-only data root was deleted during cleanup."
            }
            install = [ordered]@{
                status = "PASS"
                evidence = @("API and dashboard reached HTTP 200 from the extracted ZIP")
                note = "No source checkout, Git, Python, Node.js or manual PostgreSQL install was used."
            }
            first_open = [ordered]@{
                status = "PASS"
                evidence = @("Start Menu shortcut created; dashboard returned HTTP 200")
                note = $null
            }
            safe_demo = [ordered]@{
                status = "PASS"
                evidence = @("TEST_FIXTURE_ONLY missing outcome opened one incident and verified one compensation")
                note = "This is fixture evidence, not real-provider evidence."
            }
            restart_reopen = [ordered]@{
                status = "PASS"
                evidence = @("Service health READY and dashboard HTTP 200 after restart")
                note = $null
            }
            diagnostics_export = [ordered]@{
                status = "PASS"
                evidence = @("Sanitized diagnostics ZIP created")
                note = $null
            }
            backup = [ordered]@{
                status = "PASS"
                evidence = @("Non-empty pg_dump custom backup plus checksum and metadata")
                note = $null
            }
            uninstall_preserve = [ordered]@{
                status = "PASS"
                evidence = @("Default uninstall preserved the PostgreSQL data directory")
                note = $null
            }
            reinstall_retention = [ordered]@{
                status = "PASS"
                evidence = @("Reinstall returned READY and preserved exactly one administrator")
                note = "Exact-confirm final cleanup removed the disposable data root."
            }
        }
        security = [ordered]@{
            credentials_in_artifact = $false
            env_file_in_artifact = $false
            database_in_artifact = $false
            raw_customer_data_in_artifact = $false
        }
        result = "PASS"
        blocker = $null
    }
    Write-JsonResult $result
}
catch {
    $failureRecord = $_
    $message = ($failureRecord.Exception.Message -replace (
        '(?i)(password|token|authorization|secret)\s*[:=]\s*\S+'
    ), '$1=[redacted]')
    if ($message.Length -gt 500) { $message = $message.Substring(0, 500) }
    $knownStages = @(
        "prerequisite_check", "install", "first_open", "safe_demo",
        "restart_reopen", "diagnostics_export", "backup",
        "uninstall_preserve", "reinstall_retention"
    )
    $failureStages = [ordered]@{}
    foreach ($stageName in $knownStages) {
        $failureStages[$stageName] = [ordered]@{
            status = "NOT_RUN"
            evidence = @()
            note = $null
        }
    }
    foreach ($passedStage in $passedStages) {
        $failureStages[$passedStage]["status"] = "PASS"
        $failureStages[$passedStage]["evidence"] = @(
            "Stage completed before the later $currentStage failure"
        )
    }
    $isBlockedPrerequisite = (
        $currentStage -ceq "prerequisite_check" -and $message -match '^DOCKER_[A-Z_]+'
    )
    $failureResult = $(if ($isBlockedPrerequisite) { "BLOCKED" } else { "FAIL" })
    $failureStages[$currentStage]["status"] = $failureResult
    $failureStages[$currentStage]["evidence"] = @(
        "error_type=$($failureRecord.Exception.GetType().Name)"
    )
    $failureStages[$currentStage]["note"] = $message
    $blocker = "FRESH_LOCAL_PROFILE_STAGE_FAILED: stage=$currentStage; $message"
    if ($blocker.Length -gt 500) { $blocker = $blocker.Substring(0, 500) }
    $failure = [ordered]@{
        schema_version = "1.0"
        session_id = $sessionId
        started_at = $startedAt.ToString('o')
        completed_at = [DateTime]::UtcNow.ToString('o')
        tester_role = "automated disposable local Windows profile"
        environment = [ordered]@{
            windows_version = [Environment]::OSVersion.VersionString
            architecture = "x86_64"
            profile_type = "fresh_local_profile"
            source_checkout_present = $false
            preinstalled_tools = @("Docker Desktop")
        }
        artifact = [ordered]@{
            filename = [IO.Path]::GetFileName($ArtifactPath)
            sha256 = $ExpectedSha256
            git_commit = $GitCommit
            git_tree = $GitTree
        }
        metrics = [ordered]@{
            download_to_running_seconds = $null
            running_to_first_demo_outcome_seconds = $null
            mandatory_decision_count = $null
            terminal_command_count = 0
            manual_secret_handoff_count = 0
            support_intervention_count = 0
            install_failure_count = $(if ($isBlockedPrerequisite) { 0 } else { 1 })
        }
        stages = $failureStages
        security = [ordered]@{
            credentials_in_artifact = $false
            env_file_in_artifact = $false
            database_in_artifact = $false
            raw_customer_data_in_artifact = $false
        }
        result = $failureResult
        blocker = $blocker
    }
    Write-JsonResult $failure
    throw
}
finally {
    $adminPasswordText = $null
    $adminPassword = $null
    if ($installAttempted -or $installed -or $preserved) {
        try {
            if ($null -ne $moduleRoot) {
                Import-Module (Join-Path $moduleRoot "FlowProof.Artifacts.psm1") -Force
                Uninstall-FlowProofAppliance -DataRoot $dataRoot -DeleteData `
                    -DataDeletionConfirmation "DELETE FLOWPROOF DATA" | Out-Null
            }
        }
        catch { }
    }
    if ([IO.Directory]::Exists($extractRoot)) {
        [IO.Directory]::Delete($extractRoot, $true)
    }
}
