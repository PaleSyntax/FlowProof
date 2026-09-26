[CmdletBinding()]
param(
    [string]$DataRoot = (Join-Path ([IO.Path]::GetTempPath()) (
        "flowproof-appliance-runtime-" + [guid]::NewGuid().ToString("N")
    )),
    [string]$ApplianceRoot,
    [string]$ArtifactPath,
    [string]$ArtifactSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($ApplianceRoot)) {
    $ApplianceRoot = Join-Path $repositoryRoot "productization\windows"
}
$resolvedApplianceRoot = (Resolve-Path $ApplianceRoot).Path
$runtimeModule = Join-Path $resolvedApplianceRoot "FlowProof.Runtime.psm1"
$artifactsModule = Join-Path $resolvedApplianceRoot "FlowProof.Artifacts.psm1"
$resolvedParent = [IO.Path]::GetFullPath((Split-Path -Parent $DataRoot)).TrimEnd('\')
$expectedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$leaf = Split-Path -Leaf $DataRoot
if ($resolvedParent -cne $expectedParent -or $leaf -notmatch '^flowproof-appliance-runtime-[a-f0-9]{32}$') {
    throw "Lifecycle proof only accepts a fresh, GUID-suffixed FlowProof folder in the OS temp directory."
}
if ([IO.Directory]::Exists($DataRoot) -or [IO.File]::Exists($DataRoot)) {
    throw "Lifecycle proof data root already exists: $DataRoot"
}

Import-Module $artifactsModule -Force
Import-Module $runtimeModule -Force

$startedAt = (Get-Date).ToUniversalTime()
$programsRoot = Join-Path $DataRoot "test-start-menu"
$passwordText = (New-FlowProofRandomSecret -ByteCount 48) + "aA1!"
$adminPassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
$passwordText = $null
$result = [ordered]@{
    schema_version = "1.0"
    evidence_scope = $(if ([string]::IsNullOrWhiteSpace($ArtifactPath)) {
        "CURRENT_HOST_LIFECYCLE_ONLY"
    } else {
        "EXTRACTED_CANDIDATE_CURRENT_HOST_LIFECYCLE"
    })
    clean_machine_proof = $false
    source_checkout_used_for_runtime = $resolvedApplianceRoot.StartsWith(
        $repositoryRoot, [StringComparison]::OrdinalIgnoreCase
    )
    artifact = $(if ([string]::IsNullOrWhiteSpace($ArtifactPath)) { $null } else {
        [ordered]@{
            path = [IO.Path]::GetFullPath($ArtifactPath).Replace('\', '/')
            sha256 = $ArtifactSha256
        }
    })
    data_root = $DataRoot.Replace('\', '/')
    started_at = $startedAt.ToString('o')
    stages = @()
}
$completed = $false

function Add-Stage {
    param([string]$Name, [string]$Status, [hashtable]$Evidence)
    $script:result.stages += [ordered]@{
        name = $Name
        status = $Status
        checked_at = (Get-Date).ToUniversalTime().ToString('o')
        evidence = $Evidence
    }
}

function Assert-Ready {
    param([object]$Status, [string]$Stage)
    if (-not $Status.Installed -or $Status.ServiceHealth -cne "READY") {
        throw "$Stage did not produce an installed READY appliance."
    }
}

function Get-AdminCount {
    $raw = Invoke-FlowProofCompose $DataRoot @(
        "exec", "-T", "postgres", "psql", "-U", "flowproof", "-d", "flowproof",
        "-tAc", "select count(*) from principals where name = 'Productization Admin';"
    )
    return [int](($raw | Select-Object -Last 1).ToString().Trim())
}

try {
    $status = Initialize-FlowProofAppliance -DataRoot $DataRoot `
        -AdminName "Productization Admin" -AdminPassword $adminPassword
    Assert-Ready $status "initial install"
    $ready = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/health/ready" -TimeoutSec 10
    $web = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8080/" -TimeoutSec 10
    $adminCount = Get-AdminCount
    if ($ready.StatusCode -ne 200 -or $web.StatusCode -ne 200 -or $adminCount -ne 1) {
        throw "Initial HTTP or persisted-admin assertion failed."
    }
    Add-Stage "install_and_readiness" "PASS" @{
        api_http_status = $ready.StatusCode
        web_http_status = $web.StatusCode
        persisted_admin_count = $adminCount
    }

    $shortcut = New-FlowProofStartMenuShortcut -DataRoot $DataRoot -ProgramsRoot $programsRoot
    if (-not [IO.File]::Exists($shortcut)) { throw "Shortcut was not created." }
    Add-Stage "launcher_shortcut" "PASS" @{ shortcut_created = $true; isolated_programs_root = $true }

    $backup = New-FlowProofBackup -DataRoot $DataRoot
    $backupStem = Join-Path ([IO.Path]::GetDirectoryName($backup)) (
        [IO.Path]::GetFileNameWithoutExtension($backup)
    )
    if (-not [IO.File]::Exists($backup) -or
        -not [IO.File]::Exists("$backupStem.sha256") -or
        -not [IO.File]::Exists("$backupStem.json")) {
        throw "Backup sidecar set is incomplete."
    }
    Add-Stage "backup" "PASS" @{
        non_empty = ((Get-Item -LiteralPath $backup).Length -gt 0)
        sha256_sidecar = $true
        metadata_sidecar = $true
    }

    $diagnostics = Export-FlowProofDiagnostics -DataRoot $DataRoot
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($diagnostics)
    try {
        $members = @($zip.Entries | ForEach-Object { $_.FullName })
    }
    finally {
        $zip.Dispose()
    }
    foreach ($required in @("prerequisites.json", "service-status.json", "readiness.json", "appliance-manifest.json", "appliance-state.json")) {
        if ($members -notcontains $required) { throw "Diagnostics archive is missing $required." }
    }
    Add-Stage "sanitized_diagnostics" "PASS" @{
        required_members = $members
        exact_generated_secret_scan = "PASS"
    }

    $status = Restart-FlowProofAppliance -DataRoot $DataRoot
    Assert-Ready $status "restart"
    Add-Stage "restart" "PASS" @{ service_health = $status.ServiceHealth }

    $stopped = Stop-FlowProofAppliance -DataRoot $DataRoot
    if ($stopped.ServiceHealth -cne "NOT_READY") { throw "Stop did not report NOT_READY." }
    $status = Start-FlowProofAppliance -DataRoot $DataRoot
    Assert-Ready $status "stop/start"
    Add-Stage "stop_start" "PASS" @{
        stopped_health = $stopped.ServiceHealth
        started_health = $status.ServiceHealth
    }

    $preserved = Uninstall-FlowProofAppliance -DataRoot $DataRoot -ProgramsRoot $programsRoot
    if (-not $preserved.DataPreserved -or -not [IO.Directory]::Exists($DataRoot) -or
        -not [IO.Directory]::Exists((Join-Path $DataRoot "postgres"))) {
        throw "Default uninstall did not preserve the data root."
    }
    $status = Initialize-FlowProofAppliance -DataRoot $DataRoot `
        -AdminName "Productization Admin" -AdminPassword $adminPassword
    Assert-Ready $status "reinstall"
    $adminCountAfter = Get-AdminCount
    if ($adminCountAfter -ne 1) { throw "Reinstall did not preserve the administrator record." }
    Add-Stage "uninstall_preserve_and_reinstall" "PASS" @{
        data_preserved = $true
        persisted_admin_count_before = $adminCount
        persisted_admin_count_after = $adminCountAfter
    }

    $deleted = Uninstall-FlowProofAppliance -DataRoot $DataRoot -DeleteData `
        -DataDeletionConfirmation "DELETE FLOWPROOF DATA" -ProgramsRoot $programsRoot
    if ($deleted.DataPreserved -or [IO.Directory]::Exists($DataRoot)) {
        throw "Confirmed full deletion left the test data root behind."
    }
    Add-Stage "confirmed_full_delete" "PASS" @{ data_root_absent = $true }
    $completed = $true
}
finally {
    $adminPassword = $null
    if (-not $completed -and [IO.Directory]::Exists($DataRoot)) {
        try {
            Uninstall-FlowProofAppliance -DataRoot $DataRoot -DeleteData `
                -DataDeletionConfirmation "DELETE FLOWPROOF DATA" -ProgramsRoot $programsRoot | Out-Null
        }
        catch {
            try { Invoke-FlowProofCompose $DataRoot @("down", "--remove-orphans") | Out-Null } catch { }
            if ([IO.Directory]::Exists($DataRoot)) { [IO.Directory]::Delete($DataRoot, $true) }
        }
    }
}

$result.completed_at = (Get-Date).ToUniversalTime().ToString('o')
$result.duration_seconds = [math]::Round(((Get-Date).ToUniversalTime() - $startedAt).TotalSeconds, 3)
$result.verdict = "PASS"
$result | ConvertTo-Json -Depth 10
