[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FromArtifact,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$FromSha256,
    [Parameter(Mandatory)][string]$ToArtifact,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ToSha256,
    [string]$DataRoot = (Join-Path ([IO.Path]::GetTempPath()) (
        "flowproof-update-runtime-" + [guid]::NewGuid().ToString("N")
    )),
    [string]$WorkingRoot = (Join-Path ([IO.Path]::GetTempPath()) (
        "flowproof-update-proof-" + [guid]::NewGuid().ToString("N")
    ))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
foreach ($candidate in @(
    @{ Path = $DataRoot; Pattern = '^flowproof-update-runtime-[a-f0-9]{32}$' },
    @{ Path = $WorkingRoot; Pattern = '^flowproof-update-proof-[a-f0-9]{32}$' }
)) {
    $parent = [IO.Path]::GetFullPath((Split-Path -Parent $candidate.Path)).TrimEnd('\')
    if ($parent -cne $tempRoot -or (Split-Path -Leaf $candidate.Path) -notmatch $candidate.Pattern) {
        throw "Update proof accepts only its GUID-suffixed folders in the OS temp directory."
    }
    if ([IO.Directory]::Exists($candidate.Path) -or [IO.File]::Exists($candidate.Path)) {
        throw "Update proof path already exists: $($candidate.Path)"
    }
}

function Assert-Artifact {
    param([string]$Path, [string]$ExpectedSha256)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) {
        throw "Artifact checksum mismatch: $resolved"
    }
    return $resolved
}

function Import-ApplianceModules {
    param([string]$ApplianceRoot)
    Remove-Module FlowProof.N8n, FlowProof.Artifacts, FlowProof.Runtime -Force `
        -ErrorAction SilentlyContinue
    Import-Module (Join-Path $ApplianceRoot "FlowProof.Artifacts.psm1") -Force
    Import-Module (Join-Path $ApplianceRoot "FlowProof.Runtime.psm1") -Force
}

function Get-AdminCount {
    $raw = Invoke-FlowProofCompose $DataRoot @(
        "exec", "-T", "postgres", "psql", "-U", "flowproof", "-d", "flowproof",
        "-tAc", "select count(*) from principals where name = 'Update Proof Admin';"
    )
    return [int](($raw | Select-Object -Last 1).ToString().Trim())
}

$fromPath = Assert-Artifact $FromArtifact $FromSha256
$toPath = Assert-Artifact $ToArtifact $ToSha256
$startedAt = (Get-Date).ToUniversalTime()
$completed = $false
$adminPassword = $null
$result = [ordered]@{
    schema_version = "1.0"
    evidence_scope = "EXTRACTED_CANDIDATE_TO_CANDIDATE_CURRENT_HOST_UPDATE"
    clean_machine_proof = $false
    source_checkout_used_for_runtime = $false
    from_artifact = [ordered]@{
        path = $fromPath.Replace('\', '/')
        sha256 = $FromSha256
    }
    to_artifact = [ordered]@{
        path = $toPath.Replace('\', '/')
        sha256 = $ToSha256
    }
    data_root = $DataRoot.Replace('\', '/')
    started_at = $startedAt.ToString('o')
    stages = @()
}

function Add-Stage {
    param([string]$Name, [hashtable]$Evidence)
    $script:result.stages += [ordered]@{
        name = $Name
        status = "PASS"
        checked_at = (Get-Date).ToUniversalTime().ToString('o')
        evidence = $Evidence
    }
}

try {
    [IO.Directory]::CreateDirectory($WorkingRoot) | Out-Null
    $fromExtract = Join-Path $WorkingRoot "from"
    $toExtract = Join-Path $WorkingRoot "to"
    [IO.Compression.ZipFile]::ExtractToDirectory($fromPath, $fromExtract)
    [IO.Compression.ZipFile]::ExtractToDirectory($toPath, $toExtract)
    $fromRoot = (Resolve-Path (Join-Path $fromExtract "FlowProof")).Path
    $toRoot = (Resolve-Path (Join-Path $toExtract "FlowProof")).Path
    if ($fromRoot.StartsWith($repositoryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $toRoot.StartsWith($repositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Update proof must execute only extracted candidate payloads."
    }

    Import-ApplianceModules $fromRoot
    $passwordText = (New-FlowProofRandomSecret -ByteCount 48) + "aA1!"
    $adminPassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $passwordText = $null
    $initial = Initialize-FlowProofAppliance $DataRoot "Update Proof Admin" $adminPassword
    if (-not $initial.Installed -or $initial.ServiceHealth -cne "READY") {
        throw "Source candidate did not install READY."
    }
    $beforeState = Get-Content -Raw -Encoding UTF8 (Get-FlowProofLayout $DataRoot).State |
        ConvertFrom-Json
    $adminBefore = Get-AdminCount
    Add-Stage "source_candidate_install" @{
        application_version = $beforeState.application_version
        service_health = $initial.ServiceHealth
        persisted_admin_count = $adminBefore
    }

    $failureRoot = Join-Path $WorkingRoot "to-failure\FlowProof"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $failureRoot)) | Out-Null
    Copy-Item -LiteralPath $toRoot -Destination $failureRoot -Recurse
    $failureManifestPath = Join-Path $failureRoot "appliance-manifest.json"
    $failureManifest = Get-Content -Raw -Encoding UTF8 $failureManifestPath |
        ConvertFrom-Json
    $failureManifest.images.api = (
        "flowproof-api:missing-update-proof-" + [guid]::NewGuid().ToString('N')
    )
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        $failureManifestPath,
        (($failureManifest | ConvertTo-Json -Depth 10) + "`n"),
        $encoding
    )
    Import-ApplianceModules $failureRoot
    $rollbackObserved = $false
    try {
        Update-FlowProofAppliance $DataRoot | Out-Null
    }
    catch {
        $rollbackObserved = $_.Exception.Message -match (
            'previous application configuration is running again'
        )
    }
    $rollbackState = Get-Content -Raw -Encoding UTF8 (Get-FlowProofLayout $DataRoot).State |
        ConvertFrom-Json
    $rollbackStatus = Get-FlowProofStatus $DataRoot
    $adminAfterRollback = Get-AdminCount
    $rollbackBackups = @(
        Get-ChildItem -LiteralPath (Get-FlowProofLayout $DataRoot).Backups `
            -Filter "*.dump" -File
    )
    if (-not $rollbackObserved -or $rollbackStatus.ServiceHealth -cne "READY" -or
        $rollbackState.application_version -cne $beforeState.application_version -or
        $adminAfterRollback -ne 1 -or $rollbackBackups.Count -lt 1) {
        throw "Injected update failure did not restore the source candidate safely."
    }
    Add-Stage "failure_rollback" @{
        injected_missing_image_reference = $true
        previous_configuration_restored = $true
        application_version = $rollbackState.application_version
        service_health = $rollbackStatus.ServiceHealth
        persisted_admin_count = $adminAfterRollback
        pre_update_backup_count = $rollbackBackups.Count
    }

    Import-ApplianceModules $toRoot
    $update = Update-FlowProofAppliance $DataRoot
    $layout = Get-FlowProofLayout $DataRoot
    $afterState = Get-Content -Raw -Encoding UTF8 $layout.State | ConvertFrom-Json
    $adminAfter = Get-AdminCount
    $backupStem = Join-Path ([IO.Path]::GetDirectoryName($update.Backup)) (
        [IO.Path]::GetFileNameWithoutExtension($update.Backup)
    )
    if (-not $update.Updated -or $update.ServiceHealth -cne "READY" -or
        -not $update.DataPreserved -or $adminBefore -ne 1 -or $adminAfter -ne 1 -or
        $afterState.application_version -cne $update.ApplicationVersion -or
        $afterState.previous_application_version -cne $update.PreviousApplicationVersion -or
        -not [IO.File]::Exists($update.Backup) -or
        -not [IO.File]::Exists("$backupStem.sha256") -or
        -not [IO.File]::Exists("$backupStem.json")) {
        throw "Candidate update assertions failed."
    }
    Add-Stage "backup_first_update" @{
        from_version = $update.PreviousApplicationVersion
        to_version = $update.ApplicationVersion
        service_health = $update.ServiceHealth
        data_preserved = $true
        persisted_admin_count_before = $adminBefore
        persisted_admin_count_after = $adminAfter
        backup = $update.Backup.Replace('\', '/')
        backup_sidecars = $true
    }

    $repeatRejected = $false
    try {
        Update-FlowProofAppliance $DataRoot | Out-Null
    }
    catch {
        $repeatRejected = $_.Exception.Message -match 'cannot update FlowProof'
    }
    if (-not $repeatRejected) {
        throw "The update contract did not reject a same-version repeat."
    }
    Add-Stage "same_version_rejected" @{ rejected_before_mutation = $true }

    $deleted = Uninstall-FlowProofAppliance $DataRoot -DeleteData `
        -DataDeletionConfirmation "DELETE FLOWPROOF DATA" -ProgramsRoot (
            Join-Path $WorkingRoot "programs"
        )
    if ($deleted.DataPreserved -or [IO.Directory]::Exists($DataRoot)) {
        throw "Update proof cleanup left the data root behind."
    }
    Add-Stage "confirmed_cleanup" @{ data_root_absent = $true }
    $completed = $true
}
finally {
    $adminPassword = $null
    if (-not $completed -and [IO.Directory]::Exists($DataRoot)) {
        try {
            Uninstall-FlowProofAppliance $DataRoot -DeleteData `
                -DataDeletionConfirmation "DELETE FLOWPROOF DATA" -ProgramsRoot (
                    Join-Path $WorkingRoot "programs"
                ) | Out-Null
        }
        catch {
            try { Invoke-FlowProofCompose $DataRoot @("down", "--remove-orphans") | Out-Null } catch { }
            if ([IO.Directory]::Exists($DataRoot)) {
                [IO.Directory]::Delete($DataRoot, $true)
            }
        }
    }
    if ([IO.Directory]::Exists($WorkingRoot)) {
        [IO.Directory]::Delete($WorkingRoot, $true)
    }
}

$result.completed_at = (Get-Date).ToUniversalTime().ToString('o')
$result.duration_seconds = [math]::Round(
    ((Get-Date).ToUniversalTime() - $startedAt).TotalSeconds, 3
)
$result.verdict = "PASS"
$result | ConvertTo-Json -Depth 10
