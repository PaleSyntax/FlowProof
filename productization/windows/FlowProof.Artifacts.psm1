Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ModuleRoot = Split-Path -Parent $PSCommandPath
$script:RuntimeModule = Join-Path $script:ModuleRoot "FlowProof.Runtime.psm1"
$script:ControllerPath = Join-Path $script:ModuleRoot "FlowProof-Controller.ps1"
$script:ManifestFile = Join-Path $script:ModuleRoot "appliance-manifest.json"
Import-Module $script:RuntimeModule

function Write-FlowProofArtifactText {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Value)
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Value, $encoding)
}

function New-FlowProofBackup {
    [CmdletBinding()]
    param([string]$DataRoot)

    $layout = Get-FlowProofLayout $DataRoot
    [IO.Directory]::CreateDirectory($layout.Backups) | Out-Null
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $stem = Join-Path $layout.Backups "flowproof-$timestamp"
    $dump = "$stem.dump"
    $partial = "$dump.partial"
    $remote = "/tmp/flowproof-appliance-backup.dump"
    $containerId = (Invoke-FlowProofCompose $layout.Root @("ps", "-q", "postgres") |
        Select-Object -First 1).ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($containerId)) {
        throw "PostgreSQL is not running. Start FlowProof before creating a backup."
    }
    try {
        Invoke-FlowProofCompose $layout.Root @(
            "exec", "-T", "postgres", "sh", "-ec",
            "umask 077; pg_dump -U flowproof -d flowproof -Fc -f $remote"
        ) | Out-Null
        Invoke-FlowProofDocker @("cp", "${containerId}:$remote", $partial) | Out-Null
        if (-not [IO.File]::Exists($partial) -or (Get-Item -LiteralPath $partial).Length -eq 0) {
            throw "PostgreSQL produced an empty backup."
        }
        Move-Item -LiteralPath $partial -Destination $dump
        $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $dump).Hash.ToLowerInvariant()
        Write-FlowProofArtifactText "$stem.sha256" "$sha  $([IO.Path]::GetFileName($dump))`n"
        $manifest = Get-Content -Raw -Encoding UTF8 $script:ManifestFile | ConvertFrom-Json
        $metadata = [ordered]@{
            schema_version = "1.0"
            created_at = (Get-Date).ToUniversalTime().ToString('o')
            format = "pg_dump_custom"
            database = "flowproof"
            sha256 = $sha
            application_version = $manifest.application_version
            artifact_status = $manifest.artifact_status
        }
        Write-FlowProofArtifactText "$stem.json" (($metadata | ConvertTo-Json -Depth 4) + "`n")
        return $dump
    }
    finally {
        try {
            Invoke-FlowProofCompose $layout.Root @(
                "exec", "-T", "postgres", "rm", "-f", $remote
            ) | Out-Null
        }
        catch { }
        if ([IO.File]::Exists($partial)) {
            [IO.File]::Delete($partial)
        }
    }
}

function Export-FlowProofDiagnostics {
    [CmdletBinding()]
    param([string]$DataRoot)

    $layout = Get-FlowProofLayout $DataRoot
    [IO.Directory]::CreateDirectory($layout.Diagnostics) | Out-Null
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $temporary = Join-Path $layout.Diagnostics (".partial-" + [guid]::NewGuid().ToString('N'))
    $archive = Join-Path $layout.Diagnostics "flowproof-diagnostics-$timestamp.zip"
    [IO.Directory]::CreateDirectory($temporary) | Out-Null
    try {
        $prerequisite = Test-FlowProofPrerequisites
        Write-FlowProofArtifactText (Join-Path $temporary "prerequisites.json") (
            ($prerequisite | ConvertTo-Json -Depth 6) + "`n"
        )
        $status = Get-FlowProofStatus $layout.Root
        Write-FlowProofArtifactText (Join-Path $temporary "service-status.json") (
            ($status | ConvertTo-Json -Depth 8) + "`n"
        )
        Copy-Item -LiteralPath $script:ManifestFile -Destination (
            Join-Path $temporary "appliance-manifest.json"
        )
        if ([IO.File]::Exists($layout.State)) {
            Copy-Item -LiteralPath $layout.State -Destination (
                Join-Path $temporary "appliance-state.json"
            )
        }
        $readiness = [ordered]@{ status = "unavailable"; checked_at = (Get-Date).ToUniversalTime().ToString('o') }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/health/ready" -TimeoutSec 5
            $readiness.status = $(if ($response.StatusCode -eq 200) { "ready" } else { "not_ready" })
            $readiness.http_status = $response.StatusCode
        }
        catch {
            $readiness.status = "not_ready"
            $readiness.error_type = $_.Exception.GetType().Name
        }
        Write-FlowProofArtifactText (Join-Path $temporary "readiness.json") (
            ($readiness | ConvertTo-Json -Depth 4) + "`n"
        )

        $combined = (Get-ChildItem -LiteralPath $temporary -File | ForEach-Object {
            [IO.File]::ReadAllText($_.FullName)
        }) -join "`n"
        foreach ($secretFile in @("token_pepper", "postgres_password")) {
            $path = Join-Path $layout.Secrets $secretFile
            if ([IO.File]::Exists($path)) {
                $secret = [IO.File]::ReadAllText($path).Trim()
                try {
                    if ($secret.Length -gt 0 -and $combined.Contains($secret)) {
                        throw "Diagnostics contained generated secret material and were refused."
                    }
                }
                finally {
                    $secret = $null
                }
            }
        }
        if ($combined -match '(?i)Bearer\s+[A-Za-z0-9._~-]{16,}') {
            throw "Diagnostics contained a bearer credential pattern and were refused."
        }
        Compress-Archive -Path (Join-Path $temporary "*") -DestinationPath $archive -CompressionLevel Optimal
        return $archive
    }
    finally {
        if ([IO.Directory]::Exists($temporary)) {
            [IO.Directory]::Delete($temporary, $true)
        }
    }
}

function New-FlowProofStartMenuShortcut {
    [CmdletBinding()]
    param(
        [string]$DataRoot,
        [string]$ProgramsRoot = [Environment]::GetFolderPath("Programs")
    )

    $layout = Get-FlowProofLayout $DataRoot
    $folder = Join-Path $ProgramsRoot "FlowProof"
    [IO.Directory]::CreateDirectory($folder) | Out-Null
    $shortcutPath = Join-Path $folder "FlowProof.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $shortcut.Arguments = (
        '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -DataRoot "{1}"' -f
        $script:ControllerPath, $layout.Root
    )
    $shortcut.WorkingDirectory = $script:ModuleRoot
    $shortcut.Description = "FlowProof local appliance controller"
    $shortcut.Save()
    return $shortcutPath
}

function Update-FlowProofAppliance {
    [CmdletBinding()]
    param([string]$DataRoot)

    $layout = Get-FlowProofLayout $DataRoot
    if (-not [IO.File]::Exists($layout.State) -or
        -not [IO.File]::Exists($layout.Environment)) {
        throw "FlowProof is not installed in this data folder. Use Install first."
    }
    $state = Get-Content -Raw -Encoding UTF8 $layout.State | ConvertFrom-Json
    $manifest = Get-Content -Raw -Encoding UTF8 $script:ManifestFile | ConvertFrom-Json
    if ($null -eq $manifest.update_contract -or
        [string]::IsNullOrWhiteSpace($manifest.update_contract.target_version) -or
        $manifest.update_contract.target_version -cne $manifest.application_version) {
        throw "This asset does not contain a valid update contract."
    }
    $acceptedVersions = @($manifest.update_contract.accepted_from)
    if ($acceptedVersions -cnotcontains $state.application_version) {
        throw (
            "This asset cannot update FlowProof $($state.application_version). " +
            "Install the explicitly supported intermediate asset first."
        )
    }
    $status = Get-FlowProofStatus $layout.Root
    if ($status.ServiceHealth -cne "READY") {
        Start-FlowProofAppliance $layout.Root | Out-Null
    }
    $schemaOutput = Invoke-FlowProofCompose $layout.Root @(
        "exec", "-T", "postgres", "psql", "-U", "flowproof", "-d", "flowproof",
        "-tAc", "select version_num from alembic_version;"
    )
    $actualSchema = ($schemaOutput | Select-Object -Last 1).ToString().Trim()
    if ($actualSchema -cne $manifest.update_contract.database_schema) {
        throw (
            "The installed database schema is not covered by this update asset. " +
            "Export diagnostics and use a compatible asset."
        )
    }

    $backup = New-FlowProofBackup $layout.Root
    $previousEnvironment = [IO.File]::ReadAllText($layout.Environment)
    $previousState = [IO.File]::ReadAllText($layout.State)
    try {
        Import-FlowProofBundledImages | Out-Null
        New-FlowProofApplianceConfiguration $layout.Root | Out-Null
        Invoke-FlowProofCompose $layout.Root @("config", "--quiet") | Out-Null
        Invoke-FlowProofCompose $layout.Root @(
            "up", "-d", "--wait", "postgres", "mock-accounting"
        ) | Out-Null
        Invoke-FlowProofMigration -DataRoot $layout.Root
        Invoke-FlowProofCompose $layout.Root @(
            "up", "-d", "--wait", "api", "scheduler", "alert-worker", "ops-watcher", "web"
        ) | Out-Null
        Wait-FlowProofReady
        Write-FlowProofState $layout.Root $state.application_version $backup
        $updatedStatus = Get-FlowProofStatus $layout.Root
        return [pscustomobject]@{
            Updated = $true
            PreviousApplicationVersion = $state.application_version
            ApplicationVersion = $manifest.application_version
            Backup = $backup
            ServiceHealth = $updatedStatus.ServiceHealth
            DataPreserved = $true
        }
    }
    catch {
        $updateError = $_.Exception.Message
        Write-FlowProofArtifactText $layout.Environment $previousEnvironment
        Write-FlowProofArtifactText $layout.State $previousState
        try {
            Invoke-FlowProofCompose $layout.Root @(
                "up", "-d", "--wait", "postgres", "mock-accounting", "api", "scheduler",
                "alert-worker", "ops-watcher", "web"
            ) | Out-Null
            Wait-FlowProofReady
        }
        catch {
            throw (
                "Update failed and automatic service rollback also failed. " +
                "The pre-update backup is $backup. Export diagnostics. Update error: $updateError"
            )
        }
        throw (
            "Update failed; the previous application configuration is running again. " +
            "The pre-update backup is $backup. Update error: $updateError"
        )
    }
}

function Uninstall-FlowProofAppliance {
    [CmdletBinding()]
    param(
        [string]$DataRoot,
        [switch]$DeleteData,
        [string]$DataDeletionConfirmation,
        [string]$ProgramsRoot = [Environment]::GetFolderPath("Programs")
    )

    $layout = Get-FlowProofLayout $DataRoot
    if ($DeleteData -and $DataDeletionConfirmation -cne "DELETE FLOWPROOF DATA") {
        throw "Full data deletion requires the exact confirmation: DELETE FLOWPROOF DATA"
    }
    if ([IO.File]::Exists($layout.Environment)) {
        Invoke-FlowProofCompose $layout.Root @("down", "--remove-orphans") | Out-Null
    }
    $shortcut = Join-Path $ProgramsRoot "FlowProof\FlowProof.lnk"
    if ([IO.File]::Exists($shortcut)) {
        [IO.File]::Delete($shortcut)
    }
    if (-not $DeleteData) {
        return [pscustomobject]@{
            Removed = $true
            DataPreserved = $true
            DataRoot = $layout.Root
            NextAction = "Reopen the FlowProof launcher to reinstall and reuse the preserved data."
        }
    }
    $resolved = Resolve-FlowProofDataRoot $layout.Root
    if ([IO.Directory]::Exists($resolved)) {
        [IO.Directory]::Delete($resolved, $true)
    }
    return [pscustomobject]@{
        Removed = $true
        DataPreserved = $false
        DataRoot = $resolved
    }
}

Export-ModuleMember -Function @(
    "New-FlowProofBackup",
    "Export-FlowProofDiagnostics",
    "New-FlowProofStartMenuShortcut",
    "Update-FlowProofAppliance",
    "Uninstall-FlowProofAppliance"
)
