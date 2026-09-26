[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$ChildRunnerPath,
    [Parameter(Mandatory)][string]$OrchestratorPath,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitCommit,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitTree,
    [string]$DiagnosticsPath,
    [switch]$ProbeOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DiagnosticsPath)) {
    $DiagnosticsPath = "$ResultPath.orchestrator.jsonl"
}
$startedAt = (Get-Date).ToUniversalTime()
$sessionId = [guid]::NewGuid().ToString()

function Protect-DiagnosticText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $safe = $Text -replace (
        '(?i)(password|token|authorization|secret)\s*[:=]\s*\S+'
    ), '$1=[redacted]'
    if ($safe.Length -gt 300) { $safe = $safe.Substring(0, 300) }
    return $safe
}

function Read-DiagnosticEvidence {
    $evidence = New-Object Collections.Generic.List[string]
    if (-not [IO.File]::Exists($DiagnosticsPath)) {
        $evidence.Add("orchestrator_diagnostics_present=false")
        return @($evidence)
    }
    $evidence.Add("orchestrator_diagnostics_present=true")
    foreach ($line in @(Get-Content -LiteralPath $DiagnosticsPath -Encoding UTF8 | Select-Object -Last 8)) {
        try {
            $entry = $line | ConvertFrom-Json
            $detail = Protect-DiagnosticText $entry.detail
            $summary = "orchestrator_event=$($entry.event);stage=$($entry.stage)"
            if (-not [string]::IsNullOrWhiteSpace($detail)) {
                $summary += ";detail=$detail"
            }
            if ($summary.Length -gt 300) { $summary = $summary.Substring(0, 300) }
            $evidence.Add($summary)
        }
        catch {
            $evidence.Add("orchestrator_diagnostic_parse_error=true")
        }
    }
    return @($evidence)
}

function Write-ParentEvidence {
    param(
        [Parameter(Mandatory)][string]$Blocker,
        [Parameter(Mandatory)][ValidateSet("PASS", "BLOCKED")][string]$PrerequisiteStatus,
        [Parameter(Mandatory)][int]$InstallFailureCount,
        [Parameter(Mandatory)][string[]]$Evidence
    )
    $payload = [ordered]@{
        schema_version = "1.0"
        session_id = $sessionId
        started_at = $startedAt.ToString('o')
        completed_at = (Get-Date).ToUniversalTime().ToString('o')
        tester_role = "automated disposable local Windows profile launcher"
        environment = [ordered]@{
            windows_version = "Windows $([Environment]::OSVersion.Version)"
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
            install_failure_count = $InstallFailureCount
        }
        stages = [ordered]@{
            prerequisite_check = [ordered]@{
                status = $PrerequisiteStatus
                evidence = @($Evidence)
                note = $Blocker
            }
            install = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            first_open = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            safe_demo = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            restart_reopen = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            diagnostics_export = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            backup = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            uninstall_preserve = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
            reinstall_retention = [ordered]@{ status = "NOT_RUN"; evidence = @(); note = $null }
        }
        security = [ordered]@{
            credentials_in_artifact = $false
            env_file_in_artifact = $false
            database_in_artifact = $false
            raw_customer_data_in_artifact = $false
        }
        result = "BLOCKED"
        blocker = $Blocker
    }
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = 1048576
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($ResultPath, ($serializer.Serialize($payload) + "`n"), $encoding)
}

function Test-InstallSessionShape {
    param([Parameter(Mandatory)][object]$Session)
    $required = @(
        "schema_version", "session_id", "started_at", "completed_at", "tester_role",
        "environment", "artifact", "metrics", "stages", "security", "result", "blocker"
    )
    $properties = @($Session.PSObject.Properties.Name)
    foreach ($name in $required) {
        if ($properties -notcontains $name) { return $false }
    }
    if ($Session.schema_version -cne "1.0") { return $false }
    if (@("PASS", "FAIL", "BLOCKED", "NOT_RUN") -cnotcontains $Session.result) {
        return $false
    }
    if ($null -ne $Session.blocker -and ([string]$Session.blocker).Length -gt 500) {
        return $false
    }
    $requiredStages = @(
        "prerequisite_check", "install", "first_open", "safe_demo", "restart_reopen",
        "diagnostics_export", "backup", "uninstall_preserve", "reinstall_retention"
    )
    $stageProperties = @($Session.stages.PSObject.Properties.Name)
    foreach ($name in $requiredStages) {
        if ($stageProperties -notcontains $name) { return $false }
    }
    return $true
}

if ([IO.File]::Exists($ResultPath)) {
    throw "Refusing to overwrite an existing install-session result: $ResultPath"
}
if ([IO.File]::Exists($DiagnosticsPath)) {
    throw "Refusing to append to an existing orchestrator diagnostic: $DiagnosticsPath"
}

$arguments = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", ('"' + $OrchestratorPath + '"'),
    "-ArtifactPath", ('"' + $ArtifactPath + '"'),
    "-ExpectedSha256", $ExpectedSha256,
    "-ChildRunnerPath", ('"' + $ChildRunnerPath + '"'),
    "-ResultPath", ('"' + $ResultPath + '"'),
    "-GitCommit", $GitCommit,
    "-GitTree", $GitTree,
    "-DiagnosticsPath", ('"' + $DiagnosticsPath + '"')
)
if ($ProbeOnly) { $arguments += "-ProbeOnly" }

try {
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments `
        -Verb RunAs -WindowStyle Hidden -Wait -PassThru
}
catch {
    $message = Protect-DiagnosticText $_.Exception.Message
    Write-ParentEvidence `
        -Blocker "FRESH_LOCAL_PROFILE_ELEVATION_LAUNCH_FAILED: $message" `
        -PrerequisiteStatus "BLOCKED" `
        -InstallFailureCount 0 `
        -Evidence @("elevated_process_started=false", "error_type=$($_.Exception.GetType().Name)")
    exit 1
}

$diagnosticEvidence = @(Read-DiagnosticEvidence)
if ([IO.File]::Exists($ResultPath)) {
    $childResultValid = $false
    try {
        $childResult = Get-Content -Raw -Encoding UTF8 -LiteralPath $ResultPath | ConvertFrom-Json
        $childResultValid = Test-InstallSessionShape $childResult
    }
    catch { }
    if ($childResultValid) {
        exit $process.ExitCode
    }
    $invalidChildPath = "$ResultPath.child-invalid.json"
    Move-Item -LiteralPath $ResultPath -Destination $invalidChildPath
    Write-ParentEvidence `
        -Blocker "FRESH_LOCAL_PROFILE_CHILD_RESULT_CONTRACT_INVALID: raw child result was preserved separately." `
        -PrerequisiteStatus "BLOCKED" `
        -InstallFailureCount 1 `
        -Evidence (@("child_result_contract_valid=false") + $diagnosticEvidence)
    exit 1
}
if ($ProbeOnly -and $process.ExitCode -eq 0 -and
    ($diagnosticEvidence -match 'orchestrator_event=probe_completed').Count -gt 0) {
    Write-ParentEvidence `
        -Blocker "FRESH_LOCAL_PROFILE_PROBE_ONLY_COMPLETED: elevated prerequisites passed; full install was intentionally not started." `
        -PrerequisiteStatus "PASS" `
        -InstallFailureCount 0 `
        -Evidence (@("elevated_process_exit_code=0") + $diagnosticEvidence)
    exit 0
}

Write-ParentEvidence `
    -Blocker "FRESH_LOCAL_PROFILE_ELEVATED_PROCESS_EXITED_WITHOUT_RESULT: exit_code=$($process.ExitCode)" `
    -PrerequisiteStatus "BLOCKED" `
    -InstallFailureCount $(if ($ProbeOnly) { 0 } else { 1 }) `
    -Evidence (@("elevated_process_exit_code=$($process.ExitCode)") + $diagnosticEvidence)
exit 1
