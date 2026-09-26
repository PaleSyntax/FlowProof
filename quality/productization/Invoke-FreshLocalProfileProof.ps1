#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$ChildRunnerPath,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitCommit,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitTree,
    [string]$DiagnosticsPath,
    [switch]$ProbeOnly
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

$suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
$userName = "FPQual$suffix"
$taskRoot = Join-Path $env:PUBLIC "Documents\FlowProofQualification-$suffix"
$stagedArtifact = Join-Path $taskRoot ([IO.Path]::GetFileName($ArtifactPath))
$stagedRunner = Join-Path $taskRoot "run-fresh-local-profile.ps1"
$stagedResult = Join-Path $taskRoot "result.json"
$passwordText = $null
$securePassword = $null
$credential = $null
$sid = $null
$userCreated = $false
$childStarted = $false
$stage = "initialize"
$startedAt = (Get-Date).ToUniversalTime()
$orchestrationSessionId = [guid]::NewGuid().ToString()
if ([string]::IsNullOrWhiteSpace($DiagnosticsPath)) {
    $DiagnosticsPath = "$ResultPath.orchestrator.jsonl"
}

function Protect-DiagnosticText {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $safe = $Text -replace (
        '(?i)(password|token|authorization|secret)\s*[:=]\s*\S+'
    ), '$1=[redacted]'
    if ($safe.Length -gt 300) { $safe = $safe.Substring(0, 300) }
    return $safe
}

function Write-JsonPayload {
    param(
        [Parameter(Mandatory)][object]$Payload,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Append
    )
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = 1048576
    $encoding = New-Object Text.UTF8Encoding($false)
    $jsonLine = $serializer.Serialize($Payload) + "`n"
    if ($Append) {
        [IO.File]::AppendAllText($Path, $jsonLine, $encoding)
    }
    else {
        [IO.File]::WriteAllText($Path, $jsonLine, $encoding)
    }
}

function Write-Diagnostic {
    param(
        [Parameter(Mandatory)][string]$Event,
        [AllowNull()][string]$Detail
    )
    try {
        Write-JsonPayload -Path $DiagnosticsPath -Append -Payload ([ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString('o')
            event = $Event
            stage = $stage
            detail = Protect-DiagnosticText $Detail
        })
    }
    catch { }
}

function Write-OrchestrationFailure {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Failure)

    $message = Protect-DiagnosticText $Failure.Exception.Message
    $resultKind = $(if ($childStarted) { "FAIL" } else { "BLOCKED" })
    $stageStatus = $(if ($childStarted) { "FAIL" } else { "BLOCKED" })
    $failure = [ordered]@{
        schema_version = "1.0"
        session_id = $orchestrationSessionId
        started_at = $startedAt.ToString('o')
        completed_at = (Get-Date).ToUniversalTime().ToString('o')
        tester_role = "automated disposable local Windows profile"
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
            install_failure_count = $(if ($childStarted) { 1 } else { 0 })
        }
        stages = [ordered]@{
            prerequisite_check = [ordered]@{
                status = $stageStatus
                evidence = @("orchestrator_stage=$stage", "error_type=$($Failure.Exception.GetType().Name)")
                note = $message
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
        result = $resultKind
        blocker = "FRESH_LOCAL_PROFILE_ORCHESTRATION_FAILED: $message"
    }
    Write-JsonPayload -Path $ResultPath -Payload $failure
}

try {
    Write-Diagnostic -Event "orchestrator_started" -Detail "probe_only=$([bool]$ProbeOnly)"
    if ($ProbeOnly) {
        $stage = "elevated_probe"
        $principal = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "The elevated probe does not have an administrator token."
        }
        if ($null -eq (Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
            throw "The elevated probe cannot access New-LocalUser."
        }
        if ($null -eq (Get-LocalGroup -Name "docker-users" -ErrorAction SilentlyContinue)) {
            throw "The elevated probe cannot find the docker-users group."
        }
        $probePath = "$ResultPath.write-probe"
        [IO.File]::WriteAllText($probePath, "probe`n", (New-Object Text.UTF8Encoding($false)))
        [IO.File]::Delete($probePath)
        Write-Diagnostic -Event "probe_completed" `
            -Detail "administrator=true;local_accounts=true;docker_group=true;result_write=true"
        return
    }

    $stage = "prepare_credentials"
    $passwordText = (New-RandomText 48) + "aA1!"
    $securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $credential = New-Object Management.Automation.PSCredential(
        "$env:COMPUTERNAME\$userName", $securePassword
    )
    Write-Diagnostic -Event "credentials_prepared" -Detail $null

    $stage = "prepare_staging"
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
        throw "The disposable qualification user already exists."
    }
    if ([IO.Directory]::Exists($taskRoot)) {
        throw "The disposable qualification staging directory already exists."
    }
    [IO.Directory]::CreateDirectory($taskRoot) | Out-Null
    $stage = "stage_candidate"
    Write-Diagnostic -Event "stage_started" -Detail $null
    Copy-Item -LiteralPath $ArtifactPath -Destination $stagedArtifact
    Copy-Item -LiteralPath $ChildRunnerPath -Destination $stagedRunner

    $stage = "create_disposable_user"
    Write-Diagnostic -Event "stage_started" -Detail $null
    $user = New-LocalUser -Name $userName -Password $securePassword `
        -Description "Temporary FlowProof qualification user" `
        -UserMayNotChangePassword -AccountNeverExpires
    $userCreated = $true
    $sid = $user.SID.Value
    $stage = "grant_docker_access"
    Write-Diagnostic -Event "stage_started" -Detail $null
    Add-LocalGroupMember -Group "docker-users" -Member $userName

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $stagedRunner + '"'),
        "-ArtifactPath", ('"' + $stagedArtifact + '"'),
        "-ExpectedSha256", $ExpectedSha256,
        "-ResultPath", ('"' + $stagedResult + '"'),
        "-GitCommit", $GitCommit,
        "-GitTree", $GitTree,
        "-DockerDesktopOwner", ('"' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + '"')
    )
    $stage = "child_runner"
    Write-Diagnostic -Event "stage_started" -Detail $null
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments `
        -Credential $credential -LoadUserProfile -WindowStyle Hidden -Wait -PassThru
    $childStarted = $true
    if ($process.ExitCode -ne 0) {
        if ([IO.File]::Exists($stagedResult)) {
            Copy-Item -LiteralPath $stagedResult -Destination $ResultPath -Force
        }
        throw "The disposable-profile child runner failed with exit code $($process.ExitCode)."
    }
    $stage = "copy_result"
    Write-Diagnostic -Event "stage_started" -Detail $null
    if (-not [IO.File]::Exists($stagedResult)) {
        throw "The disposable-profile child runner did not produce evidence."
    }
    Copy-Item -LiteralPath $stagedResult -Destination $ResultPath -Force
    Write-Diagnostic -Event "orchestrator_completed" -Detail "result_copied=true"
}
catch {
    $failureRecord = $_
    Write-Diagnostic -Event "orchestrator_failed" `
        -Detail "error_type=$($failureRecord.Exception.GetType().Name); message=$($failureRecord.Exception.Message)"
    if (-not [IO.File]::Exists($ResultPath)) {
        try { Write-OrchestrationFailure $failureRecord }
        catch {
            Write-Diagnostic -Event "fallback_write_failed" `
                -Detail "error_type=$($_.Exception.GetType().Name); message=$($_.Exception.Message)"
        }
    }
    throw
}
finally {
    $stage = "cleanup"
    $credential = $null
    $securePassword = $null
    $passwordText = $null
    if ($userCreated) {
        try { Remove-LocalUser -Name $userName -ErrorAction Stop } catch { }
    }
    if (-not [string]::IsNullOrWhiteSpace($sid)) {
        Start-Sleep -Seconds 2
        try {
            $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction Stop
            if ($null -ne $profile -and -not $profile.Loaded) {
                $profile | Remove-CimInstance -ErrorAction Stop
            }
        }
        catch { }
    }
    if ([IO.Directory]::Exists($taskRoot)) {
        [IO.Directory]::Delete($taskRoot, $true)
    }
    Write-Diagnostic -Event "cleanup_completed" `
        -Detail "user_created=$userCreated;staging_present=$([IO.Directory]::Exists($taskRoot))"
}
