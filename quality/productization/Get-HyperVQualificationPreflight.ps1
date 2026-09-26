[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][string]$ResultPath,
    [string]$WindowsMediaPath,
    [ValidatePattern('^[A-Za-z]:\\')][string]$VmStoragePath = 'A:\FlowProof-Qualification',
    [switch]$ElevatedChild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-ArgumentToken {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Contains('"')) { throw 'Paths containing quotation marks are unsupported.' }
    return '"' + $Value + '"'
}

function Get-OptionalFeatureState {
    param([Parameter(Mandatory)][string]$FeatureName)
    try {
        return [string](Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State
    }
    catch {
        return 'UNKNOWN'
    }
}

function Get-ServiceState {
    param([Parameter(Mandatory)][string]$Name)
    try {
        return [string](Get-Service -Name $Name).Status
    }
    catch {
        return 'NOT_INSTALLED'
    }
}

function Get-PathDriveInfo {
    param([Parameter(Mandatory)][string]$Path)
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    $drive = New-Object IO.DriveInfo($root)
    return [ordered]@{
        root = $drive.Name
        drive_type = [string]$drive.DriveType
        total_bytes = [int64]$drive.TotalSize
        free_bytes = [int64]$drive.AvailableFreeSpace
    }
}

if (-not (Test-IsAdministrator)) {
    if ($ElevatedChild) {
        throw 'Elevation was requested but the child process is not an administrator.'
    }
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-ArgumentToken $PSCommandPath),
        '-ArtifactPath', (ConvertTo-ArgumentToken ([IO.Path]::GetFullPath($ArtifactPath))),
        '-ExpectedSha256', $ExpectedSha256,
        '-ResultPath', (ConvertTo-ArgumentToken ([IO.Path]::GetFullPath($ResultPath))),
        '-VmStoragePath', (ConvertTo-ArgumentToken $VmStoragePath),
        '-ElevatedChild'
    )
    if (-not [string]::IsNullOrWhiteSpace($WindowsMediaPath)) {
        $arguments += @(
            '-WindowsMediaPath',
            (ConvertTo-ArgumentToken ([IO.Path]::GetFullPath($WindowsMediaPath)))
        )
    }
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments `
        -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    exit $process.ExitCode
}

$resolvedResultPath = [IO.Path]::GetFullPath($ResultPath)
$resolvedArtifactPath = [IO.Path]::GetFullPath($ArtifactPath)
if ([IO.File]::Exists($resolvedResultPath)) {
    throw "Refusing to overwrite existing preflight evidence: $resolvedResultPath"
}
if (-not [IO.File]::Exists($resolvedArtifactPath)) {
    throw "Candidate artifact not found: $resolvedArtifactPath"
}

$artifactHash = (Get-FileHash -LiteralPath $resolvedArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
$artifactHashMatches = $artifactHash -ceq $ExpectedSha256
$computer = Get-CimInstance Win32_ComputerSystem
$processor = Get-CimInstance Win32_Processor | Select-Object -First 1
$windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$targetDrive = Get-PathDriveInfo -Path $VmStoragePath

$featureNames = @(
    'Microsoft-Hyper-V-All',
    'VirtualMachinePlatform',
    'Microsoft-Windows-Subsystem-Linux',
    'Containers-DisposableClientVM'
)
$features = [ordered]@{}
foreach ($featureName in $featureNames) {
    $features[$featureName] = Get-OptionalFeatureState -FeatureName $featureName
}

$vms = @()
$switches = @()
try {
    $vms = @(Get-VM | Select-Object Name, State, Generation)
}
catch { }
try {
    $switches = @(Get-VMSwitch | Select-Object Name, SwitchType)
}
catch { }

$mediaExists = $false
$mediaHash = $null
$resolvedMediaPath = $null
if (-not [string]::IsNullOrWhiteSpace($WindowsMediaPath)) {
    $resolvedMediaPath = [IO.Path]::GetFullPath($WindowsMediaPath)
    $mediaExists = [IO.File]::Exists($resolvedMediaPath)
    if ($mediaExists) {
        $extension = [IO.Path]::GetExtension($resolvedMediaPath).ToLowerInvariant()
        if (@('.iso', '.vhd', '.vhdx') -contains $extension) {
            $mediaHash = (Get-FileHash -LiteralPath $resolvedMediaPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        else {
            $mediaExists = $false
        }
    }
}

$blockingReasons = New-Object Collections.Generic.List[string]
if (-not $artifactHashMatches) { $blockingReasons.Add('CANDIDATE_SHA256_MISMATCH') }
if ($features['Microsoft-Hyper-V-All'] -cne 'Enabled') { $blockingReasons.Add('HYPER_V_NOT_ENABLED') }
if ([int64]$computer.TotalPhysicalMemory -lt 16GB) { $blockingReasons.Add('HOST_MEMORY_BELOW_16_GIB') }
if ($targetDrive.free_bytes -lt 80GB) { $blockingReasons.Add('VM_TARGET_FREE_SPACE_BELOW_80_GIB') }
if ($switches.Count -eq 0) { $blockingReasons.Add('NO_HYPER_V_NETWORK_SWITCH') }
if (-not $mediaExists) { $blockingReasons.Add('OWNER_APPROVED_WINDOWS_MEDIA_REQUIRED') }

$sandboxStatus = if ($features['Containers-DisposableClientVM'] -eq 'Enabled') {
    'ENABLED_BUT_NOT_SELECTED'
}
else {
    'DISABLED_AND_NOT_SELECTED'
}

$payload = [ordered]@{
    schema_version = '1.0'
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    evidence_scope = 'READ_ONLY_HYPERV_FRESH_WINDOWS_QUALIFICATION_PREFLIGHT'
    mutating_actions_performed = $false
    host = [ordered]@{
        product_name = [string]$windows.ProductName
        edition_id = [string]$windows.EditionID
        display_version = [string]$windows.DisplayVersion
        build = [string]$windows.CurrentBuildNumber
        architecture = if ([Environment]::Is64BitOperatingSystem) { 'x86_64' } else { 'x86' }
        hypervisor_present = [bool]$computer.HypervisorPresent
        total_physical_memory_bytes = [int64]$computer.TotalPhysicalMemory
        logical_processor_count = [int]$computer.NumberOfLogicalProcessors
        cpu_name = [string]$processor.Name
        virtualization_firmware_enabled = [bool]$processor.VirtualizationFirmwareEnabled
        vm_monitor_mode_extensions = [bool]$processor.VMMonitorModeExtensions
    }
    windows_features = $features
    services = [ordered]@{
        vmms = Get-ServiceState -Name 'vmms'
        vmcompute = Get-ServiceState -Name 'vmcompute'
    }
    hyper_v = [ordered]@{
        existing_vm_count = $vms.Count
        vms = @($vms | ForEach-Object {
            [ordered]@{
                name = [string]$_.Name
                state = [string]$_.State
                generation = [int]$_.Generation
            }
        })
        switch_count = $switches.Count
        switches = @($switches | ForEach-Object {
            [ordered]@{ name = [string]$_.Name; type = [string]$_.SwitchType }
        })
    }
    candidate = [ordered]@{
        filename = [IO.Path]::GetFileName($resolvedArtifactPath)
        expected_sha256 = $ExpectedSha256
        observed_sha256 = $artifactHash
        sha256_match = $artifactHashMatches
    }
    vm_storage = [ordered]@{
        requested_path = $VmStoragePath
        drive = $targetDrive
        minimum_free_bytes = [int64](80GB)
        space_requirement_met = $targetDrive.free_bytes -ge 80GB
    }
    windows_media = [ordered]@{
        path_supplied = -not [string]::IsNullOrWhiteSpace($WindowsMediaPath)
        path = $resolvedMediaPath
        exists_and_supported_extension = $mediaExists
        sha256 = $mediaHash
    }
    sandbox = [ordered]@{
        status = $sandboxStatus
        selected_for_candidate_qualification = $false
        reason = 'Host-installed Docker Desktop is not available inside Windows Sandbox; this preflight does not enable features or assume nested Docker support.'
    }
    decision = [ordered]@{
        fresh_hyper_v_vm_status = if ($blockingReasons.Count -eq 0) {
            'READY_FOR_OWNER_AUTHORIZED_BUILD'
        }
        else {
            'BLOCKED'
        }
        blocking_reasons = @($blockingReasons)
        required_next_action = if (
            $blockingReasons.Count -eq 1 -and
            $blockingReasons[0] -eq 'OWNER_APPROVED_WINDOWS_MEDIA_REQUIRED'
        ) {
            'Provide or authorize acquisition of official Windows installation media before any VM mutation.'
        }
        else {
            'Resolve every blocking reason before any VM mutation.'
        }
        docker_support_boundary = 'Nested Docker Desktop on a local Hyper-V guest is a qualification experiment, not an officially supported Docker Desktop VM/VDI configuration.'
    }
    result = if ($blockingReasons.Count -eq 0) { 'PASS' } else { 'BLOCKED' }
}

$parent = [IO.Directory]::GetParent($resolvedResultPath)
if ($null -ne $parent -and -not $parent.Exists) {
    [IO.Directory]::CreateDirectory($parent.FullName) | Out-Null
}
$encoding = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText(
    $resolvedResultPath,
    (($payload | ConvertTo-Json -Depth 8) + "`n"),
    $encoding
)

if ($payload.result -eq 'PASS') { exit 0 }
exit 2
