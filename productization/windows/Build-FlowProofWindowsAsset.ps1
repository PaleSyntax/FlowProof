[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitCommit,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$GitTree,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$CandidateSourceSha256,
    [string]$ApplicationVersion = "0.6.0",
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($ApplicationVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$') {
    throw "ApplicationVersion contains unsupported asset-name characters."
}

$sourceRoot = $PSScriptRoot
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $sourceRoot)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "dist\productization"
}
$manifestPath = Join-Path $sourceRoot "appliance-manifest.json"
$manifest = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json
$docker = Get-Command docker.exe -ErrorAction SilentlyContinue
if ($null -eq $docker) { throw "Docker Desktop is required to build the Windows asset." }

$previousPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    $desktopStatus = @(& $docker.Source desktop status 2>&1)
    $desktopExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousPreference
}
if ($desktopExitCode -ne 0 -or (($desktopStatus -join ' ') -notmatch 'running')) {
    throw "Docker Desktop must be running before the Windows asset can be built."
}

$candidateImages = [ordered]@{}
$imageInventory = @()
foreach ($imageProperty in $manifest.images.PSObject.Properties) {
    $sourceImage = [string]$imageProperty.Value
    & $docker.Source image inspect $sourceImage *> $null
    if ($LASTEXITCODE -ne 0) { throw "Required local image is missing: $sourceImage" }
    $candidateImage = $sourceImage
    if ($imageProperty.Name -cne "postgres") {
        $repository = [regex]::Replace($sourceImage, ':[^/:]+$', '')
        $candidateImage = "${repository}:$($ApplicationVersion.ToLowerInvariant())"
        & $docker.Source image tag $sourceImage $candidateImage
        if ($LASTEXITCODE -ne 0) {
            throw "Docker could not create the versioned candidate image reference."
        }
    }
    $candidateImages[$imageProperty.Name] = $candidateImage
    $imageId = @(& $docker.Source image inspect --format "{{.Id}}" $candidateImage)
    if ($LASTEXITCODE -ne 0 -or $imageId.Count -ne 1) {
        throw "Required local image identity is unavailable: $candidateImage"
    }
    $imageInventory += [ordered]@{
        reference = $candidateImage
        id = $imageId[0].ToString().Trim()
    }
}
$images = @($candidateImages.Values)

$workflowSource = Join-Path $repositoryRoot "workflows"
$payloadNames = @(
    "FlowProof.Runtime.psm1",
    "FlowProof.Artifacts.psm1",
    "FlowProof.N8n.psm1",
    "FlowProof-Controller.ps1",
    "FlowProof Launcher.vbs",
    "FlowProof-Launcher.cmd",
    "docker-compose.appliance.yml",
    "README-Windows.txt",
    "appliance-manifest.json",
    "Build-FlowProofWindowsAsset.ps1"
)
$sourceInventory = @()
foreach ($name in $payloadNames) {
    $path = Join-Path $sourceRoot $name
    $sourceInventory += [ordered]@{
        path = "productization/windows/$($name.Replace(' ', '%20'))"
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    }
}
foreach ($workflow in Get-ChildItem -LiteralPath $workflowSource -Filter "*.json" -File | Sort-Object Name) {
    $sourceInventory += [ordered]@{
        path = "workflows/$($workflow.Name)"
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $workflow.FullName).Hash.ToLowerInvariant()
    }
}
$candidateInventory = [ordered]@{
    schema_version = "1.0"
    git_commit = $GitCommit
    git_tree = $GitTree
    files = $sourceInventory
    images = $imageInventory
}
$candidateInventoryJson = $candidateInventory | ConvertTo-Json -Depth 8 -Compress
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $inventoryBytes = [Text.Encoding]::UTF8.GetBytes($candidateInventoryJson)
    $computedCandidateSourceSha256 = -join @(
        $sha256.ComputeHash($inventoryBytes) | ForEach-Object { $_.ToString('x2') }
    )
}
finally {
    $sha256.Dispose()
}
if (-not [string]::IsNullOrWhiteSpace($CandidateSourceSha256) -and
    $CandidateSourceSha256 -cne $computedCandidateSourceSha256) {
    throw "The supplied candidate-source digest does not match the computed inventory."
}
$CandidateSourceSha256 = $computedCandidateSourceSha256

[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$temporary = Join-Path ([IO.Path]::GetTempPath()) (
    "flowproof-windows-asset-" + [guid]::NewGuid().ToString('N')
)
$payload = Join-Path $temporary "FlowProof"
$archiveName = "flowproof-images.tar"
$imageArchive = Join-Path $payload $archiveName
$assetName = "FlowProof-Windows-x86_64-$ApplicationVersion.zip"
$assetPath = Join-Path $OutputDirectory $assetName
$checksumPath = "$assetPath.sha256"
if ([IO.File]::Exists($assetPath) -or [IO.File]::Exists($checksumPath)) {
    throw "The candidate asset or checksum already exists: $assetPath"
}

try {
    [IO.Directory]::CreateDirectory($payload) | Out-Null
    foreach ($name in @(
        "FlowProof.Runtime.psm1",
        "FlowProof.Artifacts.psm1",
        "FlowProof.N8n.psm1",
        "FlowProof-Controller.ps1",
        "FlowProof Launcher.vbs",
        "FlowProof-Launcher.cmd",
        "docker-compose.appliance.yml",
        "README-Windows.txt"
    )) {
        Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination (Join-Path $payload $name)
    }
    $workflowDestination = Join-Path $payload "n8n-workflows"
    [IO.Directory]::CreateDirectory($workflowDestination) | Out-Null
    foreach ($workflow in Get-ChildItem -LiteralPath $workflowSource -Filter "*.json" -File) {
        Copy-Item -LiteralPath $workflow.FullName -Destination (
            Join-Path $workflowDestination $workflow.Name
        )
    }
    if (@(Get-ChildItem -LiteralPath $workflowDestination -Filter "*.json" -File).Count -ne 4) {
        throw "The candidate must bundle exactly four managed n8n workflows."
    }
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText(
        (Join-Path $payload "candidate-source-inventory.json"),
        (($candidateInventory | ConvertTo-Json -Depth 8) + "`n"),
        $encoding
    )

    & $docker.Source image save --output $imageArchive @images
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($imageArchive)) {
        throw "Docker could not create the bundled image archive."
    }
    $imageArchiveSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $imageArchive
    ).Hash.ToLowerInvariant()

    $manifest.application_version = $ApplicationVersion
    $manifest.update_contract.target_version = $ApplicationVersion
    foreach ($imageName in $candidateImages.Keys) {
        $manifest.images.$imageName = $candidateImages[$imageName]
    }
    $manifest.artifact_status = "UNSIGNED_CANDIDATE"
    $manifest.git_commit = $GitCommit
    $manifest.git_tree = $GitTree
    $manifest.git_coordinate_scope = "BASE_COMMIT_AND_TREE_WITH_WORKTREE_CANDIDATE_DIGEST"
    $manifest.candidate_source_sha256 = $CandidateSourceSha256
    $manifest.built_at = (Get-Date).ToUniversalTime().ToString('o')
    $manifest.image_bundle = [ordered]@{
        filename = $archiveName
        sha256 = $imageArchiveSha256
        format = "docker-image-save-tar"
        image_count = $images.Count
    }
    $manifest.code_signing = "UNSIGNED_SMARTSCREEN_GATE"
    [IO.File]::WriteAllText(
        (Join-Path $payload "appliance-manifest.json"),
        (($manifest | ConvertTo-Json -Depth 8) + "`n"),
        $encoding
    )

    Compress-Archive -LiteralPath $payload -DestinationPath $assetPath -CompressionLevel Optimal
    $assetSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $assetPath).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksumPath,
        "$assetSha256  $assetName`n",
        $encoding
    )
    [pscustomobject]@{
        asset = $assetPath
        sha256 = $assetSha256
        checksum = $checksumPath
        bytes = (Get-Item -LiteralPath $assetPath).Length
        image_archive_sha256 = $imageArchiveSha256
        git_commit = $GitCommit
        git_tree = $GitTree
        candidate_source_sha256 = $CandidateSourceSha256
        candidate_source_inventory = "candidate-source-inventory.json"
        code_signing = $manifest.code_signing
    } | ConvertTo-Json -Depth 5
}
finally {
    if ([IO.Directory]::Exists($temporary)) {
        [IO.Directory]::Delete($temporary, $true)
    }
}
