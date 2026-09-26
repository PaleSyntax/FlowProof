[CmdletBinding()]
param(
    [ValidateSet("Gui", "Status", "Start", "Stop", "Restart", "Update", "Open", "Diagnostics", "Backup")]
    [string]$Action = "Gui",
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA "FlowProof")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $root "FlowProof.Artifacts.psm1") -Force
Import-Module (Join-Path $root "FlowProof.Runtime.psm1") -Force
Import-Module (Join-Path $root "FlowProof.N8n.psm1") -Force

if ($Action -ne "Gui") {
    switch ($Action) {
        "Status" { Get-FlowProofStatus $DataRoot | ConvertTo-Json -Depth 8 }
        "Start" { Start-FlowProofAppliance $DataRoot | ConvertTo-Json -Depth 8 }
        "Stop" { Stop-FlowProofAppliance $DataRoot | ConvertTo-Json -Depth 8 }
        "Restart" { Restart-FlowProofAppliance $DataRoot | ConvertTo-Json -Depth 8 }
        "Update" { Update-FlowProofAppliance $DataRoot | ConvertTo-Json -Depth 8 }
        "Open" { Open-FlowProofDashboard }
        "Diagnostics" { Export-FlowProofDiagnostics $DataRoot }
        "Backup" { New-FlowProofBackup $DataRoot }
    }
    exit 0
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="FlowProof" Height="760" Width="760" WindowStartupLocation="CenterScreen"
        ResizeMode="CanMinimize" Background="#F4F7FB">
  <ScrollViewer VerticalScrollBarVisibility="Auto">
    <StackPanel Margin="28">
      <TextBlock Text="FlowProof" FontSize="30" FontWeight="Bold" Foreground="#102A43" />
      <TextBlock Margin="0,4,0,18" TextWrapping="Wrap" FontSize="15"
        Text="Outcome assurance for business-critical n8n automations. Service health is not proof of a business outcome." />

      <Border Padding="16" Background="White" CornerRadius="8" Margin="0,0,0,14">
        <StackPanel>
          <TextBlock Text="Local setup" FontSize="18" FontWeight="SemiBold" />
          <TextBlock Margin="0,10,0,4" Text="Data folder" />
          <TextBox Name="DataRootBox" Height="30" />
          <TextBlock Margin="0,10,0,4" Text="Administrator name" />
          <TextBox Name="AdminNameBox" Height="30" Text="admin" />
          <TextBlock Margin="0,10,0,4" Text="Administrator password (12+ characters)" />
          <PasswordBox Name="AdminPasswordBox" Height="30" />
          <Button Name="InstallButton" Margin="0,14,0,0" Height="36" Content="Install / repair local appliance" />
        </StackPanel>
      </Border>

      <Border Padding="16" Background="White" CornerRadius="8" Margin="0,0,0,14">
        <StackPanel>
          <TextBlock Text="Controller" FontSize="18" FontWeight="SemiBold" />
          <TextBlock Name="ServiceHealthText" Margin="0,10,0,0" FontWeight="Bold" Text="Service health: checking..." />
          <TextBlock Margin="0,6,0,12" TextWrapping="Wrap"
            Text="Outcome truth: open FlowProof and inspect the entity timeline and evidence. This controller never decides invariant truth." />
          <WrapPanel>
            <Button Name="RefreshButton" Margin="0,0,8,8" Padding="14,7" Content="Refresh" />
            <Button Name="StartButton" Margin="0,0,8,8" Padding="14,7" Content="Start" />
            <Button Name="StopButton" Margin="0,0,8,8" Padding="14,7" Content="Stop" />
            <Button Name="RestartButton" Margin="0,0,8,8" Padding="14,7" Content="Restart" />
            <Button Name="OpenButton" Margin="0,0,8,8" Padding="14,7" Content="Open FlowProof" />
            <Button Name="UpdateButton" Margin="0,0,8,8" Padding="14,7" Content="Update from this asset" />
          </WrapPanel>
          <TextBlock Margin="0,4,0,0" TextWrapping="Wrap" Foreground="#52657D"
            Text="Update first creates a database backup and only accepts an explicitly compatible installed version. On failure it restores the previous service configuration." />
        </StackPanel>
      </Border>

      <Border Padding="16" Background="White" CornerRadius="8" Margin="0,0,0,14">
        <StackPanel>
          <TextBlock Text="Connect an existing n8n workflow" FontSize="18" FontWeight="SemiBold" />
          <TextBlock Margin="0,6,0,4" TextWrapping="Wrap"
            Text="Enter an owner-created n8n API key once. FlowProof sends its fixed least-privilege credential directly to n8n's encrypted credential store; neither key is written to this profile." />
          <TextBlock Margin="0,10,0,4" Text="n8n base URL" />
          <TextBox Name="N8nBaseUrlBox" Height="30" Text="http://127.0.0.1:5678" />
          <TextBlock Margin="0,10,0,4" Text="n8n API key (not stored)" />
          <PasswordBox Name="N8nCredentialBox" Height="30" />
          <TextBlock Margin="0,10,0,4" Text="FlowProof API URL as reached by n8n" />
          <TextBox Name="FlowProofApiUrlBox" Height="30" Text="http://host.docker.internal:8000" />
          <TextBlock Margin="0,6,0,8" TextWrapping="Wrap" Foreground="#52657D"
            Text="Remote addresses require HTTPS. The provisioned service can write events and execute/verify an approved recovery, but can never approve it." />
          <WrapPanel>
            <Button Name="TestN8nButton" Margin="0,0,8,8" Padding="14,7" Content="Test n8n connection" />
            <Button Name="ConnectN8nButton" Margin="0,0,8,8" Padding="14,7" Content="Provision FlowProof pack" />
          </WrapPanel>
        </StackPanel>
      </Border>

      <Border Padding="16" Background="White" CornerRadius="8">
        <StackPanel>
          <TextBlock Text="Data and support" FontSize="18" FontWeight="SemiBold" />
          <WrapPanel Margin="0,12,0,0">
            <Button Name="DiagnosticsButton" Margin="0,0,8,8" Padding="14,7" Content="Export diagnostics" />
            <Button Name="BackupButton" Margin="0,0,8,8" Padding="14,7" Content="Backup data" />
            <Button Name="UninstallButton" Margin="0,0,8,8" Padding="14,7" Content="Uninstall (preserve data)" />
          </WrapPanel>
          <TextBlock Name="ProgressText" Margin="0,10,0,0" TextWrapping="Wrap" Text="Ready." />
        </StackPanel>
      </Border>
    </StackPanel>
  </ScrollViewer>
</Window>
"@

$reader = New-Object Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$dataRootBox = $window.FindName("DataRootBox")
$adminNameBox = $window.FindName("AdminNameBox")
$adminPasswordBox = $window.FindName("AdminPasswordBox")
$n8nBaseUrlBox = $window.FindName("N8nBaseUrlBox")
$n8nCredentialBox = $window.FindName("N8nCredentialBox")
$flowProofApiUrlBox = $window.FindName("FlowProofApiUrlBox")
$serviceHealthText = $window.FindName("ServiceHealthText")
$progressText = $window.FindName("ProgressText")
$dataRootBox.Text = Resolve-FlowProofDataRoot $DataRoot

function Refresh-ControllerStatus {
    $status = Get-FlowProofStatus $dataRootBox.Text
    $serviceHealthText.Text = "Service health: $($status.ServiceHealth)"
    if (-not $status.Prerequisite.Ready) {
        $progressText.Text = "$($status.Prerequisite.Message) $($status.Prerequisite.NextAction)"
    }
    elseif ($status.ServiceHealth -eq "READY") {
        $progressText.Text = "FlowProof services are ready. Open FlowProof to inspect business outcomes."
    }
    else {
        $progressText.Text = "FlowProof services are not ready. Choose Start or Export diagnostics."
    }
}

function Invoke-ControllerAction {
    param([string]$WorkingText, [scriptblock]$Operation)
    $progressText.Text = $WorkingText
    $window.Dispatcher.Invoke([action]{}, "Render")
    try {
        $result = & $Operation
        Refresh-ControllerStatus
        return $result
    }
    catch {
        $progressText.Text = $_.Exception.Message
        [Windows.MessageBox]::Show($_.Exception.Message, "FlowProof", "OK", "Warning") | Out-Null
        return $null
    }
}

$window.FindName("InstallButton").Add_Click({
    Invoke-ControllerAction "Installing FlowProof. First start may take several minutes..." {
        $password = $adminPasswordBox.SecurePassword
        Initialize-FlowProofAppliance $dataRootBox.Text $adminNameBox.Text $password | Out-Null
        New-FlowProofStartMenuShortcut $dataRootBox.Text | Out-Null
    } | Out-Null
})
$window.FindName("RefreshButton").Add_Click({ Refresh-ControllerStatus })
$window.FindName("StartButton").Add_Click({
    Invoke-ControllerAction "Starting FlowProof..." { Start-FlowProofAppliance $dataRootBox.Text | Out-Null } | Out-Null
})
$window.FindName("StopButton").Add_Click({
    Invoke-ControllerAction "Stopping FlowProof services..." { Stop-FlowProofAppliance $dataRootBox.Text | Out-Null } | Out-Null
})
$window.FindName("RestartButton").Add_Click({
    Invoke-ControllerAction "Restarting FlowProof..." { Restart-FlowProofAppliance $dataRootBox.Text | Out-Null } | Out-Null
})
$window.FindName("UpdateButton").Add_Click({
    $result = Invoke-ControllerAction "Backing up data and updating FlowProof..." {
        Update-FlowProofAppliance $dataRootBox.Text
    }
    if ($null -ne $result) {
        $progressText.Text = (
            "FlowProof updated from $($result.PreviousApplicationVersion) to " +
            "$($result.ApplicationVersion). Backup: $($result.Backup)"
        )
    }
})
$window.FindName("OpenButton").Add_Click({ Open-FlowProofDashboard })
$window.FindName("DiagnosticsButton").Add_Click({
    $path = Invoke-ControllerAction "Exporting sanitized diagnostics..." {
        Export-FlowProofDiagnostics $dataRootBox.Text
    }
    if ($null -ne $path) {
        [Windows.MessageBox]::Show("Diagnostics exported to:`n$path", "FlowProof") | Out-Null
    }
})
$window.FindName("BackupButton").Add_Click({
    $path = Invoke-ControllerAction "Creating a bounded database backup..." {
        New-FlowProofBackup $dataRootBox.Text
    }
    if ($null -ne $path) {
        [Windows.MessageBox]::Show("Backup created:`n$path", "FlowProof") | Out-Null
    }
})
$window.FindName("TestN8nButton").Add_Click({
    $result = Invoke-ControllerAction "Testing n8n API access..." {
        Test-FlowProofN8nConnection $n8nBaseUrlBox.Text $n8nCredentialBox.SecurePassword
    }
    if ($null -ne $result) {
        $progressText.Text = "n8n connection is ready. The API key remains only in this field."
    }
})
$window.FindName("ConnectN8nButton").Add_Click({
    $result = Invoke-ControllerAction "Provisioning the least-privilege credential and four workflows..." {
        Connect-FlowProofN8n $dataRootBox.Text $n8nBaseUrlBox.Text `
            $n8nCredentialBox.SecurePassword $flowProofApiUrlBox.Text
    }
    if ($null -ne $result) {
        $n8nCredentialBox.Clear()
        $progressText.Text = (
            "n8n connected: $($result.workflow_ids.Count) workflows, " +
            "$($result.published_workflow_count) published. No API key was stored."
        )
    }
})
$window.FindName("UninstallButton").Add_Click({
    $choice = [Windows.MessageBox]::Show(
        "Stop and remove FlowProof services? Your data will be preserved by default.",
        "FlowProof uninstall", "YesNo", "Question"
    )
    if ($choice -eq "Yes") {
        Invoke-ControllerAction "Removing services and preserving data..." {
            Uninstall-FlowProofAppliance $dataRootBox.Text | Out-Null
        } | Out-Null
        $progressText.Text = "FlowProof services were removed. Data remains in $($dataRootBox.Text)."
    }
})

Refresh-ControllerStatus
$window.ShowDialog() | Out-Null
