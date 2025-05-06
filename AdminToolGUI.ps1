Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Fonctions pour récupérer les informations système
function Get-PCUptime {
    $os = Get-WmiObject Win32_OperatingSystem
    $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
    return "$($uptime.Days) jours, $($uptime.Hours) heures, $($uptime.Minutes) minutes"
}

function Get-AdminStatus {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $(if ($isAdmin) { "Administrateur" } else { "Utilisateur standard" })
}

function Get-LocalUsers {
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, Description, @{Name="Groups";Expression={
            $userName = $_.Name
            $groups = Get-LocalGroup | Where-Object { 
                $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue
                $members | Where-Object { $_.Name -like "*\$userName" }
            } | Select-Object -ExpandProperty Name
            $groups -join ", "
        }}
        return $users
    }
    catch {
        return @( @{ Name="Erreur"; Enabled="N/A"; Description="Impossible de récupérer les utilisateurs"; Groups="N/A" } )
    }
}

function Get-SystemInfo {
    $os = Get-WmiObject Win32_OperatingSystem
    $cpu = Get-WmiObject Win32_Processor
    $memory = Get-WmiObject Win32_ComputerSystem
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
    
    $totalMemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    $freeMemoryGB = [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
    
    return @{
        OSVersion = $os.Caption
        OSBuild = $os.BuildNumber
        OSArchitecture = $os.OSArchitecture
        Processor = $cpu.Name
        CPUCores = $cpu.NumberOfCores
        CPULogicalProcessors = $cpu.NumberOfLogicalProcessors
        TotalRAM = "$totalMemoryGB GB"
        FreeRAM = "$freeMemoryGB GB"
        Drives = $drives | ForEach-Object {
            $driveLetter = $_.DeviceID
            $totalSizeGB = [math]::Round($_.Size / 1GB, 2)
            $freeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
            
            if ($_.Size -gt 0) {
                $percentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
                "$driveLetter : $freeSpaceGB GB libre sur $totalSizeGB GB ($percentFree%)"
            } else {
                "$driveLetter : $freeSpaceGB GB libre sur $totalSizeGB GB"
            }
        }
        IPAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }).IPAddress
    }
}

function Export-SystemInfo {
    param([string]$Path)
    
    $sysInfo = Get-SystemInfo
    $computerInfo = [ordered]@{
        "Nom du PC" = $env:COMPUTERNAME
        "Domaine" = if ($env:USERDOMAIN -eq $env:COMPUTERNAME) { "Groupe de travail" } else { $env:USERDOMAIN }
        "Système d'exploitation" = $sysInfo.OSVersion
        "Version OS" = $sysInfo.OSBuild
        "Architecture" = $sysInfo.OSArchitecture
        "Processeur" = $sysInfo.Processor
        "Cœurs CPU" = $sysInfo.CPUCores
        "Processeurs logiques" = $sysInfo.CPULogicalProcessors
        "Mémoire RAM" = $sysInfo.TotalRAM
        "RAM disponible" = $sysInfo.FreeRAM
        "Adresses IP" = ($sysInfo.IPAddresses -join ", ")
        "Disques" = ($sysInfo.Drives -join "`n")
        "Uptime" = Get-PCUptime
        "Statut utilisateur" = Get-AdminStatus
        "Date d'exportation" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $output = $computerInfo.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }
    $output | Out-File -FilePath $Path -Encoding UTF8
    return $Path
}

function Get-DiskUsageByUser {
    $users = Get-LocalUser
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    
    $result = @()
    foreach ($folder in $userFolders) {
        $userName = $folder.Name
        try {
            $size = Get-ChildItem -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue
            
            $sizeInGB = [math]::Round($size.Sum / 1GB, 2)
            if ([string]::IsNullOrEmpty($sizeInGB)) { $sizeInGB = 0 }
            
            $userExists = $users | Where-Object { $_.Name -eq $userName }
            
            $result += [PSCustomObject]@{
                UserName = $userName
                FolderPath = $folder.FullName
                SizeGB = $sizeInGB
                IsLocalUser = ($userExists -ne $null)
            }
        }
        catch {
            $result += [PSCustomObject]@{
                UserName = $userName
                FolderPath = $folder.FullName
                SizeGB = 0
                IsLocalUser = ($userExists -ne $null)
            }
        }
    }
    
    return $result | Sort-Object -Property SizeGB -Descending
}

function Get-PerformanceInfo {
    $os = Get-WmiObject Win32_OperatingSystem
    $processor = Get-WmiObject Win32_Processor
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    
    $totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
    $freeMemoryGB = [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
    $usedMemoryGB = $totalMemoryGB - $freeMemoryGB
    $memoryUsagePercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 1)
    
    $cpuLoad = $processor.LoadPercentage
    
    return @{
        TotalMemoryGB = $totalMemoryGB
        UsedMemoryGB = $usedMemoryGB
        FreeMemoryGB = $freeMemoryGB
        MemoryUsagePercent = $memoryUsagePercent
        CPULoadPercent = $cpuLoad
        CPUName = $processor.Name
        CPUCores = $processor.NumberOfCores
        CPULogicalProcessors = $processor.NumberOfLogicalProcessors
    }
}

# Nouvelle fonction pour récupérer les informations sur les cartes réseau
function Get-NetworkAdapterInfo {
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            $adapter = $_
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
            $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | 
                           Where-Object { $_.AddressFamily -eq "IPv4" } | 
                           Select-Object -ExpandProperty IPAddress
            
            # Déterminer si la carte est "utilisée" (a une IP et est connectée)
            $isUsed = ($adapter.Status -eq "Up") -and ($ipAddresses.Count -gt 0) -and ($ipConfig.IPv4DefaultGateway -ne $null)
            
            # Déterminer l'état de la carte
            $state = if ($adapter.Status -eq "Up") {
                        if ($isUsed) { "Actif" } else { "Actif (non utilisé)" }
                     } else {
                        "Inactif"
                     }
            
            # Récupérer les serveurs DNS
            $dnsServers = $ipConfig.DNSServer | Where-Object { $_.AddressFamily -eq "IPv4" } | Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
            if ($null -eq $dnsServers) { $dnsServers = @() }
            
            # Récupérer le statut de DHCP
            $dhcpEnabled = $ipConfig.IPv4Address.PrefixOrigin -eq "Dhcp"
            
            [PSCustomObject]@{
                Name = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                Status = $adapter.Status
                State = $state
                MacAddress = $adapter.MacAddress
                IPAddresses = $ipAddresses -join ", "
                DefaultGateway = if ($ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { "" }
                DNSServers = $dnsServers -join ", "
                DHCPEnabled = $dhcpEnabled
                InterfaceIndex = $adapter.ifIndex
                IsUsed = $isUsed
            }
        }
        return $adapters
    }
    catch {
        return @()
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Outil d'Administration"
$form.Size = New-Object System.Drawing.Size(950, 700)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.BackColor = [System.Drawing.Color]::WhiteSmoke

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"
$tabControl.Appearance = "Normal"

$tabSystem = New-Object System.Windows.Forms.TabPage
$tabSystem.Text = "Système"
$tabSystem.BackColor = [System.Drawing.Color]::WhiteSmoke
$tabControl.Controls.Add($tabSystem)

$scrollPanel = New-Object System.Windows.Forms.Panel
$scrollPanel.Dock = "Fill"
$scrollPanel.AutoScroll = $true

$panelSystem = New-Object System.Windows.Forms.TableLayoutPanel
$panelSystem.Dock = "Top"
$panelSystem.AutoSize = $true
$panelSystem.ColumnCount = 2
$panelSystem.RowCount = 15
$panelSystem.Padding = New-Object System.Windows.Forms.Padding(20)
$panelSystem.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 25)))
$panelSystem.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 75)))

for ($i = 0; $i -lt $panelSystem.RowCount; $i++) {
    $panelSystem.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 70)))
}

$sysInfo = Get-SystemInfo

$labelComputerName = New-Object System.Windows.Forms.Label
$labelComputerName.Text = "Nom du PC:"
$labelComputerName.Anchor = 'Left'
$labelComputerName.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
$labelComputerNameValue = New-Object System.Windows.Forms.Label
$labelComputerNameValue.Text = $env:COMPUTERNAME
$labelComputerNameValue.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$labelComputerNameValue.Anchor = 'Left'
$labelComputerNameValue.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$labelDomain = New-Object System.Windows.Forms.Label
$labelDomain.Text = "Domaine:"
$labelDomain.Anchor = 'Left'
$labelDomain.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
$labelDomainValue = New-Object System.Windows.Forms.Label
$labelDomainValue.Text = if ($env:USERDOMAIN -eq $env:COMPUTERNAME) { "Groupe de travail" } else { $env:USERDOMAIN }
$labelDomainValue.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$labelDomainValue.Anchor = 'Left'
$labelDomainValue.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$labelOS = New-Object System.Windows.Forms.Label
$labelOS.Text = "Système d'exploitation:"
$labelOS.Anchor = 'Left'
$labelOS.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
$labelOSValue = New-Object System.Windows.Forms.Label
$labelOSValue.Text = $sysInfo.OSVersion
$labelOSValue.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$labelOSValue.Anchor = 'Left'
$labelOSValue.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$labelIP = New-Object System.Windows.Forms.Label
$labelIP.Text = "Adresses IP:"
$labelIP.Anchor = 'Left'
$labelIP.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
$labelIPValue = New-Object System.Windows.Forms.Label
$labelIPValue.Text = ($sysInfo.IPAddresses -join ", ")
$labelIPValue.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$labelIPValue.Anchor = 'Left'
$labelIPValue.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$labelUptime = New-Object System.Windows.Forms.Label
$labelUptime.Text = "Uptime:"
$labelUptime.Anchor = 'Left'
$labelUptime.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
$labelUptimeValue = New-Object System.Windows.Forms.Label
$labelUptimeValue.Text = Get-PCUptime
$labelUptimeValue.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$labelUptimeValue.Anchor = 'Left'
$labelUptimeValue.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$labelAdmin = New-Object System.Windows.Forms.Label
$labelAdmin.Text = "Statut:"
$labelAdmin.Anchor = 'Left'
$labelAdmin.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
$labelAdminValue = New-Object System.Windows.Forms.Label
$labelAdminValue.Text = Get-AdminStatus
$labelAdminValue.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$labelAdminValue.Anchor = 'Left'
$labelAdminValue.ForeColor = if (Get-AdminStatus -eq "Administrateur") { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::FromArgb(0, 51, 153) }

$panelSystem.Controls.Add($labelComputerName, 0, 0)
$panelSystem.Controls.Add($labelComputerNameValue, 1, 0)
$panelSystem.Controls.Add($labelDomain, 0, 1)
$panelSystem.Controls.Add($labelDomainValue, 1, 1)
$panelSystem.Controls.Add($labelOS, 0, 2)
$panelSystem.Controls.Add($labelOSValue, 1, 2)
$panelSystem.Controls.Add($labelIP, 0, 3)
$panelSystem.Controls.Add($labelIPValue, 1, 3)
$panelSystem.Controls.Add($labelUptime, 0, 4)
$panelSystem.Controls.Add($labelUptimeValue, 1, 4)
$panelSystem.Controls.Add($labelAdmin, 0, 5)
$panelSystem.Controls.Add($labelAdminValue, 1, 5)

$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonPanel.Dock = "Bottom"
$buttonPanel.AutoSize = $true
$buttonPanel.FlowDirection = "LeftToRight"
$buttonPanel.WrapContents = $false
$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(20, 10, 20, 20)

$buttonRefreshSystem = New-Object System.Windows.Forms.Button
$buttonRefreshSystem.Text = "Rafraîchir les informations"
$buttonRefreshSystem.Width = 200
$buttonRefreshSystem.Height = 35
$buttonRefreshSystem.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonRefreshSystem.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonRefreshSystem.Add_Click({
    $sysInfo = Get-SystemInfo
    $labelOSValue.Text = $sysInfo.OSVersion
    $labelIPValue.Text = ($sysInfo.IPAddresses -join ", ")
    $labelUptimeValue.Text = Get-PCUptime
    $labelAdminValue.Text = Get-AdminStatus
})

$buttonExportSystem = New-Object System.Windows.Forms.Button
$buttonExportSystem.Text = "Exporter les informations"
$buttonExportSystem.Width = 200
$buttonExportSystem.Height = 35
$buttonExportSystem.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonExportSystem.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonExportSystem.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Fichiers texte (*.txt)|*.txt"
    $saveFileDialog.Title = "Exporter les informations système"
    $saveFileDialog.FileName = "InfosSysteme_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd').txt"
    
    if ($saveFileDialog.ShowDialog() -eq 'OK') {
        try {
            $filePath = Export-SystemInfo -Path $saveFileDialog.FileName
            [System.Windows.Forms.MessageBox]::Show("Informations système exportées avec succès dans:`n$filePath", "Exportation réussie", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de l'exportation: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$buttonExplorer = New-Object System.Windows.Forms.Button
$buttonExplorer.Text = "Explorateur Windows"
$buttonExplorer.Width = 200
$buttonExplorer.Height = 35
$buttonExplorer.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonExplorer.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonExplorer.Add_Click({
    Start-Process explorer.exe
})

$buttonPanel.Controls.Add($buttonRefreshSystem)
$buttonPanel.Controls.Add($buttonExportSystem)
$buttonPanel.Controls.Add($buttonExplorer)

$scrollPanel.Controls.Add($panelSystem)
$scrollPanel.Controls.Add($buttonPanel)
$tabSystem.Controls.Add($scrollPanel)

$tabPerformance = New-Object System.Windows.Forms.TabPage
$tabPerformance.Text = "Performance"
$tabPerformance.BackColor = [System.Drawing.Color]::WhiteSmoke
$tabControl.Controls.Add($tabPerformance)

$perfScrollPanel = New-Object System.Windows.Forms.Panel
$perfScrollPanel.Dock = "Fill"
$perfScrollPanel.AutoScroll = $true

$perfPanel = New-Object System.Windows.Forms.TableLayoutPanel
$perfPanel.Dock = "Top"
$perfPanel.AutoSize = $true
$perfPanel.ColumnCount = 1
$perfPanel.RowCount = 4
$perfPanel.Padding = New-Object System.Windows.Forms.Padding(20)

for ($i = 0; $i -lt $perfPanel.RowCount; $i++) {
    $perfPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
}

$cpuGroupBox = New-Object System.Windows.Forms.GroupBox
$cpuGroupBox.Text = "Processeur (CPU)"
$cpuGroupBox.Dock = "Fill"
$cpuGroupBox.Height = 200
$cpuGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)

$cpuPanel = New-Object System.Windows.Forms.TableLayoutPanel
$cpuPanel.Dock = "Fill"
$cpuPanel.ColumnCount = 2
$cpuPanel.RowCount = 4
$cpuPanel.Padding = New-Object System.Windows.Forms.Padding(10)

$cpuInfoLabel = New-Object System.Windows.Forms.Label
$cpuInfoLabel.Text = "Nom:"
$cpuInfoLabel.Anchor = "Left"
$cpuInfoLabel.AutoSize = $true

$cpuInfoValueLabel = New-Object System.Windows.Forms.Label
$cpuInfoValueLabel.Text = $sysInfo.Processor
$cpuInfoValueLabel.Anchor = "Left"
$cpuInfoValueLabel.AutoSize = $true
$cpuInfoValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$cpuInfoValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$cpuCoresLabel = New-Object System.Windows.Forms.Label
$cpuCoresLabel.Text = "Cœurs:"
$cpuCoresLabel.Anchor = "Left"
$cpuCoresLabel.AutoSize = $true

$cpuCoresValueLabel = New-Object System.Windows.Forms.Label
$cpuCoresValueLabel.Text = "$($sysInfo.CPUCores) cores / $($sysInfo.CPULogicalProcessors) processeurs logiques"
$cpuCoresValueLabel.Anchor = "Left"
$cpuCoresValueLabel.AutoSize = $true
$cpuCoresValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$cpuCoresValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$cpuUsageLabel = New-Object System.Windows.Forms.Label
$cpuUsageLabel.Text = "Utilisation:"
$cpuUsageLabel.Anchor = "Left"
$cpuUsageLabel.AutoSize = $true

$perfInfo = Get-PerformanceInfo
$cpuUsageValueLabel = New-Object System.Windows.Forms.Label
$cpuUsageValueLabel.Text = "$($perfInfo.CPULoadPercent)%"
$cpuUsageValueLabel.Anchor = "Left"
$cpuUsageValueLabel.AutoSize = $true
$cpuUsageValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$cpuUsageValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 102, 0)

$cpuProgressBar = New-Object System.Windows.Forms.ProgressBar
$cpuProgressBar.Minimum = 0
$cpuProgressBar.Maximum = 100
$cpuProgressBar.Value = $perfInfo.CPULoadPercent
$cpuProgressBar.Dock = "Fill"
$cpuProgressBar.Height = 30

$cpuPanel.Controls.Add($cpuInfoLabel, 0, 0)
$cpuPanel.Controls.Add($cpuInfoValueLabel, 1, 0)
$cpuPanel.Controls.Add($cpuCoresLabel, 0, 1)
$cpuPanel.Controls.Add($cpuCoresValueLabel, 1, 1)
$cpuPanel.Controls.Add($cpuUsageLabel, 0, 2)
$cpuPanel.Controls.Add($cpuUsageValueLabel, 1, 2)
$cpuPanel.Controls.Add($cpuProgressBar, 0, 3)
$cpuPanel.SetColumnSpan($cpuProgressBar, 2)

$cpuGroupBox.Controls.Add($cpuPanel)

$ramGroupBox = New-Object System.Windows.Forms.GroupBox
$ramGroupBox.Text = "Mémoire RAM"
$ramGroupBox.Dock = "Fill"
$ramGroupBox.Height = 200
$ramGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)

$ramPanel = New-Object System.Windows.Forms.TableLayoutPanel
$ramPanel.Dock = "Fill"
$ramPanel.ColumnCount = 2
$ramPanel.RowCount = 4
$ramPanel.Padding = New-Object System.Windows.Forms.Padding(10)

$ramTotalLabel = New-Object System.Windows.Forms.Label
$ramTotalLabel.Text = "Total:"
$ramTotalLabel.Anchor = "Left"
$ramTotalLabel.AutoSize = $true

$ramTotalValueLabel = New-Object System.Windows.Forms.Label
$ramTotalValueLabel.Text = "$($perfInfo.TotalMemoryGB) GB"
$ramTotalValueLabel.Anchor = "Left"
$ramTotalValueLabel.AutoSize = $true
$ramTotalValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$ramTotalValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 51, 153)

$ramUsedLabel = New-Object System.Windows.Forms.Label
$ramUsedLabel.Text = "Utilisée:"
$ramUsedLabel.Anchor = "Left"
$ramUsedLabel.AutoSize = $true

$ramUsedValueLabel = New-Object System.Windows.Forms.Label
$ramUsedValueLabel.Text = "$($perfInfo.UsedMemoryGB) GB ($($perfInfo.MemoryUsagePercent)%)"
$ramUsedValueLabel.Anchor = "Left"
$ramUsedValueLabel.AutoSize = $true
$ramUsedValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$ramUsedValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(204, 102, 0)

$ramFreeLabel = New-Object System.Windows.Forms.Label
$ramFreeLabel.Text = "Disponible:"
$ramFreeLabel.Anchor = "Left"
$ramFreeLabel.AutoSize = $true

$ramFreeValueLabel = New-Object System.Windows.Forms.Label
$ramFreeValueLabel.Text = "$($perfInfo.FreeMemoryGB) GB"
$ramFreeValueLabel.Anchor = "Left"
$ramFreeValueLabel.AutoSize = $true
$ramFreeValueLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$ramFreeValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 102, 0)

$ramProgressBar = New-Object System.Windows.Forms.ProgressBar
$ramProgressBar.Minimum = 0
$ramProgressBar.Maximum = 100
$ramProgressBar.Value = $perfInfo.MemoryUsagePercent
$ramProgressBar.Dock = "Fill"
$ramProgressBar.Height = 30

$ramPanel.Controls.Add($ramTotalLabel, 0, 0)
$ramPanel.Controls.Add($ramTotalValueLabel, 1, 0)
$ramPanel.Controls.Add($ramUsedLabel, 0, 1)
$ramPanel.Controls.Add($ramUsedValueLabel, 1, 1)
$ramPanel.Controls.Add($ramFreeLabel, 0, 2)
$ramPanel.Controls.Add($ramFreeValueLabel, 1, 2)
$ramPanel.Controls.Add($ramProgressBar, 0, 3)
$ramPanel.SetColumnSpan($ramProgressBar, 2)

$ramGroupBox.Controls.Add($ramPanel)

$buttonRefreshPerf = New-Object System.Windows.Forms.Button
$buttonRefreshPerf.Text = "Rafraîchir les performances"
$buttonRefreshPerf.Width = 200
$buttonRefreshPerf.Height = 35
$buttonRefreshPerf.Dock = "Top"
$buttonRefreshPerf.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonRefreshPerf.Add_Click({
    $perfInfo = Get-PerformanceInfo
    
    $cpuUsageValueLabel.Text = "$($perfInfo.CPULoadPercent)%"
    $cpuProgressBar.Value = $perfInfo.CPULoadPercent
    
    $ramTotalValueLabel.Text = "$($perfInfo.TotalMemoryGB) GB"
    $ramUsedValueLabel.Text = "$($perfInfo.UsedMemoryGB) GB ($($perfInfo.MemoryUsagePercent)%)"
    $ramFreeValueLabel.Text = "$($perfInfo.FreeMemoryGB) GB"
    $ramProgressBar.Value = $perfInfo.MemoryUsagePercent
})

$perfPanel.Controls.Add($cpuGroupBox, 0, 0)
$perfPanel.Controls.Add($ramGroupBox, 0, 1)
$perfPanel.Controls.Add($buttonRefreshPerf, 0, 2)

$perfScrollPanel.Controls.Add($perfPanel)
$tabPerformance.Controls.Add($perfScrollPanel)

$tabDisks = New-Object System.Windows.Forms.TabPage
$tabDisks.Text = "Disques"
$tabDisks.BackColor = [System.Drawing.Color]::WhiteSmoke
$tabControl.Controls.Add($tabDisks)

$disksPanel = New-Object System.Windows.Forms.TableLayoutPanel
$disksPanel.Dock = "Fill"
$disksPanel.ColumnCount = 1
$disksPanel.RowCount = 3
$disksPanel.Padding = New-Object System.Windows.Forms.Padding(20)
$disksPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 40)))
$disksPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 40)))
$disksPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 20)))

$disksGroupBox = New-Object System.Windows.Forms.GroupBox
$disksGroupBox.Text = "Disques physiques"
$disksGroupBox.Dock = "Fill"
$disksGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$listViewDisks = New-Object System.Windows.Forms.ListView
$listViewDisks.View = [System.Windows.Forms.View]::Details
$listViewDisks.FullRowSelect = $true
$listViewDisks.GridLines = $true
$listViewDisks.Dock = "Fill"
$listViewDisks.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$listViewDisks.Columns.Add("Lettre", 80) | Out-Null
$listViewDisks.Columns.Add("Capacité totale", 120) | Out-Null
$listViewDisks.Columns.Add("Espace libre", 120) | Out-Null
$listViewDisks.Columns.Add("% libre", 80) | Out-Null
$listViewDisks.Columns.Add("Type", 100) | Out-Null
$listViewDisks.Columns.Add("Format", 80) | Out-Null

$drives = Get-WmiObject Win32_LogicalDisk
foreach ($drive in $drives) {
    if ($drive.DriveType -eq 3) {
        $totalSizeGB = [math]::Round($drive.Size / 1GB, 2)
        $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        $percentFree = 0
        
        if ($drive.Size -gt 0) {
            $percentFree = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)
        }
        
        $item = New-Object System.Windows.Forms.ListViewItem($drive.DeviceID)
        $item.SubItems.Add("$totalSizeGB GB") | Out-Null
        $item.SubItems.Add("$freeSpaceGB GB") | Out-Null
        $item.SubItems.Add("$percentFree%") | Out-Null
        $item.SubItems.Add("Fixe") | Out-Null
        $item.SubItems.Add($drive.FileSystem) | Out-Null
        
        $listViewDisks.Items.Add($item) | Out-Null
    }
}

$disksGroupBox.Controls.Add($listViewDisks)

$userDiskGroupBox = New-Object System.Windows.Forms.GroupBox
$userDiskGroupBox.Text = "Utilisation par utilisateur (Dossiers C:\Users)"
$userDiskGroupBox.Dock = "Fill"
$userDiskGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$listViewUserDisk = New-Object System.Windows.Forms.ListView
$listViewUserDisk.View = [System.Windows.Forms.View]::Details
$listViewUserDisk.FullRowSelect = $true
$listViewUserDisk.GridLines = $true
$listViewUserDisk.Dock = "Fill"
$listViewUserDisk.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$listViewUserDisk.Columns.Add("Utilisateur", 150) | Out-Null
$listViewUserDisk.Columns.Add("Chemin", 250) | Out-Null
$listViewUserDisk.Columns.Add("Taille (GB)", 100) | Out-Null
$listViewUserDisk.Columns.Add("Utilisateur local", 100) | Out-Null

$userUsage = Get-DiskUsageByUser
foreach ($user in $userUsage) {
    $item = New-Object System.Windows.Forms.ListViewItem($user.UserName)
    $item.SubItems.Add($user.FolderPath) | Out-Null
    $item.SubItems.Add($user.SizeGB) | Out-Null
    $item.SubItems.Add($(if ($user.IsLocalUser) { "Oui" } else { "Non" })) | Out-Null
    
    $listViewUserDisk.Items.Add($item) | Out-Null
}

$userDiskGroupBox.Controls.Add($listViewUserDisk)

$diskButtonsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$diskButtonsPanel.Dock = "Fill"
$diskButtonsPanel.FlowDirection = "LeftToRight"
$diskButtonsPanel.WrapContents = $false
$diskButtonsPanel.AutoSize = $true

$buttonRefreshDisks = New-Object System.Windows.Forms.Button
$buttonRefreshDisks.Text = "Rafraîchir les informations disques"
$buttonRefreshDisks.Width = 250
$buttonRefreshDisks.Height = 35
$buttonRefreshDisks.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonRefreshDisks.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonRefreshDisks.Add_Click({
    $listViewDisks.Items.Clear()
    $drives = Get-WmiObject Win32_LogicalDisk
    foreach ($drive in $drives) {
        if ($drive.DriveType -eq 3) {
            $totalSizeGB = [math]::Round($drive.Size / 1GB, 2)
            $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $percentFree = 0
            
            if ($drive.Size -gt 0) {
                $percentFree = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 1)
            }
            
            $item = New-Object System.Windows.Forms.ListViewItem($drive.DeviceID)
            $item.SubItems.Add("$totalSizeGB GB") | Out-Null
            $item.SubItems.Add("$freeSpaceGB GB") | Out-Null
            $item.SubItems.Add("$percentFree%") | Out-Null
            $item.SubItems.Add("Fixe") | Out-Null
            $item.SubItems.Add($drive.FileSystem) | Out-Null
            
            $listViewDisks.Items.Add($item) | Out-Null
        }
    }
    
    $listViewUserDisk.Items.Clear()
    $userUsage = Get-DiskUsageByUser
    foreach ($user in $userUsage) {
        $item = New-Object System.Windows.Forms.ListViewItem($user.UserName)
        $item.SubItems.Add($user.FolderPath) | Out-Null
        $item.SubItems.Add($user.SizeGB) | Out-Null
        $item.SubItems.Add($(if ($user.IsLocalUser) { "Oui" } else { "Non" })) | Out-Null
        
        $listViewUserDisk.Items.Add($item) | Out-Null
    }
})

$buttonDiskMgmt = New-Object System.Windows.Forms.Button
$buttonDiskMgmt.Text = "Ouvrir le gestionnaire de disques"
$buttonDiskMgmt.Width = 250
$buttonDiskMgmt.Height = 35
$buttonDiskMgmt.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonDiskMgmt.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonDiskMgmt.Add_Click({
    Start-Process diskmgmt.msc
})

$diskButtonsPanel.Controls.Add($buttonRefreshDisks)
$diskButtonsPanel.Controls.Add($buttonDiskMgmt)

$disksPanel.Controls.Add($disksGroupBox, 0, 0)
$disksPanel.Controls.Add($userDiskGroupBox, 0, 1)
$disksPanel.Controls.Add($diskButtonsPanel, 0, 2)

$tabDisks.Controls.Add($disksPanel)

$tabUsers = New-Object System.Windows.Forms.TabPage
$tabUsers.Text = "Utilisateurs"
$tabUsers.BackColor = [System.Drawing.Color]::WhiteSmoke
$tabControl.Controls.Add($tabUsers)

$panelUsers = New-Object System.Windows.Forms.TableLayoutPanel
$panelUsers.Dock = "Fill"
$panelUsers.ColumnCount = 1
$panelUsers.RowCount = 2
$panelUsers.Padding = New-Object System.Windows.Forms.Padding(10)
$panelUsers.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 70)))
$panelUsers.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))

$dataGridUsers = New-Object System.Windows.Forms.DataGridView
$dataGridUsers.Dock = "Fill"
$dataGridUsers.AllowUserToAddRows = $false
$dataGridUsers.AllowUserToDeleteRows = $false
$dataGridUsers.ReadOnly = $true
$dataGridUsers.MultiSelect = $false
$dataGridUsers.SelectionMode = "FullRowSelect"
$dataGridUsers.AutoSizeColumnsMode = "Fill"
$dataGridUsers.RowHeadersVisible = $false
$dataGridUsers.AllowUserToResizeRows = $false

$panelUserActions = New-Object System.Windows.Forms.Panel
$panelUserActions.Dock = "Fill"

$buttonAddUser = New-Object System.Windows.Forms.Button
$buttonAddUser.Text = "Ajouter un utilisateur"
$buttonAddUser.Location = New-Object System.Drawing.Point(10, 10)
$buttonAddUser.Size = New-Object System.Drawing.Size(200, 30)
$buttonAddUser.Add_Click({
    $formAdd = New-Object System.Windows.Forms.Form
    $formAdd.Text = "Ajouter un utilisateur"
    $formAdd.Size = New-Object System.Drawing.Size(400, 300)
    $formAdd.StartPosition = "CenterParent"
    $formAdd.FormBorderStyle = "FixedDialog"
    $formAdd.MaximizeBox = $false
    $formAdd.MinimizeBox = $false
    
    $labelUserName = New-Object System.Windows.Forms.Label
    $labelUserName.Text = "Nom d'utilisateur:"
    $labelUserName.Location = New-Object System.Drawing.Point(10, 20)
    $labelUserName.Size = New-Object System.Drawing.Size(150, 23)
    $formAdd.Controls.Add($labelUserName)
    
    $textBoxUserName = New-Object System.Windows.Forms.TextBox
    $textBoxUserName.Location = New-Object System.Drawing.Point(160, 20)
    $textBoxUserName.Size = New-Object System.Drawing.Size(200, 23)
    $formAdd.Controls.Add($textBoxUserName)
    
    $labelPassword = New-Object System.Windows.Forms.Label
    $labelPassword.Text = "Mot de passe:"
    $labelPassword.Location = New-Object System.Drawing.Point(10, 50)
    $labelPassword.Size = New-Object System.Drawing.Size(150, 23)
    $formAdd.Controls.Add($labelPassword)
    
    $textBoxPassword = New-Object System.Windows.Forms.TextBox
    $textBoxPassword.Location = New-Object System.Drawing.Point(160, 50)
    $textBoxPassword.Size = New-Object System.Drawing.Size(200, 23)
    $textBoxPassword.PasswordChar = '*'
    $formAdd.Controls.Add($textBoxPassword)
    
    $labelDesc = New-Object System.Windows.Forms.Label
    $labelDesc.Text = "Description:"
    $labelDesc.Location = New-Object System.Drawing.Point(10, 80)
    $labelDesc.Size = New-Object System.Drawing.Size(150, 23)
    $formAdd.Controls.Add($labelDesc)
    
    $textBoxDesc = New-Object System.Windows.Forms.TextBox
    $textBoxDesc.Location = New-Object System.Drawing.Point(160, 80)
    $textBoxDesc.Size = New-Object System.Drawing.Size(200, 23)
    $formAdd.Controls.Add($textBoxDesc)
    
    $checkBoxAdmin = New-Object System.Windows.Forms.CheckBox
    $checkBoxAdmin.Text = "Administrateur"
    $checkBoxAdmin.Location = New-Object System.Drawing.Point(160, 110)
    $checkBoxAdmin.Size = New-Object System.Drawing.Size(200, 23)
    $formAdd.Controls.Add($checkBoxAdmin)
    
    $buttonCreate = New-Object System.Windows.Forms.Button
    $buttonCreate.Text = "Créer"
    $buttonCreate.Location = New-Object System.Drawing.Point(160, 150)
    $buttonCreate.Size = New-Object System.Drawing.Size(100, 30)
    $buttonCreate.Add_Click({
        try {
            $password = ConvertTo-SecureString $textBoxPassword.Text -AsPlainText -Force
            New-LocalUser -Name $textBoxUserName.Text -Password $password -Description $textBoxDesc.Text -ErrorAction Stop
            
            if ($checkBoxAdmin.Checked) {
                Add-LocalGroupMember -Group "Administrateurs" -Member $textBoxUserName.Text -ErrorAction SilentlyContinue
                Add-LocalGroupMember -Group "Administrators" -Member $textBoxUserName.Text -ErrorAction SilentlyContinue
            }
            
            $dataGridUsers.DataSource = [System.Collections.ArrayList]@(Get-LocalUsers)
            
            [System.Windows.Forms.MessageBox]::Show("Utilisateur créé avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            $formAdd.Close()
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de la création de l'utilisateur: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    })
    $formAdd.Controls.Add($buttonCreate)
    
    $buttonCancel = New-Object System.Windows.Forms.Button
    $buttonCancel.Text = "Annuler"
    $buttonCancel.Location = New-Object System.Drawing.Point(270, 150)
    $buttonCancel.Size = New-Object System.Drawing.Size(100, 30)
    $buttonCancel.Add_Click({ $formAdd.Close() })
    $formAdd.Controls.Add($buttonCancel)
    
    $formAdd.ShowDialog()
})

$buttonDeleteUser = New-Object System.Windows.Forms.Button
$buttonDeleteUser.Text = "Supprimer l'utilisateur"
$buttonDeleteUser.Location = New-Object System.Drawing.Point(220, 10)
$buttonDeleteUser.Size = New-Object System.Drawing.Size(200, 30)
$buttonDeleteUser.Add_Click({
    if ($dataGridUsers.SelectedRows.Count -gt 0) {
        $userName = $dataGridUsers.SelectedRows[0].Cells["Name"].Value
        
        $result = [System.Windows.Forms.MessageBox]::Show("Êtes-vous sûr de vouloir supprimer l'utilisateur '$userName'?", "Confirmation", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($result -eq "Yes") {
            try {
                Remove-LocalUser -Name $userName -ErrorAction Stop
                $dataGridUsers.DataSource = [System.Collections.ArrayList]@(Get-LocalUsers)
                [System.Windows.Forms.MessageBox]::Show("Utilisateur supprimé avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Erreur lors de la suppression de l'utilisateur: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner un utilisateur.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$buttonChangeAdmin = New-Object System.Windows.Forms.Button
$buttonChangeAdmin.Text = "Modifier statut admin"
$buttonChangeAdmin.Location = New-Object System.Drawing.Point(430, 10)
$buttonChangeAdmin.Size = New-Object System.Drawing.Size(200, 30)
$buttonChangeAdmin.Add_Click({
    if ($dataGridUsers.SelectedRows.Count -gt 0) {
        $userName = $dataGridUsers.SelectedRows[0].Cells["Name"].Value
        $groups = $dataGridUsers.SelectedRows[0].Cells["Groups"].Value
        
        $isAdmin = $groups -match "Administrateurs|Administrators"
        
        $result = [System.Windows.Forms.MessageBox]::Show("Voulez-vous " + $(if ($isAdmin) { "retirer" } else { "ajouter" }) + " les droits d'administrateur pour '$userName'?", "Confirmation", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($result -eq "Yes") {
            try {
                if ($isAdmin) {
                    Remove-LocalGroupMember -Group "Administrateurs" -Member $userName -ErrorAction SilentlyContinue
                    Remove-LocalGroupMember -Group "Administrators" -Member $userName -ErrorAction SilentlyContinue
                }
                else {
                    Add-LocalGroupMember -Group "Administrateurs" -Member $userName -ErrorAction SilentlyContinue
                    Add-LocalGroupMember -Group "Administrators" -Member $userName -ErrorAction SilentlyContinue
                }
                
                $dataGridUsers.DataSource = [System.Collections.ArrayList]@(Get-LocalUsers)
                [System.Windows.Forms.MessageBox]::Show("Statut administrateur modifié avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Erreur lors de la modification du statut administrateur: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner un utilisateur.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$buttonRefresh = New-Object System.Windows.Forms.Button
$buttonRefresh.Text = "Actualiser"
$buttonRefresh.Location = New-Object System.Drawing.Point(640, 10)
$buttonRefresh.Size = New-Object System.Drawing.Size(100, 30)
$buttonRefresh.Add_Click({
    try {
        $users = Get-LocalUsers
        $dataGridUsers.DataSource = [System.Collections.ArrayList]@($users)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Erreur lors de l'actualisation de la liste des utilisateurs: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$panelUserActions.Controls.Add($buttonAddUser)
$panelUserActions.Controls.Add($buttonDeleteUser)
$panelUserActions.Controls.Add($buttonChangeAdmin)
$panelUserActions.Controls.Add($buttonRefresh)

$panelUsers.Controls.Add($dataGridUsers, 0, 0)
$panelUsers.Controls.Add($panelUserActions, 0, 1)
$tabUsers.Controls.Add($panelUsers)

$tabNetwork = New-Object System.Windows.Forms.TabPage
$tabNetwork.Text = "Réseau"
$tabNetwork.BackColor = [System.Drawing.Color]::WhiteSmoke
$tabControl.Controls.Add($tabNetwork)

# Panel principal pour l'onglet réseau
$networkPanel = New-Object System.Windows.Forms.TableLayoutPanel
$networkPanel.Dock = "Fill"
$networkPanel.ColumnCount = 1
$networkPanel.RowCount = 2
$networkPanel.Padding = New-Object System.Windows.Forms.Padding(20)
$networkPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 70)))
$networkPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))

# ListView pour afficher les cartes réseau
$listViewNetwork = New-Object System.Windows.Forms.ListView
$listViewNetwork.View = [System.Windows.Forms.View]::Details
$listViewNetwork.FullRowSelect = $true
$listViewNetwork.GridLines = $true
$listViewNetwork.Dock = "Fill"
$listViewNetwork.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Définir les couleurs pour différents états
$colorActive = [System.Drawing.Color]::FromArgb(225, 255, 225)  # Vert clair
$colorInactive = [System.Drawing.Color]::FromArgb(255, 225, 225)  # Rouge clair
$colorUnused = [System.Drawing.Color]::FromArgb(255, 240, 200)  # Orange clair

# Ajout des colonnes à la ListView
$listViewNetwork.Columns.Add("Nom", 150) | Out-Null
$listViewNetwork.Columns.Add("Description", 200) | Out-Null
$listViewNetwork.Columns.Add("État", 100) | Out-Null
$listViewNetwork.Columns.Add("Adresse MAC", 120) | Out-Null
$listViewNetwork.Columns.Add("Adresse(s) IP", 150) | Out-Null
$listViewNetwork.Columns.Add("Passerelle", 100) | Out-Null
$listViewNetwork.Columns.Add("Serveurs DNS", 150) | Out-Null
$listViewNetwork.Columns.Add("DHCP", 50) | Out-Null

# Fonction pour peupler la ListView
function Update-NetworkListView {
    $listViewNetwork.Items.Clear()
    $adapters = Get-NetworkAdapterInfo
    
    foreach ($adapter in $adapters) {
        $item = New-Object System.Windows.Forms.ListViewItem($adapter.Name)
        $item.UseItemStyleForSubItems = $false
        $item.Tag = $adapter.InterfaceIndex  # Stocker l'index pour les opérations ultérieures
        
        $item.SubItems.Add($adapter.InterfaceDescription) | Out-Null
        $stateItem = $item.SubItems.Add($adapter.State) | Out-Null
        $item.SubItems.Add($adapter.MacAddress) | Out-Null
        $item.SubItems.Add($adapter.IPAddresses) | Out-Null
        $item.SubItems.Add($adapter.DefaultGateway) | Out-Null
        $item.SubItems.Add($adapter.DNSServers) | Out-Null
        $item.SubItems.Add($(if ($adapter.DHCPEnabled) { "Oui" } else { "Non" })) | Out-Null
        
        # Définir la couleur de la ligne selon l'état
        if ($adapter.State -eq "Actif") {
            for ($i = 0; $i -lt $item.SubItems.Count; $i++) {
                $item.SubItems[$i].BackColor = $colorActive
            }
        }
        elseif ($adapter.State -eq "Inactif") {
            for ($i = 0; $i -lt $item.SubItems.Count; $i++) {
                $item.SubItems[$i].BackColor = $colorInactive
            }
        }
        else {  # Actif mais non utilisé
            for ($i = 0; $i -lt $item.SubItems.Count; $i++) {
                $item.SubItems[$i].BackColor = $colorUnused
            }
        }
        
        $listViewNetwork.Items.Add($item) | Out-Null
    }
}

# Panel pour les boutons d'action
$networkButtonsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$networkButtonsPanel.Dock = "Fill"
$networkButtonsPanel.FlowDirection = "LeftToRight"
$networkButtonsPanel.WrapContents = $true
$networkButtonsPanel.AutoSize = $true
$networkButtonsPanel.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

# Bouton pour rafraîchir la liste des cartes réseau
$buttonRefreshNetwork = New-Object System.Windows.Forms.Button
$buttonRefreshNetwork.Text = "Rafraîchir"
$buttonRefreshNetwork.Width = 120
$buttonRefreshNetwork.Height = 35
$buttonRefreshNetwork.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonRefreshNetwork.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonRefreshNetwork.Add_Click({
    Update-NetworkListView
})

# Bouton pour activer une carte réseau
$buttonEnableAdapter = New-Object System.Windows.Forms.Button
$buttonEnableAdapter.Text = "Activer"
$buttonEnableAdapter.Width = 120
$buttonEnableAdapter.Height = 35
$buttonEnableAdapter.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonEnableAdapter.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonEnableAdapter.Add_Click({
    if ($listViewNetwork.SelectedItems.Count -gt 0) {
        $interfaceIndex = $listViewNetwork.SelectedItems[0].Tag
        try {
            Enable-NetAdapter -InterfaceIndex $interfaceIndex -Confirm:$false -ErrorAction Stop
            Update-NetworkListView
            [System.Windows.Forms.MessageBox]::Show("Carte réseau activée avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de l'activation de la carte réseau: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner une carte réseau.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# Bouton pour désactiver une carte réseau
$buttonDisableAdapter = New-Object System.Windows.Forms.Button
$buttonDisableAdapter.Text = "Désactiver"
$buttonDisableAdapter.Width = 120
$buttonDisableAdapter.Height = 35
$buttonDisableAdapter.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonDisableAdapter.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonDisableAdapter.Add_Click({
    if ($listViewNetwork.SelectedItems.Count -gt 0) {
        $interfaceIndex = $listViewNetwork.SelectedItems[0].Tag
        try {
            Disable-NetAdapter -InterfaceIndex $interfaceIndex -Confirm:$false -ErrorAction Stop
            Update-NetworkListView
            [System.Windows.Forms.MessageBox]::Show("Carte réseau désactivée avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de la désactivation de la carte réseau: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner une carte réseau.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# Bouton pour modifier les paramètres IP
$buttonModifyIP = New-Object System.Windows.Forms.Button
$buttonModifyIP.Text = "Modifier IP"
$buttonModifyIP.Width = 120
$buttonModifyIP.Height = 35
$buttonModifyIP.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonModifyIP.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonModifyIP.Add_Click({
    if ($listViewNetwork.SelectedItems.Count -gt 0) {
        $interfaceIndex = $listViewNetwork.SelectedItems[0].Tag
        $adapterInfo = Get-NetworkAdapterInfo | Where-Object { $_.InterfaceIndex -eq $interfaceIndex }
        
        # Créer un formulaire pour la modification d'IP
        $formIP = New-Object System.Windows.Forms.Form
        $formIP.Text = "Modifier les paramètres IP de $($adapterInfo.Name)"
        $formIP.Size = New-Object System.Drawing.Size(450, 350)
        $formIP.StartPosition = "CenterParent"
        $formIP.FormBorderStyle = "FixedDialog"
        $formIP.MaximizeBox = $false
        $formIP.MinimizeBox = $false
        $formIP.BackColor = [System.Drawing.Color]::WhiteSmoke
        
        # Récupération des informations actuelles
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $interfaceIndex
        $currentIPv4 = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $dhcpEnabled = $ipConfig.IPv4Address.PrefixOrigin -eq "Dhcp"
        
        # Groupe pour DHCP/Statique
        $groupBoxIPMode = New-Object System.Windows.Forms.GroupBox
        $groupBoxIPMode.Text = "Mode de configuration IP"
        $groupBoxIPMode.Location = New-Object System.Drawing.Point(20, 20)
        $groupBoxIPMode.Size = New-Object System.Drawing.Size(390, 60)
        
        $radioDHCP = New-Object System.Windows.Forms.RadioButton
        $radioDHCP.Text = "Obtenir une adresse IP automatiquement (DHCP)"
        $radioDHCP.Location = New-Object System.Drawing.Point(10, 20)
        $radioDHCP.Size = New-Object System.Drawing.Size(350, 30)
        $radioDHCP.Checked = $dhcpEnabled
        
        $radioStatic = New-Object System.Windows.Forms.RadioButton
        $radioStatic.Text = "Utiliser l'adresse IP suivante"
        $radioStatic.Location = New-Object System.Drawing.Point(10, 50)
        $radioStatic.Size = New-Object System.Drawing.Size(350, 30)
        $radioStatic.Checked = -not $dhcpEnabled
        
        $groupBoxIPMode.Controls.Add($radioDHCP)
        $groupBoxIPMode.Controls.Add($radioStatic)
        
        # Groupe pour les paramètres IP
        $groupBoxIPSettings = New-Object System.Windows.Forms.GroupBox
        $groupBoxIPSettings.Text = "Paramètres IP"
        $groupBoxIPSettings.Location = New-Object System.Drawing.Point(20, 90)
        $groupBoxIPSettings.Size = New-Object System.Drawing.Size(390, 150)
        
        # Adresse IP
        $labelIP = New-Object System.Windows.Forms.Label
        $labelIP.Text = "Adresse IP:"
        $labelIP.Location = New-Object System.Drawing.Point(10, 30)
        $labelIP.Size = New-Object System.Drawing.Size(120, 23)
        
        $textBoxIP = New-Object System.Windows.Forms.TextBox
        $textBoxIP.Location = New-Object System.Drawing.Point(150, 30)
        $textBoxIP.Size = New-Object System.Drawing.Size(220, 23)
        $textBoxIP.Text = $currentIPv4.IPAddress
        $textBoxIP.Enabled = -not $dhcpEnabled
        
        # Masque de sous-réseau
        $labelSubnet = New-Object System.Windows.Forms.Label
        $labelSubnet.Text = "Masque de sous-réseau:"
        $labelSubnet.Location = New-Object System.Drawing.Point(10, 60)
        $labelSubnet.Size = New-Object System.Drawing.Size(140, 23)
        
        $textBoxSubnet = New-Object System.Windows.Forms.TextBox
        $textBoxSubnet.Location = New-Object System.Drawing.Point(150, 60)
        $textBoxSubnet.Size = New-Object System.Drawing.Size(220, 23)
        $textBoxSubnet.Text = if ($currentIPv4) { $currentIPv4.PrefixLength } else { "24" }
        $textBoxSubnet.Enabled = -not $dhcpEnabled
        
        # Passerelle par défaut
        $labelGateway = New-Object System.Windows.Forms.Label
        $labelGateway.Text = "Passerelle par défaut:"
        $labelGateway.Location = New-Object System.Drawing.Point(10, 90)
        $labelGateway.Size = New-Object System.Drawing.Size(140, 23)
        
        $textBoxGateway = New-Object System.Windows.Forms.TextBox
        $textBoxGateway.Location = New-Object System.Drawing.Point(150, 90)
        $textBoxGateway.Size = New-Object System.Drawing.Size(220, 23)
        $textBoxGateway.Text = if ($ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { "" }
        $textBoxGateway.Enabled = -not $dhcpEnabled
        
        # Serveurs DNS
        $labelDNS = New-Object System.Windows.Forms.Label
        $labelDNS.Text = "Serveurs DNS:"
        $labelDNS.Location = New-Object System.Drawing.Point(10, 120)
        $labelDNS.Size = New-Object System.Drawing.Size(140, 23)
        
        $textBoxDNS = New-Object System.Windows.Forms.TextBox
        $textBoxDNS.Location = New-Object System.Drawing.Point(150, 120)
        $textBoxDNS.Size = New-Object System.Drawing.Size(220, 23)
        $textBoxDNS.Text = $adapterInfo.DNSServers
        $textBoxDNS.Enabled = -not $dhcpEnabled
        
        $groupBoxIPSettings.Controls.Add($labelIP)
        $groupBoxIPSettings.Controls.Add($textBoxIP)
        $groupBoxIPSettings.Controls.Add($labelSubnet)
        $groupBoxIPSettings.Controls.Add($textBoxSubnet)
        $groupBoxIPSettings.Controls.Add($labelGateway)
        $groupBoxIPSettings.Controls.Add($textBoxGateway)
        $groupBoxIPSettings.Controls.Add($labelDNS)
        $groupBoxIPSettings.Controls.Add($textBoxDNS)
        
        # Activer/désactiver les champs en fonction du mode DHCP
        $radioDHCP.Add_CheckedChanged({
            $textBoxIP.Enabled = -not $radioDHCP.Checked
            $textBoxSubnet.Enabled = -not $radioDHCP.Checked
            $textBoxGateway.Enabled = -not $radioDHCP.Checked
            $textBoxDNS.Enabled = -not $radioDHCP.Checked
        })
        
        # Boutons OK et Annuler
        $buttonOK = New-Object System.Windows.Forms.Button
        $buttonOK.Text = "Appliquer"
        $buttonOK.Location = New-Object System.Drawing.Point(150, 260)
        $buttonOK.Size = New-Object System.Drawing.Size(100, 30)
        $buttonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $buttonOK.Add_Click({
            try {
                if ($radioDHCP.Checked) {
                    # Configuration DHCP
                    Set-NetIPInterface -InterfaceIndex $interfaceIndex -Dhcp Enabled -ErrorAction Stop
                    
                    # Configurer les serveurs DNS en DHCP
                    Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ResetServerAddresses -ErrorAction Stop
                }
                else {
                    # Vérifier que les champs sont remplis
                    if ([string]::IsNullOrWhiteSpace($textBoxIP.Text) -or [string]::IsNullOrWhiteSpace($textBoxSubnet.Text)) {
                        [System.Windows.Forms.MessageBox]::Show("Veuillez remplir tous les champs obligatoires.", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                        return
                    }
                    
                    # Configuration statique IP
                    $gateway = if (-not [string]::IsNullOrWhiteSpace($textBoxGateway.Text)) { $textBoxGateway.Text } else { $null }
                    
                    # Supprimer les anciennes configurations
                    if ($currentIPv4) {
                        Remove-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    
                    if ($gateway) {
                        Remove-NetRoute -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    
                    # Ajouter la nouvelle configuration IP
                    New-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -IPAddress $textBoxIP.Text -PrefixLength $textBoxSubnet.Text -DefaultGateway $gateway -ErrorAction Stop | Out-Null
                    
                    # Configurer les serveurs DNS
                    if (-not [string]::IsNullOrWhiteSpace($textBoxDNS.Text)) {
                        $dnsServers = $textBoxDNS.Text -split "[,;\s]+" | Where-Object { $_ -ne "" }
                        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses $dnsServers -ErrorAction Stop
                    }
                }
                
                $formIP.Close()
                Update-NetworkListView
                [System.Windows.Forms.MessageBox]::Show("Configuration IP modifiée avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Erreur lors de la modification des paramètres IP: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        })
        
        $buttonCancel = New-Object System.Windows.Forms.Button
        $buttonCancel.Text = "Annuler"
        $buttonCancel.Location = New-Object System.Drawing.Point(260, 260)
        $buttonCancel.Size = New-Object System.Drawing.Size(100, 30)
        $buttonCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $buttonCancel.Add_Click({ $formIP.Close() })
        
        # Ajouter les contrôles au formulaire
        $formIP.Controls.Add($groupBoxIPMode)
        $formIP.Controls.Add($groupBoxIPSettings)
        $formIP.Controls.Add($buttonOK)
        $formIP.Controls.Add($buttonCancel)
        
        $formIP.ShowDialog() | Out-Null
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner une carte réseau.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# Bouton pour ouvrir le Centre Réseau et partage
$buttonNetworkCenter = New-Object System.Windows.Forms.Button
$buttonNetworkCenter.Text = "Centre Réseau"
$buttonNetworkCenter.Width = 120
$buttonNetworkCenter.Height = 35
$buttonNetworkCenter.Margin = New-Object System.Windows.Forms.Padding(10)
$buttonNetworkCenter.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonNetworkCenter.Add_Click({
    Start-Process control.exe -ArgumentList "ncpa.cpl"
})

# Ajouter les boutons au panel
$networkButtonsPanel.Controls.Add($buttonRefreshNetwork)
$networkButtonsPanel.Controls.Add($buttonEnableAdapter)
$networkButtonsPanel.Controls.Add($buttonDisableAdapter)
$networkButtonsPanel.Controls.Add($buttonModifyIP)
$networkButtonsPanel.Controls.Add($buttonNetworkCenter)

# Ajouter les contrôles au panel principal
$networkPanel.Controls.Add($listViewNetwork, 0, 0)
$networkPanel.Controls.Add($networkButtonsPanel, 0, 1)

# Ajouter le panel à l'onglet
$tabNetwork.Controls.Add($networkPanel)

$form.Controls.Add($tabControl)

$dataGridUsers.DataSource = [System.Collections.ArrayList]@(Get-LocalUsers)

$form.Add_Shown({
    $form.Activate()
})

# Initialiser la liste des adaptateurs réseau
Update-NetworkListView

[void]$form.ShowDialog()
