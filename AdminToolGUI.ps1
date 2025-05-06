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
        # Récupérer d'abord tous les adaptateurs en un seul appel
        $allAdapters = Get-NetAdapter -ErrorAction Stop
        
        $adapters = $allAdapters | ForEach-Object {
            $adapter = $_
            
            try {
                # Vérifier si l'interface existe toujours avant de récupérer sa configuration
                $adapterStillExists = Get-NetAdapter -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
                
                if ($null -eq $adapterStillExists) {
                    # L'interface a disparu entre-temps, retourner des infos minimales
                    return [PSCustomObject]@{
                        Name = $adapter.Name
                        InterfaceDescription = $adapter.InterfaceDescription
                        Status = "Indisponible"
                        State = "Erreur - Interface disparue"
                        MacAddress = $adapter.MacAddress
                        IPAddresses = ""
                        DefaultGateway = ""
                        DNSServers = ""
                        DHCPEnabled = $false
                        InterfaceIndex = $adapter.ifIndex
                        IsUsed = $false
                    }
                }
                
                # Récupérer la configuration IP avec gestion d'erreurs plus robuste
                $ipConfig = $null
                try {
                    $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
                }
                catch {
                    # En cas d'échec, essayer une alternative plus légère
                    $ipConfig = $null
                }
                
                $ipAddresses = @()
                try {
                    $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                                Select-Object -ExpandProperty IPAddress
                    # Si aucune adresse n'est trouvée, utiliser un tableau vide
                    if ($null -eq $ipAddresses) { $ipAddresses = @() }
                } catch {
                    # En cas d'erreur, utiliser un tableau vide
                    $ipAddresses = @()
                }
                
                # Déterminer si la carte est "utilisée" (a une IP et est connectée)
                $isUsed = ($adapter.Status -eq "Up") -and ($ipAddresses.Count -gt 0) -and 
                          ($null -ne $ipConfig) -and 
                          ($null -ne $ipConfig.IPv4DefaultGateway)
                
                # Déterminer l'état de la carte
                $state = if ($adapter.Status -eq "Up") {
                            if ($isUsed) { "Actif" } else { "Actif (non utilisé)" }
                         } else {
                            "Inactif"
                         }
                
                # Récupérer les serveurs DNS avec gestion d'erreur
                $dnsServers = @()
                if ($null -ne $ipConfig -and $null -ne $ipConfig.DNSServer) {
                    try {
                        $dnsServers = $ipConfig.DNSServer | 
                                    Where-Object { $null -ne $_ -and $_.AddressFamily -eq "IPv4" } | 
                                    Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
                    }
                    catch {
                        # En cas d'erreur, garder un tableau vide
                    }
                    
                    if ($null -eq $dnsServers) { $dnsServers = @() }
                }
                
                # Récupérer le statut de DHCP avec gestion d'erreur
                $dhcpEnabled = $false
                if ($null -ne $ipConfig -and $null -ne $ipConfig.IPv4Address) {
                    $dhcpEnabled = $ipConfig.IPv4Address.PrefixOrigin -eq "Dhcp"
                }
                
                # Récupérer la passerelle avec gestion d'erreur
                $gateway = ""
                if ($null -ne $ipConfig -and $null -ne $ipConfig.IPv4DefaultGateway) {
                    $gateway = $ipConfig.IPv4DefaultGateway.NextHop
                }
                
                [PSCustomObject]@{
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    State = $state
                    MacAddress = $adapter.MacAddress
                    IPAddresses = $ipAddresses -join ", "
                    DefaultGateway = $gateway
                    DNSServers = $dnsServers -join ", "
                    DHCPEnabled = $dhcpEnabled
                    InterfaceIndex = $adapter.ifIndex
                    IsUsed = $isUsed
                }
            }
            catch {
                # En cas d'erreur sur un adaptateur spécifique, retourner un objet avec des informations minimales
                [PSCustomObject]@{
                    Name = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    State = "Erreur"
                    MacAddress = $adapter.MacAddress
                    IPAddresses = ""
                    DefaultGateway = ""
                    DNSServers = ""
                    DHCPEnabled = $false
                    InterfaceIndex = $adapter.ifIndex
                    IsUsed = $false
                }
            }
        }
        return $adapters
    }
    catch {
        Write-Warning "Erreur lors de la récupération des adaptateurs réseau: $($_.Exception.Message)"
        return @()
    }
}

# Fonction pour peupler la ListView - optimisée
function Update-NetworkListView {
    $listViewNetwork.Items.Clear()
    
    try {
        $adapters = Get-NetworkAdapterInfo
        
        # Commence le mode mise à jour groupée pour améliorer les performances
        $listViewNetwork.BeginUpdate()
        
        foreach ($adapter in $adapters) {
            try {
                # Vérification finale que l'interface existe toujours avant d'ajouter à la liste
                $adapterStillExists = Get-NetAdapter -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($null -eq $adapterStillExists) {
                    continue  # Ignorer les interfaces qui ont disparu entre-temps
                }
                
                # Création de l'élément et de ses propriétés
                $item = New-Object System.Windows.Forms.ListViewItem($adapter.Name)
                $item.UseItemStyleForSubItems = $false
                $item.Tag = $adapter.InterfaceIndex  # Stocker l'index pour les opérations ultérieures
                
                # Ajout des sous-éléments
                [void]$item.SubItems.Add($adapter.InterfaceDescription)
                [void]$item.SubItems.Add($adapter.State)
                [void]$item.SubItems.Add($adapter.MacAddress)
                [void]$item.SubItems.Add($adapter.IPAddresses)
                [void]$item.SubItems.Add($adapter.DefaultGateway)
                [void]$item.SubItems.Add($adapter.DNSServers)
                [void]$item.SubItems.Add($(if ($adapter.DHCPEnabled) { "Oui" } else { "Non" }))
                
                # Déterminer la couleur de fond en fonction de l'état
                $backgroundColor = switch -Wildcard ($adapter.State) {
                    "Actif" { $colorActive }
                    "Inactif" { $colorInactive }
                    "Erreur*" { [System.Drawing.Color]::FromArgb(230, 230, 230) }  # Gris clair
                    default { $colorUnused }  # Actif mais non utilisé ou autre état
                }
                
                # Appliquer la couleur à tous les sous-éléments
                foreach ($subItem in $item.SubItems) {
                    $subItem.BackColor = $backgroundColor
                }
                
                # Ajouter l'élément à la ListView
                [void]$listViewNetwork.Items.Add($item)
            }
            catch {
                # Journaliser l'erreur avec plus de détails
                $errorMsg = "Erreur lors de l'ajout de l'adaptateur '$($adapter.Name)' (Index: $($adapter.InterfaceIndex)): $($_.Exception.Message)"
                Write-Warning $errorMsg
            }
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Erreur lors de la mise à jour de la liste des interfaces réseau: $($_.Exception.Message)",
            "Erreur",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally {
        # Toujours terminer le mode mise à jour groupée, même en cas d'erreur
        $listViewNetwork.EndUpdate()
    }
}

# Fonction pour télécharger et charger les assemblies nécessaires pour le sniffing
function Load-SnifferAssemblies {
    # Déterminer le chemin pour les assemblies
    # Si $PSScriptRoot est vide (par exemple lors de l'exécution dans la console), utiliser un chemin alternatif
    $assembliesPath = if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        Join-Path $env:USERPROFILE "Documents\BebzToolGUI\lib"
    } else {
        Join-Path $PSScriptRoot "lib"
    }
    
    # Créer le dossier s'il n'existe pas
    if (-not (Test-Path $assembliesPath)) {
        try {
            New-Item -Path $assembliesPath -ItemType Directory -Force | Out-Null
            Write-Host "Dossier créé: $assembliesPath"
        } catch {
            $errorMsg = "Erreur lors de la création du dossier $assembliesPath : $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($errorMsg, "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return $false
        }
    }
    
    # URLs des packages NuGet - inclure des URLs alternatives
    $sharpPcapUrl = @(
        "https://github.com/chmorgan/sharppcap/releases/download/6.2.5/SharpPcap.6.2.5.nupkg",
        "https://www.nuget.org/api/v2/package/SharpPcap/6.2.5"
    )
    $packetDotNetUrl = @(
        "https://github.com/chmorgan/packetnet/releases/download/1.4.0/PacketDotNet.1.4.0.nupkg",
        "https://www.nuget.org/api/v2/package/PacketDotNet/1.4.0"
    )
    
    $sharpPcapPath = Join-Path $assembliesPath "SharpPcap.dll"
    $packetDotNetPath = Join-Path $assembliesPath "PacketDotNet.dll"
    
    if (-not (Test-Path $sharpPcapPath) -or -not (Test-Path $packetDotNetPath)) {
        try {
            # Téléchargement des packages NuGet avec stratégie de nouvelle tentative
            $sharpPcapNupkg = Join-Path $assembliesPath "SharpPcap.nupkg"
            $packetDotNetNupkg = Join-Path $assembliesPath "PacketDotNet.nupkg"
            
            # Fonction pour télécharger avec retries
            function Download-FileWithRetry {
                param (
                    [string[]]$Urls,
                    [string]$OutputPath,
                    [string]$Description,
                    [int]$MaxRetries = 3
                )
                
                $retryCount = 0
                $downloadSuccess = $false
                $lastError = $null
                
                while (-not $downloadSuccess -and $retryCount -lt $MaxRetries -and $Urls.Count -gt 0) {
                    $currentUrl = $Urls[0]
                    $Urls = $Urls[1..$Urls.Length]  # Passer à l'URL suivante
                    
                    Write-Host "Téléchargement de $Description depuis $currentUrl (tentative $($retryCount + 1)/$MaxRetries)..."
                    
                    try {
                        # Premier essai avec Invoke-WebRequest
                        try {
                            Invoke-WebRequest -Uri $currentUrl -OutFile $OutputPath -TimeoutSec 30
                            $downloadSuccess = $true
                            Write-Host "Téléchargement réussi!"
                            break
                        }
                        catch {
                            Write-Host "Échec avec Invoke-WebRequest, tentative avec WebClient..."
                            # En cas d'échec, essayer avec WebClient
                            $webClient = New-Object System.Net.WebClient
                            $webClient.Headers.Add("User-Agent", "PowerShell Script")
                            $webClient.DownloadFile($currentUrl, $OutputPath)
                            $downloadSuccess = $true
                            Write-Host "Téléchargement réussi avec WebClient!"
                            break
                        }
                    }
                    catch {
                        $lastError = $_
                        $retryCount++
                        Write-Host "Échec du téléchargement: $($_.Exception.Message)"
                        
                        if ($retryCount -lt $MaxRetries -and $Urls.Count -gt 0) {
                            Write-Host "Nouvelle tentative dans 2 secondes..."
                            Start-Sleep -Seconds 2
                        }
                    }
                }
                
                if (-not $downloadSuccess) {
                    throw "Impossible de télécharger $Description après $MaxRetries tentatives. Dernière erreur: $($lastError.Exception.Message)"
                }
                
                return $downloadSuccess
            }
            
            # Télécharger SharpPcap
            $sharpPcapDownloaded = Download-FileWithRetry -Urls $sharpPcapUrl -OutputPath $sharpPcapNupkg -Description "SharpPcap"
            # Télécharger PacketDotNet
            $packetDotNetDownloaded = Download-FileWithRetry -Urls $packetDotNetUrl -OutputPath $packetDotNetNupkg -Description "PacketDotNet"
            
            if (-not ($sharpPcapDownloaded -and $packetDotNetDownloaded)) {
                # Si le téléchargement automatique échoue, proposer un téléchargement manuel
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Le téléchargement automatique a échoué. Voulez-vous ouvrir les pages web pour télécharger manuellement les bibliothèques?",
                    "Téléchargement manuel",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                
                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    Start-Process "https://www.nuget.org/packages/SharpPcap/6.2.5"
                    Start-Process "https://www.nuget.org/packages/PacketDotNet/1.4.0"
                    
                    [System.Windows.Forms.MessageBox]::Show(
                        "1. Téléchargez les packages NuGet (.nupkg)`n" +
                        "2. Renommez-les en .zip et extrayez-les`n" +
                        "3. Copiez les fichiers .dll du dossier lib\netstandard2.0 vers:`n" +
                        "$assembliesPath",
                        "Instructions de téléchargement manuel",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                }
                return $false
            }
            
            # Extraire les DLL des packages NuGet
            $sharpPcapZip = Join-Path $assembliesPath "SharpPcap.zip"
            $packetDotNetZip = Join-Path $assembliesPath "PacketDotNet.zip"
            
            # Vérifier si les fichiers existent avant de les renommer
            if (Test-Path $sharpPcapNupkg) {
                Copy-Item -Path $sharpPcapNupkg -Destination $sharpPcapZip -Force
            } else {
                throw "Le fichier téléchargé SharpPcap n'existe pas"
            }
            
            if (Test-Path $packetDotNetNupkg) {
                Copy-Item -Path $packetDotNetNupkg -Destination $packetDotNetZip -Force
            } else {
                throw "Le fichier téléchargé PacketDotNet n'existe pas"
            }
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            
            $sharpPcapExtract = Join-Path $assembliesPath "SharpPcapExtract"
            $packetDotNetExtract = Join-Path $assembliesPath "PacketDotNetExtract"
            
            # Supprimer les dossiers d'extraction s'ils existent déjà
            if (Test-Path $sharpPcapExtract) {
                Remove-Item -Path $sharpPcapExtract -Recurse -Force
            }
            if (Test-Path $packetDotNetExtract) {
                Remove-Item -Path $packetDotNetExtract -Recurse -Force
            }
            
            # Extraire les archives avec gestion des erreurs
            try {
                [System.IO.Compression.ZipFile]::ExtractToDirectory($sharpPcapZip, $sharpPcapExtract)
                [System.IO.Compression.ZipFile]::ExtractToDirectory($packetDotNetZip, $packetDotNetExtract)
            }
            catch {
                throw "Erreur lors de l'extraction des archives: $($_.Exception.Message)"
            }
            
            # Rechercher les DLL dans les packages extraits
            $sharpPcapDllPath = Get-ChildItem -Path $sharpPcapExtract -Filter "SharpPcap.dll" -Recurse | Select-Object -First 1 -ExpandProperty FullName
            $packetDotNetDllPath = Get-ChildItem -Path $packetDotNetExtract -Filter "PacketDotNet.dll" -Recurse | Select-Object -First 1 -ExpandProperty FullName
            
            if (-not $sharpPcapDllPath) {
                throw "DLL SharpPcap.dll introuvable dans le package téléchargé"
            }
            if (-not $packetDotNetDllPath) {
                throw "DLL PacketDotNet.dll introuvable dans le package téléchargé"
            }
            
            # Copier les DLL vers le dossier lib
            Copy-Item -Path $sharpPcapDllPath -Destination $sharpPcapPath -Force
            Copy-Item -Path $packetDotNetDllPath -Destination $packetDotNetPath -Force
            
            Write-Host "DLL copiées avec succès: SharpPcap.dll et PacketDotNet.dll"
            
            # Nettoyage
            try {
                if (Test-Path $sharpPcapZip) { Remove-Item -Path $sharpPcapZip -Force }
                if (Test-Path $packetDotNetZip) { Remove-Item -Path $packetDotNetZip -Force }
                if (Test-Path $sharpPcapNupkg) { Remove-Item -Path $sharpPcapNupkg -Force }
                if (Test-Path $packetDotNetNupkg) { Remove-Item -Path $packetDotNetNupkg -Force }
                if (Test-Path $sharpPcapExtract) { Remove-Item -Path $sharpPcapExtract -Recurse -Force }
                if (Test-Path $packetDotNetExtract) { Remove-Item -Path $packetDotNetExtract -Recurse -Force }
            }
            catch {
                Write-Host "Attention: impossible de nettoyer certains fichiers temporaires: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        catch {
            $errorMsg = "Erreur lors du téléchargement des bibliothèques nécessaires: $($_.Exception.Message)"
            Write-Host $errorMsg -ForegroundColor Red
            
            # Vérifier si les DLL existent quand même (téléchargées partiellement mais utilisables)
            if ((Test-Path $sharpPcapPath) -and (Test-Path $packetDotNetPath)) {
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Une erreur s'est produite pendant le téléchargement, mais des versions des bibliothèques semblent exister sur le disque. Voulez-vous essayer de les utiliser quand même?",
                    "Erreur partielle",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                
                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    # Continuer et essayer d'utiliser les DLL existantes
                    goto TryExistingDlls
                }
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                $errorMsg,
                "Erreur",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return $false
        }
    }
    
    # Étiquette pour aller directement à l'essai de chargement des DLL existantes
    TryExistingDlls:
    try {
        Write-Host "Chargement des assemblies à partir de: $sharpPcapPath et $packetDotNetPath"
        Add-Type -Path $sharpPcapPath
        Add-Type -Path $packetDotNetPath
        Write-Host "Chargement des bibliothèques réussi!" -ForegroundColor Green
        return $true
    }
    catch {
        $errorMsg = "Erreur lors du chargement des bibliothèques: $($_.Exception.Message)"
        Write-Host $errorMsg -ForegroundColor Red
        [System.Windows.Forms.MessageBox]::Show(
            $errorMsg,
            "Erreur",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $false
    }
}

# Classe pour représenter un paquet réseau capturé
class NetworkPacket {
    [int]$Id
    [DateTime]$Time
    [string]$Source
    [string]$Destination
    [string]$Protocol
    [int]$Length
    [string]$Info
    [byte[]]$RawData
    
    NetworkPacket($id, $time, $source, $dest, $proto, $len, $info, $data) {
        $this.Id = $id
        $this.Time = $time
        $this.Source = $source
        $this.Destination = $dest
        $this.Protocol = $proto
        $this.Length = $len
        $this.Info = $info
        $this.RawData = $data
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
            # Vérifier si l'interface existe toujours
            $adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex -ErrorAction Stop
            if ($null -eq $adapter) {
                throw "Interface réseau non trouvée"
            }
            
            Enable-NetAdapter -InterfaceIndex $interfaceIndex -Confirm:$false -ErrorAction Stop
            Update-NetworkListView
            [System.Windows.Forms.MessageBox]::Show("Carte réseau activée avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            # Actualiser la vue pour éliminer les références aux interfaces disparues
            Update-NetworkListView
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
            # Vérifier si l'interface existe toujours
            $adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex -ErrorAction Stop
            if ($null -eq $adapter) {
                throw "Interface réseau non trouvée"
            }
            
            Disable-NetAdapter -InterfaceIndex $interfaceIndex -Confirm:$false -ErrorAction Stop
            Update-NetworkListView
            [System.Windows.Forms.MessageBox]::Show("Carte réseau désactivée avec succès.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
        catch {
            # Actualiser la vue pour éliminer les références aux interfaces disparues
            Update-NetworkListView
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de la désactivation de la carte réseau: $($_.Exception.Message)", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
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
$networkButtonsPanel.Controls.Add($buttonNetworkCenter)

# Ajouter les contrôles au panel principal
$networkPanel.Controls.Add($listViewNetwork, 0, 0)
$networkPanel.Controls.Add($networkButtonsPanel, 0, 1)

# Ajouter le panel à l'onglet
$tabNetwork.Controls.Add($networkPanel)

# Ajout du nouvel onglet Sniffer
$tabSniffer = New-Object System.Windows.Forms.TabPage
$tabSniffer.Text = "Sniffer Réseau"
$tabSniffer.BackColor = [System.Drawing.Color]::WhiteSmoke
$tabControl.Controls.Add($tabSniffer)

# Panel principal pour l'onglet Sniffer
$snifferPanel = New-Object System.Windows.Forms.TableLayoutPanel
$snifferPanel.Dock = "Fill"
$snifferPanel.ColumnCount = 1
$snifferPanel.RowCount = 4
$snifferPanel.Padding = New-Object System.Windows.Forms.Padding(10)
$snifferPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40)))
$snifferPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40)))
$snifferPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 70)))
$snifferPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))

# Panel pour les contrôles de sélection d'interface
$interfacePanel = New-Object System.Windows.Forms.FlowLayoutPanel
$interfacePanel.Dock = "Fill"
$interfacePanel.FlowDirection = "LeftToRight"
$interfacePanel.WrapContents = $false
$interfacePanel.AutoSize = $true

# Combobox pour sélectionner l'interface réseau
$labelInterface = New-Object System.Windows.Forms.Label
$labelInterface.Text = "Interface réseau:"
$labelInterface.AutoSize = $true
$labelInterface.Margin = New-Object System.Windows.Forms.Padding(0, 6, 5, 0)

$comboInterfaces = New-Object System.Windows.Forms.ComboBox
$comboInterfaces.Width = 350
$comboInterfaces.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$comboInterfaces.Margin = New-Object System.Windows.Forms.Padding(0, 3, 10, 3)

# Boutons de contrôle de capture
$buttonStartCapture = New-Object System.Windows.Forms.Button
$buttonStartCapture.Text = "Démarrer la capture"
$buttonStartCapture.Width = 150
$buttonStartCapture.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonStartCapture.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)

$buttonStopCapture = New-Object System.Windows.Forms.Button
$buttonStopCapture.Text = "Arrêter la capture"
$buttonStopCapture.Width = 150
$buttonStopCapture.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonStopCapture.Enabled = $false
$buttonStopCapture.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)

# Ajouter les contrôles au panel d'interface
$interfacePanel.Controls.Add($labelInterface)
$interfacePanel.Controls.Add($comboInterfaces)
$interfacePanel.Controls.Add($buttonStartCapture)
$interfacePanel.Controls.Add($buttonStopCapture)

# Panel pour les filtres
$filterPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$filterPanel.Dock = "Fill"
$filterPanel.FlowDirection = "LeftToRight"
$filterPanel.WrapContents = $false
$filterPanel.AutoSize = $true

# Contrôles de filtrage
$labelFilter = New-Object System.Windows.Forms.Label
$labelFilter.Text = "Filtre:"
$labelFilter.AutoSize = $true
$labelFilter.Margin = New-Object System.Windows.Forms.Padding(0, 6, 5, 0)

$comboFilterField = New-Object System.Windows.Forms.ComboBox
$comboFilterField.Width = 120
$comboFilterField.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$comboFilterField.Items.AddRange(@("Tout", "Source", "Destination", "Protocole"))
$comboFilterField.SelectedIndex = 0
$comboFilterField.Margin = New-Object System.Windows.Forms.Padding(0, 3, 5, 3)

$textBoxFilterValue = New-Object System.Windows.Forms.TextBox
$textBoxFilterValue.Width = 200
$textBoxFilterValue.Margin = New-Object System.Windows.Forms.Padding(0, 3, 10, 3)

$buttonApplyFilter = New-Object System.Windows.Forms.Button
$buttonApplyFilter.Text = "Appliquer le filtre"
$buttonApplyFilter.Width = 120
$buttonApplyFilter.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonApplyFilter.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)

$buttonClearFilter = New-Object System.Windows.Forms.Button
$buttonClearFilter.Text = "Effacer le filtre"
$buttonClearFilter.Width = 120
$buttonClearFilter.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonClearFilter.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)

$buttonClearPackets = New-Object System.Windows.Forms.Button
$buttonClearPackets.Text = "Effacer les paquets"
$buttonClearPackets.Width = 140
$buttonClearPackets.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$buttonClearPackets.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)

# Ajouter les contrôles au panel de filtres
$filterPanel.Controls.Add($labelFilter)
$filterPanel.Controls.Add($comboFilterField)
$filterPanel.Controls.Add($textBoxFilterValue)
$filterPanel.Controls.Add($buttonApplyFilter)
$filterPanel.Controls.Add($buttonClearFilter)
$filterPanel.Controls.Add($buttonClearPackets)

# ListView pour afficher les paquets capturés
$listViewPackets = New-Object System.Windows.Forms.ListView
$listViewPackets.View = [System.Windows.Forms.View]::Details
$listViewPackets.FullRowSelect = $true
$listViewPackets.GridLines = $true
$listViewPackets.MultiSelect = $false
$listViewPackets.Dock = "Fill"
$listViewPackets.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Ajout des colonnes
$listViewPackets.Columns.Add("#", 50) | Out-Null
$listViewPackets.Columns.Add("Heure", 120) | Out-Null
$listViewPackets.Columns.Add("Source", 150) | Out-Null
$listViewPackets.Columns.Add("Destination", 150) | Out-Null
$listViewPackets.Columns.Add("Protocole", 100) | Out-Null
$listViewPackets.Columns.Add("Longueur", 80) | Out-Null
$listViewPackets.Columns.Add("Info", 250) | Out-Null

# RichTextBox pour afficher les détails du paquet
$textBoxPacketDetails = New-Object System.Windows.Forms.RichTextBox
$textBoxPacketDetails.Dock = "Fill"
$textBoxPacketDetails.Font = New-Object System.Drawing.Font("Consolas", 9)
$textBoxPacketDetails.ReadOnly = $true
$textBoxPacketDetails.BackColor = [System.Drawing.Color]::White

# Ajouter les contrôles au panel principal
$snifferPanel.Controls.Add($interfacePanel, 0, 0)
$snifferPanel.Controls.Add($filterPanel, 0, 1)
$snifferPanel.Controls.Add($listViewPackets, 0, 2)
$snifferPanel.Controls.Add($textBoxPacketDetails, 0, 3)

# Ajouter le panel principal à l'onglet
$tabSniffer.Controls.Add($snifferPanel)

# Variables globales pour la capture
$script:captureDevice = $null
$script:isCapturing = $false
$script:packetCount = 0
$script:capturedPackets = New-Object System.Collections.ArrayList
$script:displayedPackets = New-Object System.Collections.ArrayList
$script:syncHash = [hashtable]::Synchronized(@{})
$script:syncHash.Form = $form
$script:syncHash.ListView = $listViewPackets
$script:syncHash.TextBox = $textBoxPacketDetails
$script:syncHash.Count = 0
$script:syncHash.Packets = $script:capturedPackets
$script:syncHash.Displayed = $script:displayedPackets

# Fonction pour remplir la liste des interfaces réseau
function Update-InterfaceList {
    $comboInterfaces.Items.Clear()
    
    try {
        # Vérifier si les assemblies sont chargés
        if (-not ([System.Management.Automation.PSTypeName]'SharpPcap.LibPcap.LibPcapLiveDevice').Type) {
            if (-not (Load-SnifferAssemblies)) {
                return
            }
        }
        
        $devices = [SharpPcap.LibPcap.LibPcapLiveDeviceList]::Instance
        foreach ($device in $devices) {
            if (-not [string]::IsNullOrEmpty($device.Interface.FriendlyName)) {
                # Récupération sécurisée de l'adresse IP
                $ipAddress = "Non disponible"
                try {
                    $ipAddresses = $device.Addresses | Where-Object { 
                        $_.Addr -ne $null -and 
                        $_.Addr.ipAddress -ne $null -and 
                        $_.Addr.ipAddress -ne [System.String]::Empty
                    } 
                    
                    if ($ipAddresses -ne $null) {
                        $firstIP = $ipAddresses | Select-Object -First 1 | ForEach-Object { $_.Addr.ipAddress }
                        if ($firstIP -ne $null -and $firstIP -ne [System.String]::Empty) {
                            $ipAddress = $firstIP
                        }
                    }
                }
                catch {
                    # En cas d'erreur, on garde "Non disponible"
                }
                
                $displayName = "$($device.Interface.FriendlyName) ($ipAddress)"
                $comboInterfaces.Items.Add($displayName) | Out-Null
                $comboInterfaces.Tag = $devices
            }
        }
        
        if ($comboInterfaces.Items.Count -gt 0) {
            $comboInterfaces.SelectedIndex = 0
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Erreur lors de la récupération des interfaces réseau: $($_.Exception.Message)",
            "Erreur",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

# Fonction pour analyser et formatter un paquet
function Format-PacketDetails {
    param (
        [Parameter(Mandatory=$true)]
        [NetworkPacket]$Packet
    )
    
    $sb = New-Object System.Text.StringBuilder
    
    # En-tête général
    $sb.AppendLine("DÉTAILS DU PAQUET #$($Packet.Id)") | Out-Null
    $sb.AppendLine("====================") | Out-Null
    $sb.AppendLine("Heure: $($Packet.Time)") | Out-Null
    $sb.AppendLine("Longueur: $($Packet.Length) octets") | Out-Null
    $sb.AppendLine() | Out-Null
    
    # En-tête d'adresses
    $sb.AppendLine("ADRESSES") | Out-Null
    $sb.AppendLine("----------") | Out-Null
    $sb.AppendLine("Source: $($Packet.Source)") | Out-Null
    $sb.AppendLine("Destination: $($Packet.Destination)") | Out-Null
    $sb.AppendLine() | Out-Null
    
    # Information de protocole
    $sb.AppendLine("PROTOCOLE: $($Packet.Protocol)") | Out-Null
    $sb.AppendLine("----------") | Out-Null
    $sb.AppendLine("$($Packet.Info)") | Out-Null
    $sb.AppendLine() | Out-Null
    
    # Données brutes en hexadécimal
    $sb.AppendLine("DONNÉES BRUTES (HEX)") | Out-Null
    $sb.AppendLine("--------------------") | Out-Null
    
    # Formatter les données en hexadécimal avec 16 octets par ligne
    $hexData = $Packet.RawData | ForEach-Object { $_.ToString("X2") } 
    $asciiData = $Packet.RawData | ForEach-Object {
        if ($_ -ge 32 -and $_ -le 126) {
            [char]$_
        } else {
            "."
        }
    }
    
    $offset = 0
    while ($offset -lt $Packet.RawData.Length) {
        # Ajouter l'offset
        $sb.Append($offset.ToString("X4") + "  ") | Out-Null
        
        # Ajouter les valeurs hex
        for ($i = 0; $i -lt 16; $i++) {
            if ($offset + $i -lt $hexData.Length) {
                $sb.Append($hexData[$offset + $i] + " ") | Out-Null
            } else {
                $sb.Append("   ") | Out-Null
            }
            
            # Ajouter un espace supplémentaire au milieu
            if ($i -eq 7) {
                $sb.Append(" ") | Out-Null
            }
        }
        
        # Ajouter les caractères ASCII
        $sb.Append(" |") | Out-Null
        for ($i = 0; $i -lt 16; $i++) {
            if ($offset + $i -lt $asciiData.Length) {
                $sb.Append($asciiData[$offset + $i]) | Out-Null
            } else {
                $sb.Append(" ") | Out-Null
            }
        }
        $sb.Append("|") | Out-Null
        $sb.AppendLine() | Out-Null
        
        $offset += 16
    }
    
    return $sb.ToString()
}

# Fonction pour filtrer les paquets
function Filter-Packets {
    $filterField = $comboFilterField.SelectedItem
    $filterValue = $textBoxFilterValue.Text.Trim()
    
    $script:displayedPackets.Clear()
        }
        
        $protocol_colors = @(
            [System.Drawing.Color]::Black,              # Default
            [System.Drawing.Color]::FromArgb(0, 100, 0), # HTTP/HTTPS (Green)
            [System.Drawing.Color]::FromArgb(0, 0, 180), # TCP (Blue)
            [System.Drawing.Color]::FromArgb(160, 0, 160), # UDP (Purple)
            [System.Drawing.Color]::FromArgb(200, 0, 0),  # ICMP (Red)
            [System.Drawing.Color]::FromArgb(180, 100, 0), # DNS (Orange)
            [System.Drawing.Color]::FromArgb(0, 100, 150)  # ARP (Cyan)
        )
        
        $item.SubItems[4].ForeColor = $protocol_colors[$colorIndex]
        
        $listViewPackets.Items.Add($item) | Out-Null
    }
    
    $listViewPackets.EndUpdate()
}

# Fonction pour démarrer la capture
function Start-PacketCapture {
    if ($script:isCapturing) { return }
    
    try {
        $selectedIndex = $comboInterfaces.SelectedIndex
        if ($selectedIndex -lt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Veuillez sélectionner une interface réseau.",
                "Erreur",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }
        
        $devices = $comboInterfaces.Tag
        $script:captureDevice = $devices[$selectedIndex]
        
        # Ouvrir le périphérique pour la capture
        $script:captureDevice.Open([SharpPcap.DeviceModes]::Promiscuous, 100)
        
        # Configurer le gestionnaire d'événements de capture
        $script:captureDevice.add_OnPacketArrival({
            param($sender, $e)
            
            $packet = $e.GetPacket()
            $rawData = $packet.Data
            $packetTime = $packet.Timeval.Date
            
            # Analyser le paquet avec PacketDotNet
            $parsedPacket = [PacketDotNet.Packet]::ParsePacket($packet.LinkLayerType, $rawData)
            if ($parsedPacket -eq $null) {
                return
            }
            
            # Extraire les informations du paquet selon son type
            $source = "Inconnu"
            $destination = "Inconnu"
            $protocol = "Inconnu"
            $info = ""
            
            $ethernetPacket = [PacketDotNet.EthernetPacket]$parsedPacket
            if ($ethernetPacket -ne $null) {
                $source = $ethernetPacket.SourceHardwareAddress.ToString()
                $destination = $ethernetPacket.DestinationHardwareAddress.ToString()
                
                # Vérifier le type de paquet encapsulé
                if ($ethernetPacket.PayloadPacket -is [PacketDotNet.IpPacket]) {
                    $ipPacket = [PacketDotNet.IpPacket]$ethernetPacket.PayloadPacket
                    $source = $ipPacket.SourceAddress.ToString()
                    $destination = $ipPacket.DestinationAddress.ToString()
                    
                    if ($ipPacket.PayloadPacket -is [PacketDotNet.TcpPacket]) {
                        $tcpPacket = [PacketDotNet.TcpPacket]$ipPacket.PayloadPacket
                        $protocol = "TCP"
                        $source = "$source`:$($tcpPacket.SourcePort)"
                        $destination = "$destination`:$($tcpPacket.DestinationPort)"
                        
                        # Détection des protocoles applicatifs courants
                        if ($tcpPacket.SourcePort -eq 80 -or $tcpPacket.DestinationPort -eq 80) {
                            $protocol = "HTTP"
                        }
                        elseif ($tcpPacket.SourcePort -eq 443 -or $tcpPacket.DestinationPort -eq 443) {
                            $protocol = "HTTPS"
                        }
                        
                        $info = "SPort: $($tcpPacket.SourcePort), DPort: $($tcpPacket.DestinationPort), Seq: $($tcpPacket.SequenceNumber), Ack: $($tcpPacket.AcknowledgmentNumber), Flags: $($tcpPacket.Flags)"
                    }
                    elseif ($ipPacket.PayloadPacket -is [PacketDotNet.UdpPacket]) {
                        $udpPacket = [PacketDotNet.UdpPacket]$ipPacket.PayloadPacket
                        $protocol = "UDP"
                        $source = "$source`:$($udpPacket.SourcePort)"
                        $destination = "$destination`:$($udpPacket.DestinationPort)"
                        
                        # Détection DNS
                        if ($udpPacket.SourcePort -eq 53 -or $udpPacket.DestinationPort -eq 53) {
                            $protocol = "DNS"
                        }
                        
                        $info = "SPort: $($udpPacket.SourcePort), DPort: $($udpPacket.DestinationPort), Len: $($udpPacket.Length)"
                    }
                    elseif ($ipPacket.PayloadPacket -is [PacketDotNet.IcmpV4Packet]) {
                        $icmpPacket = [PacketDotNet.IcmpV4Packet]$ipPacket.PayloadPacket
                        $protocol = "ICMP"
                        $info = "Type: $($icmpPacket.TypeCode.Type), Code: $($icmpPacket.TypeCode.Code)"
                    }
                    else {
                        $protocol = "IP"
                        $info = "Protocol: $($ipPacket.Protocol), TTL: $($ipPacket.TimeToLive)"
                    }
                }
                elseif ($ethernetPacket.PayloadPacket -is [PacketDotNet.ArpPacket]) {
                    $arpPacket = [PacketDotNet.ArpPacket]$ethernetPacket.PayloadPacket
                    $protocol = "ARP"
                    $source = $arpPacket.SenderProtocolAddress.ToString()
                    $destination = $arpPacket.TargetProtocolAddress.ToString()
                    $info = "Operation: $($arpPacket.Operation), SHA: $($arpPacket.SenderHardwareAddress), THA: $($arpPacket.TargetHardwareAddress)"
                }
                else {
                    $protocol = "ETH"
                    $info = "Type: $($ethernetPacket.Type)"
                }
            }
            
            # Créer et ajouter le paquet à la liste
            $script:syncHash.Count++
            $netPacket = [NetworkPacket]::new(
                $script:syncHash.Count,
                $packetTime,
                $source,
                $destination,
                $protocol,
                $rawData.Length,
                $info,
                $rawData
            )
            
            [void]$script:syncHash.Packets.Add($netPacket)
            [void]$script:syncHash.Displayed.Add($netPacket)
            
            # Mettre à jour l'interface utilisateur depuis le thread principal
            $script:syncHash.Form.Invoke([Action]{
                # Ajouter le paquet à la ListView sans effacer tous les éléments
                $item = New-Object System.Windows.Forms.ListViewItem($netPacket.Id)
                $item.UseItemStyleForSubItems = $false
                $item.Tag = $netPacket
                
                # Ajouter les sous-éléments
                [void]$item.SubItems.Add($netPacket.Time.ToString("HH:mm:ss.fff"))
                [void]$item.SubItems.Add($netPacket.Source)
                [void]$item.SubItems.Add($netPacket.Destination)
                [void]$item.SubItems.Add($netPacket.Protocol)
                [void]$item.SubItems.Add($netPacket.Length)
                [void]$item.SubItems.Add($netPacket.Info)
                
                # Coloration selon le protocole
                $colorIndex = 0
                switch ($netPacket.Protocol) {
                    "HTTP" { $colorIndex = 1 }
                    "HTTPS" { $colorIndex = 1 }
                    "TCP" { $colorIndex = 2 }
                    "UDP" { $colorIndex = 3 }
                    "ICMP" { $colorIndex = 4 }
                    "DNS" { $colorIndex = 5 }
                    "ARP" { $colorIndex = 6 }
                }
                
                $protocol_colors = @(
                    [System.Drawing.Color]::Black,              # Default
                    [System.Drawing.Color]::FromArgb(0, 100, 0), # HTTP/HTTPS (Green)
                    [System.Drawing.Color]::FromArgb(0, 0, 180), # TCP (Blue)
                    [System.Drawing.Color]::FromArgb(160, 0, 160), # UDP (Purple)
                    [System.Drawing.Color]::FromArgb(200, 0, 0),  # ICMP (Red)
                    [System.Drawing.Color]::FromArgb(180, 100, 0), # DNS (Orange)
                    [System.Drawing.Color]::FromArgb(0, 100, 150)  # ARP (Cyan)
                )
                
                $item.SubItems[4].ForeColor = $protocol_colors[$colorIndex]
                
                [void]$script:syncHash.ListView.Items.Add($item)
                
                # Si la ListView est trop grande, supprimer les anciens éléments
                if ($script:syncHash.ListView.Items.Count > 10000) {
                    $script:syncHash.ListView.Items.RemoveAt(0)
                }
                
                # Défiler automatiquement vers le bas
                if ($script:syncHash.ListView.Items.Count > 0) {
                    $script:syncHash.ListView.EnsureVisible($script:syncHash.ListView.Items.Count - 1)
                }
            })
        })
        
        # Démarrer la capture en arrière-plan
        $script:captureDevice.StartCapture()
        $script:isCapturing = $true
        
        # Mettre à jour l'état des boutons
        $buttonStartCapture.Enabled = $false
        $buttonStopCapture.Enabled = $true
        $comboInterfaces.Enabled = $false
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Erreur lors du démarrage de la capture: $($_.Exception.Message)",
            "Erreur",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

# Fonction pour arrêter la capture
function Stop-PacketCapture {
    if (-not $script:isCapturing) { return }
    
    try {
        if ($script:captureDevice -ne $null) {
            $script:captureDevice.StopCapture()
            $script:captureDevice.Close()
            $script:captureDevice = $null
        }
        
        $script:isCapturing = $false
        
        # Mettre à jour l'état des boutons
        $buttonStartCapture.Enabled = $true
        $buttonStopCapture.Enabled = $false
        $comboInterfaces.Enabled = $true
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Erreur lors de l'arrêt de la capture: $($_.Exception.Message)",
            "Erreur",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}

# Événement de sélection d'un paquet
$listViewPackets.Add_SelectedIndexChanged({
    if ($listViewPackets.SelectedItems.Count -gt 0) {
        $selectedPacket = $listViewPackets.SelectedItems[0].Tag
        $textBoxPacketDetails.Text = Format-PacketDetails -Packet $selectedPacket
    }
})

# Événements des boutons
$buttonStartCapture.Add_Click({ 
    if (Ensure-NpcapInstalled) {
        Start-PacketCapture 
    }
})

$buttonStopCapture.Add_Click({ Stop-PacketCapture })

$buttonApplyFilter.Add_Click({ Filter-Packets })

$buttonClearFilter.Add_Click({
    $comboFilterField.SelectedIndex = 0
    $textBoxFilterValue.Text = ""
    Filter-Packets
})

$buttonClearPackets.Add_Click({
    $script:capturedPackets.Clear()
    $script:displayedPackets.Clear()
    Update-PacketListView
    $textBoxPacketDetails.Clear()
})

# Événement pour fermer proprement la capture lors de la fermeture de l'application
$form.Add_FormClosing({
    if ($script:isCapturing) {
        Stop-PacketCapture
    }
})

# Initialisation de l'onglet Sniffer
$tabSniffer.Add_Enter({
    if ($comboInterfaces.Items.Count -eq 0) {
        if (Ensure-NpcapInstalled) {
            Update-InterfaceList
        }
    }
})

$dataGridUsers.DataSource = [System.Collections.ArrayList]@(Get-LocalUsers)

$form.Add_Shown({
    $form.Activate()
})

# Initialiser la liste des adaptateurs réseau
Update-NetworkListView

# Ajout du TabControl à la form principale
$form.Controls.Add($tabControl)

[void]$form.ShowDialog()
