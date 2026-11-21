#requires -Version 5.1
<#
.SYNOPSIS
    Windows 10/11 局域网 RDP 一键配置、状态检查和关闭工具。

.DESCRIPTION
    仅面向局域网 RDP：
      * 启用 RDP Host、强制 NLA，不修改 3389 端口和安全层；
      * 创建独立标准本地账户 rdp_access，使用加密随机密码；
      * 创建仅允许 LocalSubnet、Domain/Private/Public 的 TCP 3389 防火墙规则；
      * 自动发现 RFC1918 内网 IPv4 地址；
      * 支持 -Status 只读检查和 -Disable 回滚关闭；
      * 支持 Public/Private/Domain 网络配置文件；LocalSubnet 不等于只有你的设备；
      * 不保存明文密码，不自动复制密码。

.NOTES
    需要 Windows PowerShell 5.1 和管理员权限。
    不支持 Windows 家庭版（Home）以及 Windows Server。
#>
[CmdletBinding()]
param(
    [switch]$Enable,
    [switch]$DisableRdp,
    [switch]$DeleteAccount,
    [switch]$DisableAndDelete,
    [switch]$Status,
    [Alias('Disable')]
    [switch]$RestoreOriginal,
    [Alias('h')]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    $script:Utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    [Console]::OutputEncoding = $script:Utf8NoBom
    $OutputEncoding = $script:Utf8NoBom
} catch {
    # 控制台编码设置失败不阻断主流程；BAT 已尝试 chcp 65001。
}

$script:AppTitle            = 'RDP QUICK ACCESS'
$script:AccountName         = 'rdp_access'
$script:ManagedDescription  = 'Managed by RDP-QuickAccess'
$script:FirewallRuleName    = 'RDP-QuickAccess-TCP'
$script:FirewallRuleGroup   = 'RDP-QuickAccess'
$script:RdpPort             = 3389
$script:RdpGroupSid         = 'S-1-5-32-555'
$script:AdministratorsSid   = 'S-1-5-32-544'
$script:TsKey               = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$script:RdpTcpKey           = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$script:PolicyKey           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

$programData = [Environment]::GetFolderPath('CommonApplicationData')
if ([string]::IsNullOrWhiteSpace($programData)) {
    $programData = Join-Path -Path $env:SystemDrive -ChildPath 'ProgramData'
}
$script:StateDirectory = Join-Path -Path $programData -ChildPath 'RDP-QuickAccess'
$script:StatePath      = Join-Path -Path $script:StateDirectory -ChildPath 'state.json'

# ---------------------------------------------------------------------------
# 控制台输出
# ---------------------------------------------------------------------------

function Write-Banner {
    param([string]$Subtitle = '')
    $width = 40
    Write-Host ''
    Write-Host ('=' * $width) -ForegroundColor Cyan
    $title = $script:AppTitle
    if (-not [string]::IsNullOrWhiteSpace($Subtitle)) {
        $title = "$title - $Subtitle"
    }
    if ($title.Length -ge $width) {
        Write-Host $title -ForegroundColor White
    } else {
        $left = [int][Math]::Floor(($width - $title.Length) / 2)
        Write-Host ((' ' * $left) + $title) -ForegroundColor White
    }
    Write-Host ('=' * $width) -ForegroundColor Cyan
    Write-Host ''
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('-' * 40) -ForegroundColor DarkCyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('-' * 40) -ForegroundColor DarkCyan
}

function Write-Kv {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [ConsoleColor]$ValueColor = [ConsoleColor]::White
    )
    Write-Host ('{0}：{1}' -f $Label, $Value) -ForegroundColor $ValueColor
}

function Write-Info {
    param([string]$Message)
    Write-Host "[信息] $Message" -ForegroundColor Gray
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[成功] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[警告] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[错误] $Message" -ForegroundColor Red
}

function Write-Failure {
    param([string]$Message)
    Write-Host ''
    Write-Host ('=' * 40) -ForegroundColor Red
    Write-Host '       RDP QUICK ACCESS - FAILED' -ForegroundColor Red
    Write-Host ('=' * 40) -ForegroundColor Red
    Write-Host '状态：未完成 / 配置失败' -ForegroundColor Red
    Write-Host ''
    Write-Host '原因：' -ForegroundColor Yellow
    Write-Host $Message -ForegroundColor Red
    Write-Host ''
    Write-Host '没有输出虚假的成功状态。请根据以上原因处理后重新运行。' -ForegroundColor Yellow
    Write-Host '如果失败发生在创建账户之后，重新运行会轮换密码并重新显示凭证。' -ForegroundColor Yellow
    Write-Host '如需回滚本工具已做的部分修改，请运行 RDP-QuickAccess.bat -Disable。' -ForegroundColor Yellow
    Write-Host ('=' * 40) -ForegroundColor Red
}

function Format-NetworkCategory {
    param([string]$Category)
    switch ($Category) {
        'Private'             { return '专用（Private）' }
        'DomainAuthenticated' { return '域（Domain）' }
        'Public'              { return '公用（Public）' }
        default               { return '未识别' }
    }
}

function Get-FirewallProfileNameForCategory {
    param([string]$Category)
    switch ($Category) {
        'Public'              { return 'Public' }
        'Private'             { return 'Private' }
        'DomainAuthenticated' { return 'Domain' }
        default               { throw "无法识别的网络配置文件类别：$Category" }
    }
}

function Format-SecurityLayer {
    param($RegistryValueInfo)
    if ($null -eq $RegistryValueInfo -or -not [bool]$RegistryValueInfo.Exists) {
        return '未设置（使用系统默认）'
    }
    return [string]$RegistryValueInfo.Value
}

# ---------------------------------------------------------------------------
# 前置条件
# ---------------------------------------------------------------------------

function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw '此操作需要管理员权限。请双击 RDP-QuickAccess.bat，或右键以管理员身份运行。'
    }
}

function Assert-Prerequisites {
    if (-not (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
        try {
            Import-Module -Name 'Microsoft.PowerShell.LocalAccounts' -ErrorAction Stop
        } catch {
            throw "无法加载系统本地账户模块 Microsoft.PowerShell.LocalAccounts：$($_.Exception.Message)"
        }
    }

    $requiredCommands = @(
        'Get-LocalUser', 'New-LocalUser', 'Set-LocalUser', 'Enable-LocalUser',
        'Remove-LocalUser', 'Get-LocalGroupMember', 'Add-LocalGroupMember',
        'Remove-LocalGroupMember',
        'Get-NetFirewallProfile', 'Get-NetFirewallRule', 'New-NetFirewallRule',
        'Set-NetFirewallRule', 'Remove-NetFirewallRule',
        'Get-NetFirewallPortFilter', 'Get-NetFirewallAddressFilter',
        'Get-NetTCPConnection', 'Get-NetAdapter', 'Get-NetIPAddress',
        'Get-NetRoute', 'Get-NetConnectionProfile'
    )
    $missing = @()
    foreach ($name in $requiredCommands) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $missing += $name
        }
    }
    if ($missing.Count -gt 0) {
        throw "系统缺少以下 PowerShell 组件：$($missing -join '、')。请确认使用的是 Windows 10/11 自带的 Windows PowerShell 5.1。"
    }
}

function Get-MachineGuid {
    $item = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid' -ErrorAction Stop
    return [string]$item.MachineGuid
}

function Get-SystemInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $po = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -Name 'ProductType' -ErrorAction SilentlyContinue
    $productType = ''
    if ($null -ne $po) {
        $productType = [string]$po.ProductType
    }
    return [pscustomobject]@{
        Caption        = [string]$os.Caption
        Version        = [string]$os.Version
        Build          = [string]$os.BuildNumber
        EditionId      = [string]$cv.EditionID
        DisplayVersion = [string]$cv.DisplayVersion
        ProductName    = [string]$cv.ProductName
        ProductType    = $productType
    }
}

function Test-RdpHostSupport {
    param($SystemInfo)

    if ($null -eq $SystemInfo) {
        return [pscustomobject]@{ Supported = $false; Reason = '无法读取操作系统信息。' }
    }

    $version = $null
    try {
        $version = [version][string]$SystemInfo.Version
    } catch {
        return [pscustomobject]@{ Supported = $false; Reason = '无法识别 Windows 版本号。' }
    }

    if ($version.Major -lt 10) {
        return [pscustomobject]@{ Supported = $false; Reason = '仅支持 Windows 10/11，当前系统版本过低。' }
    }

    if ([string]$SystemInfo.ProductType -ne 'WinNT') {
        return [pscustomobject]@{ Supported = $false; Reason = '本工具仅支持 Windows 10/11 客户端，不支持 Windows Server。' }
    }

    $editionText = "$($SystemInfo.EditionId) $($SystemInfo.ProductName) $($SystemInfo.Caption)"
    if ($editionText -match '(?i)\bHome\b' -or
        [string]$SystemInfo.EditionId -match '(?i)^(Core|Home)' -or
        $editionText -match '(?i)\bWindows\s+11\s+SE\b' -or
        [string]$SystemInfo.EditionId -match '(?i)^Cloud') {
        return [pscustomobject]@{ Supported = $false; Reason = '检测到 Windows 家庭版/SE/Cloud 版本。该版本不包含 RDP Host 功能，无法启用远程桌面主机。' }
    }

    $termService = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
    if ($null -eq $termService) {
        return [pscustomobject]@{ Supported = $false; Reason = '远程桌面服务 TermService 不存在，当前系统可能不支持 RDP Host。' }
    }

    if (-not (Test-Path -LiteralPath $script:RdpTcpKey)) {
        return [pscustomobject]@{ Supported = $false; Reason = '未找到 RDP-Tcp 配置项，当前系统可能不支持 RDP Host。' }
    }

    return [pscustomobject]@{ Supported = $true; Reason = '' }
}

# ---------------------------------------------------------------------------
# 注册表、组策略和 TermService
# ---------------------------------------------------------------------------

function Get-RegistryValueInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }
    $values = @($key.GetValueNames())
    if ($values -contains $Name) {
        return [pscustomobject]@{ Exists = $true; Value = $key.GetValue($Name) }
    }
    return [pscustomobject]@{ Exists = $false; Value = $null }
}

function Get-RdpRegistryState {
    $deny = Get-RegistryValueInfo -Path $script:TsKey -Name 'fDenyTSConnections'
    $nla  = Get-RegistryValueInfo -Path $script:RdpTcpKey -Name 'UserAuthentication'
    $port = Get-RegistryValueInfo -Path $script:RdpTcpKey -Name 'PortNumber'
    $sl   = Get-RegistryValueInfo -Path $script:RdpTcpKey -Name 'SecurityLayer'

    $denyValue = $null
    if ([bool]$deny.Exists) { $denyValue = [int]$deny.Value }
    $nlaValue = $null
    if ([bool]$nla.Exists) { $nlaValue = [int]$nla.Value }
    $portValue = $script:RdpPort
    if ([bool]$port.Exists) { $portValue = [int]$port.Value }

    return [pscustomobject]@{
        Deny          = $deny
        Nla           = $nla
        Port          = $port
        SecurityLayer = $sl
        DenyValue     = $denyValue
        NlaValue      = $nlaValue
        PortValue     = $portValue
        RdpEnabled    = ([bool]$deny.Exists -and $denyValue -eq 0)
        NlaEnabled    = ([bool]$nla.Exists -and $nlaValue -eq 1)
    }
}

function Get-RdpPolicyState {
    $policy = Get-ItemProperty -Path $script:PolicyKey -ErrorAction SilentlyContinue
    $deny = $null
    $nla  = $null
    if ($null -ne $policy) {
        if ($null -ne $policy.PSObject.Properties['fDenyTSConnections']) {
            $deny = [int]$policy.fDenyTSConnections
        }
        if ($null -ne $policy.PSObject.Properties['UserAuthentication']) {
            $nla = [int]$policy.UserAuthentication
        }
    }
    return [pscustomobject]@{
        fDenyTSConnections = $deny
        UserAuthentication = $nla
    }
}

function ConvertTo-ServiceStartupType {
    param([string]$StartMode)
    switch ($StartMode) {
        'Auto'      { return 'Automatic' }
        'Automatic' { return 'Automatic' }
        'Manual'    { return 'Manual' }
        'Disabled'  { return 'Disabled' }
        default     { throw "无法识别的服务启动类型：$StartMode" }
    }
}

function Get-TermServiceInfo {
    $service = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [pscustomobject]@{
            Exists     = $false
            Status     = 'NotFound'
            StartMode  = 'Unknown'
            StartType  = 'Unknown'
            WasRunning = $false
        }
    }
    $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService'" -ErrorAction SilentlyContinue
    $startMode = 'Unknown'
    if ($null -ne $wmi) {
        $startMode = [string]$wmi.StartMode
    }
    $startType = 'Unknown'
    try {
        if ($startMode -ne 'Unknown') {
            $startType = ConvertTo-ServiceStartupType -StartMode $startMode
        }
    } catch {
        $startType = 'Unknown'
    }
    return [pscustomobject]@{
        Exists     = $true
        Status     = [string]$service.Status
        StartMode  = $startMode
        StartType  = $startType
        WasRunning = ([string]$service.Status -eq 'Running')
    }
}

function Set-RdpRegistryEnabled {
    if (-not (Test-Path -LiteralPath $script:RdpTcpKey)) {
        throw "未找到注册表路径 $script:RdpTcpKey，无法启用 RDP。"
    }

    # 先强制 NLA，再启用 RDP，避免出现“已开启 RDP 但 NLA 尚未生效”的窗口。
    Set-ItemProperty -LiteralPath $script:RdpTcpKey -Name 'UserAuthentication' -Value 1 -Type DWord -ErrorAction Stop
    $nlaCheck = Get-RdpRegistryState
    if (-not $nlaCheck.NlaEnabled) {
        throw '写入 UserAuthentication=1 后验证失败，NLA 仍未启用。'
    }

    Set-ItemProperty -LiteralPath $script:TsKey -Name 'fDenyTSConnections' -Value 0 -Type DWord -ErrorAction Stop
    $after = Get-RdpRegistryState
    if (-not $after.RdpEnabled) {
        throw '写入 fDenyTSConnections=0 后验证失败，RDP 仍未启用。'
    }
    if (-not $after.NlaEnabled) {
        throw '写入 UserAuthentication=1 后验证失败，NLA 仍未启用。'
    }
    Write-Ok 'RDP 已启用，NLA 已强制启用。'
}

function Initialize-TermService {
    param($State)

    $service = Get-Service -Name 'TermService' -ErrorAction Stop
    $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService'" -ErrorAction Stop
    if ($null -eq $wmi) {
        throw '无法读取 TermService 的启动配置。'
    }
    $startMode = [string]$wmi.StartMode

    if ($startMode -eq 'Disabled') {
        Write-Warn 'TermService 当前启动类型为 Disabled，将临时改为 Manual；原始配置已记录，可用 -Disable 恢复。'
        $State.TermService.StartupTypeChanged = $true
        Save-StateFile -State $State
        Set-Service -Name 'TermService' -StartupType Manual -ErrorAction Stop
        $check = Get-TermServiceInfo
        if ($check.StartType -ne 'Manual') {
            throw "TermService 启动类型修改后验证失败（当前：$($check.StartType)）。"
        }
    }

    if ([string]$service.Status -ne 'Running') {
        Write-Info '正在启动远程桌面服务 TermService...'
        Start-Service -Name 'TermService' -ErrorAction Stop
    }

    $deadline = (Get-Date).AddSeconds(20)
    do {
        $service.Refresh()
        if ([string]$service.Status -eq 'Running') { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    if ([string]$service.Status -ne 'Running') {
        throw "TermService 启动失败，当前状态：$($service.Status)"
    }
    Write-Ok 'TermService 正在运行。'
}

function Test-RdpListener {
    $listener = @(Get-NetTCPConnection -State Listen -LocalPort $script:RdpPort -ErrorAction SilentlyContinue)
    return ($listener.Count -gt 0)
}

function Wait-RdpListener {
    param([int]$TimeoutSeconds = 25)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-RdpListener) { return $true }
        Start-Sleep -Milliseconds 700
    } while ((Get-Date) -lt $deadline)
    return (Test-RdpListener)
}

function Ensure-RdpListener {
    param($State, [bool]$WasRdpEnabled = $false)

    if (Wait-RdpListener -TimeoutSeconds 8) {
        Write-Ok 'RDP 已在 TCP 3389 上监听。'
        return
    }

    if (-not $WasRdpEnabled) {
        Write-Warn 'RDP 监听尚未就绪，正在重启 TermService 以应用配置...'
        Restart-Service -Name 'TermService' -Force -ErrorAction Stop
        if (-not (Wait-RdpListener -TimeoutSeconds 25)) {
            throw 'TermService 已重启，但 TCP 3389 仍未监听。请检查系统事件日志、服务依赖和安全软件。'
        }
        Write-Ok 'RDP 已在 TCP 3389 上监听。'
        return
    }

    if (-not (Wait-RdpListener -TimeoutSeconds 17)) {
        throw 'RDP 配置已写入，但 TCP 3389 未监听。请检查 TermService、事件日志或安全软件。'
    }
    Write-Ok 'RDP 已在 TCP 3389 上监听。'
}

# ---------------------------------------------------------------------------
# 状态目录 ACL（仅 Administrators/SYSTEM）
# ---------------------------------------------------------------------------

function New-StateDirectoryAcl {
    $adminSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $script:AdministratorsSid
    $systemSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $acl = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($adminSid, $rights, $inheritance, $propagation, $allow)
    $systemRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($systemSid, $rights, $inheritance, $propagation, $allow)
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    return $acl
}

function Initialize-StateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $acl = New-StateDirectoryAcl
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        $verify = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if (-not $verify.AreAccessRulesProtected) {
            throw '状态目录的 ACL 继承未被禁用。'
        }
        $adminFull = $false
        $systemFull = $false
        $fullMask = [int][System.Security.AccessControl.FileSystemRights]::FullControl
        foreach ($rule in @($verify.Access)) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = ''
            try {
                $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                $sid = ''
            }
            if ((([int]$rule.FileSystemRights) -band $fullMask) -ne $fullMask) { continue }
            if ($sid -eq $script:AdministratorsSid) { $adminFull = $true }
            if ($sid -eq 'S-1-5-18') { $systemFull = $true }
        }
        if (-not $adminFull -or -not $systemFull) {
            throw '状态目录 ACL 缺少 Administrators 或 SYSTEM 的完全控制。'
        }
    } catch {
        throw "无法保护状态目录 ACL（$Path）：$($_.Exception.Message)"
    }
}

function Get-StateDirectoryAclInfo {
    $info = [pscustomobject]@{
        Exists     = $false
        Hardened   = $false
        UsersWrite = $false
        Message    = '状态目录尚未创建'
    }
    if (-not (Test-Path -LiteralPath $script:StateDirectory -PathType Container)) {
        return $info
    }
    $info.Exists = $true
    $paths = @($script:StateDirectory)
    if (Test-Path -LiteralPath $script:StatePath -PathType Leaf) { $paths += $script:StatePath }
    $writeMask = [int]([System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Modify -bor [System.Security.AccessControl.FileSystemRights]::FullControl)
    $bad = $false
    $messages = @()
    foreach ($path in $paths) {
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            foreach ($rule in @($acl.Access)) {
                if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                $sid = ''
                try {
                    $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } catch {
                    $sid = ''
                }
                if ($sid -eq $script:AdministratorsSid -or $sid -eq 'S-1-5-18') { continue }
                if ((([int]$rule.FileSystemRights) -band $writeMask) -ne 0) {
                    $bad = $true
                    $messages += "$path 存在非 Administrators/SYSTEM 的可写权限"
                    break
                }
            }
        } catch {
            $bad = $true
            $messages += "无法读取 $path 的 ACL：$($_.Exception.Message)"
        }
    }
    $info.UsersWrite = $bad
    $info.Hardened = (-not $bad)
    if ($bad) {
        $info.Message = ($messages -join '；')
    } else {
        $info.Message = '仅 Administrators/SYSTEM 可写（未发现其他可写主体）'
    }
    return $info
}

# ---------------------------------------------------------------------------
# 状态快照（不包含密码）
# ---------------------------------------------------------------------------

function Read-StateFile {
    if (-not (Test-Path -LiteralPath $script:StatePath -PathType Leaf)) {
        return $null
    }

    try {
        $raw = [System.IO.File]::ReadAllText($script:StatePath, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw '状态文件为空'
        }
        $state = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "状态文件无法读取或解析：$($_.Exception.Message)（$script:StatePath）。为避免误恢复，已停止。"
    }

    if ($null -eq $state -or $null -eq $state.PSObject.Properties['SchemaVersion'] -or [int]$state.SchemaVersion -ne 1) {
        throw "状态文件版本不受支持：$script:StatePath"
    }

    if ($null -eq $state.PSObject.Properties['MachineGuid']) {
        throw "状态文件缺少 MachineGuid，无法确认归属：$script:StatePath"
    }

    try {
        $machineGuid = Get-MachineGuid
    } catch {
        throw "无法读取本机 MachineGuid：$($_.Exception.Message)"
    }
    if ([string]$state.MachineGuid -ne $machineGuid) {
        throw "状态文件不属于当前计算机（MachineGuid 不匹配）：$script:StatePath"
    }

    foreach ($required in @('Rdp', 'TermService')) {
        if ($null -eq $state.PSObject.Properties[$required]) {
            throw "状态文件缺少必要字段 '$required'：$script:StatePath"
        }
    }
    foreach ($valueName in @('fDenyTSConnections', 'UserAuthentication')) {
        if ($null -eq $state.Rdp.PSObject.Properties[$valueName]) {
            throw "状态文件缺少 RDP 快照字段 '$valueName'：$script:StatePath"
        }
    }
    foreach ($serviceName in @('StartupTypeBefore', 'StartupTypeChanged')) {
        if ($null -eq $state.TermService.PSObject.Properties[$serviceName]) {
            throw "状态文件缺少服务快照字段 '$serviceName'：$script:StatePath"
        }
    }

    return $state
}

function Save-StateFile {
    param($State)
    if ($null -eq $State) {
        throw '内部错误：状态对象为空。'
    }
    if (-not (Test-Path -LiteralPath $script:StateDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $script:StateDirectory -Force -ErrorAction Stop | Out-Null
    }

    $directoryItem = Get-Item -LiteralPath $script:StateDirectory -Force -ErrorAction Stop
    if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "状态目录是重解析点，拒绝写入：$script:StateDirectory"
    }

    Initialize-StateDirectoryAcl -Path $script:StateDirectory

    $State.LastUpdatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $json = $State | ConvertTo-Json -Depth 10
    $tempPath = $script:StatePath + '.tmp'
    foreach ($candidate in @($script:StatePath, $tempPath)) {
        $candidateItem = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if ($null -ne $candidateItem -and (($candidateItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "状态文件路径是重解析点，拒绝写入：$candidate"
        }
    }
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    try {
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        Move-Item -LiteralPath $tempPath -Destination $script:StatePath -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $tempPath -ErrorAction SilentlyContinue) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-ConfigSnapshot {
    $rdp = Get-RdpRegistryState
    $service = Get-TermServiceInfo
    if (-not $service.Exists) {
        throw 'TermService 不存在，无法保存服务配置快照。'
    }
    if ($service.StartType -eq 'Unknown') {
        throw '无法识别 TermService 启动类型，无法保存可恢复的服务配置快照。'
    }

    return [pscustomobject]@{
        SchemaVersion       = 1
        MachineGuid         = Get-MachineGuid
        ComputerName        = $env:COMPUTERNAME
        CreatedAt           = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        LastUpdatedAt       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Rdp                 = [pscustomobject]@{
            fDenyTSConnections = $rdp.Deny
            UserAuthentication = $rdp.Nla
            PortNumber         = $rdp.Port
            SecurityLayer      = $rdp.SecurityLayer
        }
        TermService         = [pscustomobject]@{
            StartupTypeBefore  = $service.StartType
            StartupTypeChanged = $false
            WasRunning         = $service.WasRunning
        }
        FirewallRuleCreated = $false
        AccountSid           = $null
    }
}

# ---------------------------------------------------------------------------
# 安全密码生成
# ---------------------------------------------------------------------------

function Get-SecureRandomIndex {
    param(
        [Parameter(Mandatory = $true)][int]$Max,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.RandomNumberGenerator]$Rng
    )
    if ($Max -le 0) {
        throw '随机数范围必须大于 0。'
    }
    $bytes = New-Object 'byte[]' 4
    $range = [uint64]4294967296
    $limit = [uint64]([Math]::Floor($range / [double]$Max) * $Max)
    while ($true) {
        $Rng.GetBytes($bytes)
        $value = [uint64][System.BitConverter]::ToUInt32($bytes, 0)
        if ($value -lt $limit) {
            return [int]($value % [uint64]$Max)
        }
    }
}

function New-SecurePassword {
    param([int]$Length = 24)
    if ($Length -lt 24) {
        throw '密码长度不能少于 24 位。'
    }

    $lower   = 'abcdefghijkmnopqrstuvwxyz'
    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $digits  = '23456789'
    $special = '!#%&*+-=?@^_~'
    $all     = $lower + $upper + $digits + $special

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $chars = New-Object -TypeName 'System.Collections.Generic.List[char]'
        $chars.Add($lower[(Get-SecureRandomIndex -Max $lower.Length -Rng $rng)])
        $chars.Add($upper[(Get-SecureRandomIndex -Max $upper.Length -Rng $rng)])
        $chars.Add($digits[(Get-SecureRandomIndex -Max $digits.Length -Rng $rng)])
        $chars.Add($special[(Get-SecureRandomIndex -Max $special.Length -Rng $rng)])

        while ($chars.Count -lt $Length) {
            $chars.Add($all[(Get-SecureRandomIndex -Max $all.Length -Rng $rng)])
        }

        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = Get-SecureRandomIndex -Max ($i + 1) -Rng $rng
            $tmp = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $tmp
        }

        return (-join $chars)
    } finally {
        $rng.Dispose()
    }
}

# ---------------------------------------------------------------------------
# 本地账户
# ---------------------------------------------------------------------------

function Get-SidString {
    param($SidObject)
    if ($null -eq $SidObject) { return '' }
    if ($SidObject -is [System.Security.Principal.SecurityIdentifier]) {
        return $SidObject.Value
    }
    return [string]$SidObject
}

function Get-RdpAccountInfo {
    $user = Get-LocalUser -Name $script:AccountName -ErrorAction SilentlyContinue
    if ($null -eq $user) {
        return [pscustomobject]@{
            Exists                = $false
            Name                  = $script:AccountName
            Sid                   = ''
            Description           = ''
            Enabled               = $false
            InRdpGroup            = $false
            InAdministrators      = $false
            DescriptionMatches    = $false
            PasswordExpires       = $null
            PasswordRequired      = $false
            UserMayChangePassword = $false
        }
    }

    $sid = Get-SidString -SidObject $user.SID
    $rdpMembers = @(Get-LocalGroupMember -SID $script:RdpGroupSid -ErrorAction SilentlyContinue)
    $adminMembers = @(Get-LocalGroupMember -SID $script:AdministratorsSid -ErrorAction SilentlyContinue)

    $inRdp = $false
    foreach ($member in $rdpMembers) {
        if ((Get-SidString -SidObject $member.SID) -eq $sid) { $inRdp = $true; break }
    }

    $inAdmins = $false
    foreach ($member in $adminMembers) {
        if ((Get-SidString -SidObject $member.SID) -eq $sid) { $inAdmins = $true; break }
    }

    $description = [string]$user.Description
    return [pscustomobject]@{
        Exists                = $true
        Name                  = [string]$user.Name
        Sid                   = $sid
        Description           = $description
        Enabled               = [bool]$user.Enabled
        InRdpGroup            = $inRdp
        InAdministrators      = $inAdmins
        DescriptionMatches    = ($description -ceq $script:ManagedDescription)
        PasswordExpires       = $user.PasswordExpires
        PasswordRequired      = [bool]$user.PasswordRequired
        UserMayChangePassword = [bool]$user.UserMayChangePassword
    }
}

function Get-RdpAccountSessionInfo {
    $result = [pscustomobject]@{
        Checked  = $false
        InUse    = $false
        Sessions = @()
        Errors   = @()
    }
    $sessions = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $errors = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $checked = $false

    try {
        $associations = @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop)
        $logonSessions = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop)
        $logonMap = @{}
        foreach ($logon in $logonSessions) {
            $logonMap[[string]$logon.LogonId] = $logon
        }
        foreach ($association in $associations) {
            if ($null -eq $association.Antecedent) { continue }
            $name = [string]$association.Antecedent.Name
            if ($name -ne $script:AccountName) { continue }
            $domain = [string]$association.Antecedent.Domain
            if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -ne $env:COMPUTERNAME -and $domain -ne '.') {
                continue
            }
            $logonId = [string]$association.Dependent.LogonId
            if (-not $logonMap.ContainsKey($logonId)) { continue }
            $logon = $logonMap[$logonId]
            $logonType = [int]$logon.LogonType
            if ($logonType -in @(2, 3, 7, 10, 11)) {
                $sessions.Add([pscustomobject]@{
                    Source    = 'Win32_LogonSession'
                    LogonId   = $logonId
                    LogonType = $logonType
                    StartTime = $logon.StartTime
                })
            }
        }
        $checked = $true
    } catch {
        $errors.Add("CIM 登录会话检查失败：$($_.Exception.Message)")
    }

    try {
        $quserOutput = @(& quser 2>$null)
        if ($LASTEXITCODE -eq 0) {
            $checked = $true
            $pattern = '(?i)(^|[\s>])' + [regex]::Escape($script:AccountName) + '([\s]|$)'
            foreach ($line in $quserOutput) {
                if ([string]$line -match $pattern) {
                    $sessions.Add([pscustomobject]@{
                        Source    = 'quser'
                        LogonId   = ''
                        LogonType = ''
                        StartTime = ''
                        Detail    = ([string]$line).Trim()
                    })
                }
            }
        }
    } catch {
        $errors.Add("quser 会话检查失败：$($_.Exception.Message)")
    }

    try {
        $processes = @(Get-Process -IncludeUserName -ErrorAction Stop | Where-Object {
            $_.UserName -and ([string]$_.UserName).ToLowerInvariant().EndsWith('\' + $script:AccountName.ToLowerInvariant())
        })
        $checked = $true
        foreach ($process in $processes) {
            $sessions.Add([pscustomobject]@{
                Source    = 'Process'
                LogonId   = ''
                LogonType = ''
                StartTime = ''
                Detail    = ("进程 {0}（PID {1}）" -f $process.ProcessName, $process.Id)
            })
        }
    } catch {
        # 非管理员或系统限制时可能无法读取进程用户；CIM/quser 仍可提供会话信息。
    }

    $result.Checked = $checked
    $result.Sessions = $sessions.ToArray()
    $result.InUse = ($sessions.Count -gt 0)
    $result.Errors = $errors.ToArray()
    return $result
}

function Initialize-RdpAccount {
    param([Parameter(Mandatory = $true)][string]$Password)

    $info = Get-RdpAccountInfo
    if ($info.Exists -and -not $info.DescriptionMatches) {
        throw "本地账户 '$($script:AccountName)' 已存在，但说明字段不是 '$($script:ManagedDescription)'（当前：'$($info.Description)'）。为避免影响其他账户，本工具未做任何修改，已停止。"
    }

    $createdNew = $false
    try {
        if ($info.Exists) {
            Write-Info "发现由本工具管理的账户 $($script:AccountName)，将校验权限并轮换密码。"
            if ($info.InAdministrators) {
                Write-Warn '该账户意外位于 Administrators 组，正在将其移除以恢复标准用户身份...'
                Remove-LocalGroupMember -SID $script:AdministratorsSid -Member $script:AccountName -Confirm:$false -ErrorAction Stop
            }
            if (-not $info.Enabled) {
                Enable-LocalUser -Name $script:AccountName -ErrorAction Stop
            }

            $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
            Set-LocalUser -Name $script:AccountName -Password $secure -PasswordNeverExpires $true -AccountNeverExpires -ErrorAction Stop
            Write-Ok '已轮换账户密码。'
        } else {
            $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
            New-LocalUser -Name $script:AccountName -Password $secure -Description $script:ManagedDescription -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
            $createdNew = $true
            Write-Ok '已创建专用本地标准账户。'
        }

        if (-not (Get-RdpAccountInfo).InRdpGroup) {
            Add-LocalGroupMember -SID $script:RdpGroupSid -Member $script:AccountName -Confirm:$false -ErrorAction Stop
            Write-Ok '已将账户加入 Remote Desktop Users 组（按 SID S-1-5-32-555 定位）。'
        }

        $verify = Get-RdpAccountInfo
        if (-not $verify.Exists) { throw "账户 $($script:AccountName) 创建或读取失败。" }
        if (-not $verify.Enabled) { throw "账户 $($script:AccountName) 处于禁用状态。" }
        if (-not $verify.DescriptionMatches) { throw "账户 $($script:AccountName) 的说明字段校验失败。" }
        if (-not $verify.InRdpGroup) { throw "账户 $($script:AccountName) 未能加入 Remote Desktop Users 组。" }
        if ($verify.InAdministrators) { throw "账户 $($script:AccountName) 意外位于 Administrators 组。" }

        return $verify
    } catch {
        $failure = $_
        if ($createdNew) {
            try {
                $cleanupInfo = Get-RdpAccountInfo
                if ($cleanupInfo.Exists -and $cleanupInfo.DescriptionMatches) {
                    Remove-LocalUser -Name $script:AccountName -Confirm:$false -ErrorAction Stop
                    Write-Warn '账户初始化未完成，已回滚删除本次新建的账户。'
                }
            } catch {
                Write-Warn "账户初始化失败，且回滚删除失败：$($_.Exception.Message)"
            }
        }
        throw $failure
    }
}

# ---------------------------------------------------------------------------
# 防火墙
# ---------------------------------------------------------------------------

function Get-ManagedFirewallRules {
    return @(Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue)
}

function Test-FirewallPortIncludes {
    param($Ports, [int]$Port)
    foreach ($item in @($Ports)) {
        $text = [string]$item
        if ($text -eq 'Any') { return $true }
        if ($text -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        } elseif ($text -match '^\s*(\d+)\s*$') {
            if ([int]$Matches[1] -eq $Port) { return $true }
        }
    }
    return $false
}

function Test-FirewallRuleConfiguration {
    param($Rule)

    $errors = New-Object -TypeName 'System.Collections.Generic.List[string]'
    if ($null -eq $Rule) {
        $errors.Add('规则不存在')
        return $errors
    }

    if ([string]$Rule.Enabled -ne 'True') {
        $errors.Add("规则未启用（当前：$($Rule.Enabled)）")
    }
    if ([string]$Rule.Direction -ne 'Inbound') {
        $errors.Add("规则方向不是 Inbound（当前：$($Rule.Direction)）")
    }
    if ([string]$Rule.Action -ne 'Allow') {
        $errors.Add("规则动作不是 Allow（当前：$($Rule.Action)）")
    }
    if ([string]$Rule.Description -cne $script:ManagedDescription) {
        $errors.Add("规则说明字段不是本工具标记（当前：$($Rule.Description)）")
    }

    $profiles = [string]$Rule.Profile
    if ($profiles -notmatch '(?i)\bDomain\b') {
        $errors.Add('未包含 Domain 网络配置文件')
    }
    if ($profiles -notmatch '(?i)\bPrivate\b') {
        $errors.Add('未包含 Private 网络配置文件')
    }
    if ($profiles -notmatch '(?i)\bPublic\b') {
        $errors.Add('未包含 Public 网络配置文件')
    }
    if ($profiles -match '(?i)^Any$') {
        $errors.Add('网络配置文件不能为 Any，必须明确覆盖 Domain/Private/Public')
    }

    $portFilters = @()
    try {
        $portFilters = @($Rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    } catch {
        $errors.Add("无法读取端口过滤器：$($_.Exception.Message)")
    }
    if ($portFilters.Count -gt 0) {
        $protocol = [string]$portFilters[0].Protocol
        if ($protocol -ne 'TCP') {
            $errors.Add("协议不是 TCP（当前：$protocol）")
        }
        $ports = @($portFilters[0].LocalPort)
        $portText = ($ports -join ',')
        $exactPort = ($ports.Count -gt 0)
        foreach ($port in $ports) {
            if ([string]$port -ne '3389') { $exactPort = $false }
        }
        if (-not $exactPort) {
            $errors.Add("本地端口必须仅为 3389（当前：$portText）")
        }
    }

    $addressFilters = @()
    try {
        $addressFilters = @($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    } catch {
        $errors.Add("无法读取地址过滤器：$($_.Exception.Message)")
    }
    if ($addressFilters.Count -gt 0) {
        $remotes = @($addressFilters[0].RemoteAddress)
        $remoteText = ($remotes -join ',')
        $allLocalSubnet = ($remotes.Count -gt 0)
        foreach ($remote in $remotes) {
            if ([string]$remote -notmatch '(?i)^LocalSubnet') { $allLocalSubnet = $false }
        }
        if (-not $allLocalSubnet) {
            $errors.Add("远程地址必须仅为 LocalSubnet（当前：$remoteText）")
        }
    }

    return $errors
}

function Assert-FirewallRulePreflight {
    $rules = @(Get-ManagedFirewallRules)
    if ($rules.Count -gt 1) {
        throw "发现 $($rules.Count) 条同名防火墙规则 '$($script:FirewallRuleName)'。为避免误删或产生重复规则，已停止。请手动检查并清理后重试。"
    }
    if ($rules.Count -eq 1) {
        $description = [string]$rules[0].Description
        if ($description -cne $script:ManagedDescription) {
            throw "防火墙规则 '$($script:FirewallRuleName)' 已存在，但说明字段不是本工具标记（当前：'$description'）。为避免修改其他人的规则，本工具未做任何修改，已停止。"
        }
    }
}

function Initialize-FirewallRule {
    param($State)

    $rules = @(Get-ManagedFirewallRules)
    if ($rules.Count -gt 1) {
        throw "发现 $($rules.Count) 条同名防火墙规则，无法安全处理。"
    }

    $rule = $null
    if ($rules.Count -eq 1) {
        $rule = $rules[0]
        if ([string]$rule.Description -cne $script:ManagedDescription) {
            throw "防火墙规则 '$($script:FirewallRuleName)' 的说明字段不匹配，停止更新。"
        }
        if ([string]$rule.Direction -ne 'Inbound') {
            Write-Warn '同名防火墙规则方向不是 Inbound，将删除本工具规则并重建...'
            Remove-NetFirewallRule -Name $rule.Name -Confirm:$false -ErrorAction Stop
            $rule = $null
        }
    }

    if ($null -eq $rule) {
        Write-Info '正在创建防火墙规则（仅 TCP 3389、仅 LocalSubnet、Domain/Private/Public）...'
        $newRuleParams = @{
            DisplayName    = $script:FirewallRuleName
            Description    = $script:ManagedDescription
            Group          = $script:FirewallRuleGroup
            Direction      = 'Inbound'
            Action         = 'Allow'
            Protocol       = 'TCP'
            LocalPort      = $script:RdpPort
            RemoteAddress  = 'LocalSubnet'
            Profile        = @('Domain', 'Private', 'Public')
            Enabled        = 'True'
        }
        New-NetFirewallRule @newRuleParams -ErrorAction Stop | Out-Null
    } else {
        Write-Info '正在校验并更新本工具防火墙规则...'
        $setRuleParams = @{
            Name           = $rule.Name
            Enabled        = 'True'
            Profile        = @('Domain', 'Private', 'Public')
            Action         = 'Allow'
            Protocol       = 'TCP'
            LocalPort      = $script:RdpPort
            RemoteAddress  = 'LocalSubnet'
            Description    = $script:ManagedDescription
        }
        Set-NetFirewallRule @setRuleParams -ErrorAction Stop
    }

    $verify = @(Get-ManagedFirewallRules)
    if ($verify.Count -ne 1) {
        throw "防火墙规则创建/更新后数量异常（$($verify.Count) 条）。"
    }
    $errors = @(Test-FirewallRuleConfiguration -Rule $verify[0])
    if ($errors.Count -gt 0) {
        throw ("防火墙规则验证失败：" + [Environment]::NewLine + "- " + ($errors -join ([Environment]::NewLine + "- ")))
    }

    if ($null -ne $State) {
        $State.FirewallRuleCreated = $true
        Save-StateFile -State $State
    }
    Write-Ok '防火墙规则已验证：TCP 3389，RemoteAddress=LocalSubnet，Profile=Domain/Private/Public。'
}

function Get-FirewallProfileStatus {
    $profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop)
    $result = [ordered]@{}
    foreach ($profile in $profiles) {
        $result[[string]$profile.Name] = ([string]$profile.Enabled -eq 'True')
    }
    return [pscustomobject]$result
}

function Assert-FirewallReady {
    param([string[]]$ActiveCategories = @())
    $service = Get-Service -Name 'MpsSvc' -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        throw '未找到 Windows Defender 防火墙服务（MpsSvc），本工具无法安全配置。'
    }
    if ([string]$service.Status -ne 'Running') {
        throw "Windows Defender 防火墙服务未运行（当前：$($service.Status)）。本工具不会自动启动或修改全局防火墙，请先手动启用防火墙后重试。"
    }

    try {
        $status = Get-FirewallProfileStatus
    } catch {
        throw "无法读取防火墙配置文件状态：$($_.Exception.Message)"
    }

    $categories = @($ActiveCategories)
    if ($categories.Count -eq 0) {
        try {
            $categories = @(Get-ActiveNetworkCategories)
        } catch {
            throw "无法读取活动网络配置文件：$($_.Exception.Message)"
        }
    }

    if ($categories.Count -eq 0) {
        Write-Warn '未检测到活动网络连接；无法验证当前配置文件的防火墙状态，将在规则已覆盖三个配置文件的前提下继续。'
    }

    foreach ($category in $categories) {
        $profileName = Get-FirewallProfileNameForCategory -Category $category
        if (-not [bool]$status.$profileName) {
            throw "当前活动的 $profileName 网络配置文件（$category）的 Windows Defender 防火墙未启用。本工具不会自动开启或绕过防火墙；请先手动启用后重试。"
        }
    }

    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        if (-not [bool]$status.$profileName) {
            Write-Warn "$profileName 防火墙配置文件未启用；规则虽覆盖该配置，但在防火墙关闭时不会生效。"
        }
    }
    return $status
}

function Get-RiskyRdpRules {
    $managed = @(Get-ManagedFirewallRules)
    $managedNames = @{}
    foreach ($rule in $managed) {
        $managedNames[[string]$rule.Name] = $true
    }

    $risky = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {
        if ($managedNames.ContainsKey([string]$rule.Name)) { continue }

        $portFilters = @()
        try {
            $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
        } catch {
            continue
        }
        if ($portFilters.Count -eq 0) { continue }

        $portText = (@($portFilters[0].LocalPort) -join ',')
        if ($portText -eq 'Any') { continue }
        if (-not (Test-FirewallPortIncludes -Ports $portFilters[0].LocalPort -Port $script:RdpPort)) { continue }

        $protocol = [string]$portFilters[0].Protocol
        if ($protocol -notin @('TCP', 'Any')) { continue }

        $addressFilters = @()
        try {
            $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
        } catch {
            $addressFilters = @()
        }
        $remotes = @()
        if ($addressFilters.Count -gt 0) {
            $remotes = @($addressFilters[0].RemoteAddress)
        }
        $remoteText = ($remotes -join ',')
        $profiles = [string]$rule.Profile
        $anyRemote = ($remoteText -match '(?i)(^|,)\s*Any\s*($|,)')

        if ($anyRemote) {
            $risky.Add([pscustomobject]@{
                DisplayName   = [string]$rule.DisplayName
                DisplayGroup  = [string]$rule.DisplayGroup
                Profile       = $profiles
                RemoteAddress = $remoteText
                Reason        = 'RemoteAddress 为 Any'
            })
        }
    }
    return $risky.ToArray()
}

# ---------------------------------------------------------------------------
# 网络地址发现
# ---------------------------------------------------------------------------

function Test-PrivateIPv4 {
    param([string]$Address)
    $parts = $Address.Split('.')
    if ($parts.Count -ne 4) { return $false }
    $octets = @()
    foreach ($part in $parts) {
        $number = 0
        if (-not [int]::TryParse($part, [ref]$number)) { return $false }
        if ($number -lt 0 -or $number -gt 255) { return $false }
        $octets += $number
    }
    if ($octets[0] -eq 10) { return $true }
    if ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) { return $true }
    if ($octets[0] -eq 192 -and $octets[1] -eq 168) { return $true }
    return $false
}

function Get-ActiveNetworkCategories {
    $connections = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    if ($connections.Count -eq 0) {
        return @()
    }

    $categories = @()
    foreach ($connection in $connections) {
        $category = [string]$connection.NetworkCategory
        if ($category -notin @('Public', 'Private', 'DomainAuthenticated')) {
            throw "无法识别的网络配置文件类别：$category（接口：$($connection.InterfaceAlias)，网络：$($connection.Name)）。本工具不会猜测或绕过未知网络状态。"
        }
        if ($categories -notcontains $category) {
            $categories += $category
        }
    }
    return @($categories)
}

function Assert-SafeNetworkProfile {
    $categories = @(Get-ActiveNetworkCategories)
    if ($categories.Count -eq 0) {
        Write-Warn '未检测到活动网络连接；将继续配置，但当前没有可用于连接的内网地址。'
        return @()
    }

    if ($categories -contains 'Public') {
        Write-Info '当前网络配置文件包含 Public；本工具支持该配置文件，并将防火墙规则覆盖 Public。'
        Write-Warn '防火墙来源仍限制为 LocalSubnet；同一子网中的其他设备也可能访问 TCP 3389。'
    }
    return @($categories)
}

function Get-NetworkAddresses {
    $addresses = New-Object -TypeName 'System.Collections.Generic.List[object]'

    $adapterMap = @{}
    try {
        foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)) {
            $adapterMap[[int]$adapter.InterfaceIndex] = $adapter
        }
    } catch {
        Write-Warn "读取网卡信息失败：$($_.Exception.Message)"
    }

    $profileMap = @{}
    foreach ($profile in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
        $profileMap[[int]$profile.InterfaceIndex] = $profile
    }

    $routeMap = @{}
    foreach ($route in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
        $index = [int]$route.InterfaceIndex
        if (-not $routeMap.ContainsKey($index)) {
            $routeMap[$index] = $route
        } elseif ([int]$route.RouteMetric -lt [int]$routeMap[$index].RouteMetric) {
            $routeMap[$index] = $route
        }
    }

    foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $address = [string]$ip.IPAddress
        if (-not (Test-PrivateIPv4 -Address $address)) { continue }
        if ([string]$ip.AddressState -ne 'Preferred') { continue }

        $index = [int]$ip.InterfaceIndex
        if (-not $adapterMap.ContainsKey($index)) { continue }
        $adapter = $adapterMap[$index]
        if ([string]$adapter.Status -ne 'Up') { continue }

        $profile = $null
        if ($profileMap.ContainsKey($index)) { $profile = $profileMap[$index] }

        $category = 'Unavailable'
        if ($null -ne $profile) { $category = [string]$profile.NetworkCategory }

        $gateway = ''
        if ($routeMap.ContainsKey($index)) {
            $gateway = [string]$routeMap[$index].NextHop
        }

        $name = [string]$adapter.Name
        $description = [string]$adapter.InterfaceDescription
        $interfaceType = 0
        if ($null -ne $adapter.InterfaceType) { $interfaceType = [int]$adapter.InterfaceType }

        $isVirtual = [bool]$adapter.Virtual
        $combinedName = "$name $description"
        if ($combinedName -match '(?i)(hyper-v|vethernet|virtualbox|vmware|virtual|wsl|docker|loopback)') {
            $isVirtual = $true
        }
        $isVpn = ($interfaceType -eq 131) -or ($combinedName -match '(?i)\b(vpn|tap|tun|wireguard|openvpn|tailscale|zerotier|hamachi|sstp|l2tp|pptp|ikev2|ppp|tunnel|teredo|isatap|ip-https)\b')

        $score = 0
        $reasons = New-Object -TypeName 'System.Collections.Generic.List[string]'
        if ($isVirtual) {
            $score -= 20
            $reasons.Add('虚拟网卡')
        } else {
            $score += 50
            $reasons.Add('物理网卡')
        }
        if ($isVpn) {
            $score -= 40
            $reasons.Add('VPN/隧道')
        }
        switch ($category) {
            'Private'             { $score += 30; $reasons.Add('专用网络') }
            'DomainAuthenticated' { $score += 25; $reasons.Add('域网络') }
            'Public'              { $score += 15; $reasons.Add('Public 网络') }
            default               { $reasons.Add('网络类型未识别') }
        }
        if (-not [string]::IsNullOrWhiteSpace($gateway)) {
            $score += 20
            $reasons.Add('有默认网关')
        }

        $addresses.Add([pscustomobject]@{
            InterfaceIndex       = $index
            InterfaceAlias       = $name
            InterfaceDescription = $description
            IPAddress            = $address
            PrefixLength         = [int]$ip.PrefixLength
            NetworkCategory      = $category
            Gateway              = $gateway
            IsVirtual            = $isVirtual
            IsVpn                = $isVpn
            Score                = $score
            Recommended          = $false
            RecommendReason      = ''
            SelectionReason      = ($reasons -join '、')
        })
    }

    $list = $addresses.ToArray()
    if ($list.Count -gt 0) {
        $preferred = @($list | Where-Object {
            (-not $_.IsVirtual) -and (-not $_.IsVpn) -and
            ([string]$_.NetworkCategory -in @('Private', 'DomainAuthenticated', 'Public'))
        })

        if ($preferred.Count -eq 0) {
            $preferred = @($list | Where-Object {
                (-not $_.IsVirtual) -and (-not $_.IsVpn) -and
                ([string]$_.NetworkCategory -eq 'Unavailable') -and
                (-not [string]::IsNullOrWhiteSpace([string]$_.Gateway))
            })
        }

        if ($preferred.Count -gt 0) {
            $bestScore = ($preferred | Measure-Object -Property Score -Maximum).Maximum
            foreach ($item in $preferred) {
                if ([int]$item.Score -eq [int]$bestScore) {
                    $item.Recommended = $true
                    $item.RecommendReason = $item.SelectionReason
                }
            }
        }
    }

    return @($list | Sort-Object -Property @{ Expression = 'Recommended'; Descending = $true }, @{ Expression = 'Score'; Descending = $true }, InterfaceAlias, IPAddress)
}

function Write-NetworkAddressList {
    param($Addresses, [switch]$ShowCommands)

    $list = @($Addresses)
    if ($list.Count -eq 0) {
        Write-Warn '未发现可用的内网 IPv4 地址。请确认已连接到局域网。'
        return
    }

    $recommendedCount = @($list | Where-Object { $_.Recommended }).Count
    foreach ($address in $list) {
        $marker = ''
        if ($address.Recommended) {
            if ($recommendedCount -gt 1) {
                $marker = '  [推荐，并列]'
            } else {
                $marker = '  [推荐]'
            }
        }
        Write-Host ("内网地址：{0}{1}" -f $address.IPAddress, $marker) -ForegroundColor White
        Write-Host ("  网卡：{0}" -f $address.InterfaceAlias) -ForegroundColor Gray
        Write-Host ("  网络配置文件：{0}" -f (Format-NetworkCategory -Category $address.NetworkCategory)) -ForegroundColor Gray
        $gatewayText = $address.Gateway
        if ([string]::IsNullOrWhiteSpace([string]$gatewayText)) { $gatewayText = '-' }
        Write-Host ("  网关：{0}" -f $gatewayText) -ForegroundColor Gray

        if ($address.IsVpn) {
            Write-Host '  类型：VPN/隧道接口（通常仅同一 VPN 内可访问）' -ForegroundColor Yellow
        } elseif ($address.IsVirtual) {
            Write-Host '  类型：虚拟网卡（可能仅本机或虚拟网络可达）' -ForegroundColor Yellow
        } else {
            Write-Host '  类型：物理网卡' -ForegroundColor Gray
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$address.SelectionReason)) {
            Write-Host ("  判定依据：{0}" -f $address.SelectionReason) -ForegroundColor DarkGray
        }
        if ($ShowCommands) {
            Write-Host ("  连接命令：mstsc /v:{0}:{1}" -f $address.IPAddress, $script:RdpPort) -ForegroundColor Cyan
        }
        Write-Host ''
    }
}

function Get-ActiveNetworkProfileSummary {
    $connections = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    if ($connections.Count -eq 0) { return '未检测到' }
    $categories = @()
    foreach ($profile in $connections) {
        $categories += (Format-NetworkCategory -Category ([string]$profile.NetworkCategory))
    }
    return (($categories | Select-Object -Unique) -join '、')
}


# ---------------------------------------------------------------------------
# 启用后验证
# ---------------------------------------------------------------------------

function Test-RdpEnabledState {
    $errors = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $rdp = Get-RdpRegistryState
    if (-not $rdp.RdpEnabled) {
        $errors.Add('RDP 未启用（fDenyTSConnections 不为 0）')
    }
    if (-not $rdp.NlaEnabled) {
        $errors.Add('NLA 未启用（UserAuthentication 不为 1）')
    }
    if ($rdp.PortValue -ne $script:RdpPort) {
        $errors.Add("RDP 端口不是 3389（当前：$($rdp.PortValue)）")
    }

    $service = Get-TermServiceInfo
    if (-not $service.Exists -or [string]$service.Status -ne 'Running') {
        $errors.Add("TermService 未运行（当前：$($service.Status)）")
    }
    if (-not (Test-RdpListener)) {
        $errors.Add('TCP 3389 未监听')
    }

    $rules = @(Get-ManagedFirewallRules)
    if ($rules.Count -ne 1) {
        $errors.Add("本工具防火墙规则数量异常：$($rules.Count)")
    } else {
        $ruleErrors = @(Test-FirewallRuleConfiguration -Rule $rules[0])
        foreach ($ruleError in $ruleErrors) {
            $errors.Add("防火墙规则：$ruleError")
        }
    }

    $account = Get-RdpAccountInfo
    if (-not $account.Exists) {
        $errors.Add("账户 $($script:AccountName) 不存在")
    } else {
        if (-not $account.DescriptionMatches) { $errors.Add('账户说明字段不匹配') }
        if (-not $account.Enabled) { $errors.Add('账户已禁用') }
        if (-not $account.InRdpGroup) { $errors.Add('账户不在 Remote Desktop Users 组') }
        if ($account.InAdministrators) { $errors.Add('账户意外位于 Administrators 组') }
    }

    $policy = Get-RdpPolicyState
    if ($policy.fDenyTSConnections -eq 1) { $errors.Add('组策略仍禁止 RDP') }
    if ($policy.UserAuthentication -eq 0) { $errors.Add('组策略禁用了 NLA') }

    try {
        $firewall = Get-FirewallProfileStatus
        $activeCategories = @(Get-ActiveNetworkCategories)
        foreach ($category in $activeCategories) {
            $profileName = Get-FirewallProfileNameForCategory -Category $category
            if (-not [bool]$firewall.$profileName) {
                $errors.Add("当前活动的 $profileName 防火墙配置文件未启用")
            }
        }
    } catch {
        $errors.Add("无法验证活动网络/防火墙状态：$($_.Exception.Message)")
    }

    return [pscustomobject]@{
        Errors      = $errors.ToArray()
        Rdp         = $rdp
        TermService = $service
        Account     = $account
        Rules       = $rules
    }
}

# ---------------------------------------------------------------------------
# 结果展示
# ---------------------------------------------------------------------------

function Show-EnableResult {
    param(
        [Parameter(Mandatory = $true)][string]$Password,
        $Addresses,
        $RdpState,
        [string[]]$ActiveCategories = @(),
        $FirewallProfiles
    )

    Write-Banner
    Write-Kv '状态' '已启用' Green
    Write-Kv '计算机名称' $env:COMPUTERNAME
    Write-Kv '远程桌面端口' ([string]$script:RdpPort)
    Write-Kv '认证方式' 'Network Level Authentication'
    Write-Host '  说明：使用独立本地账户认证，不是多因素认证（MFA）。' -ForegroundColor DarkGray

    Write-Section '连接地址'
    Write-NetworkAddressList -Addresses $Addresses -ShowCommands

    Write-Section '远程桌面凭证'
    Write-Kv '用户名' '.\rdp_access' Yellow
    Write-Kv '密码' $Password Yellow
    Write-Host '  注意：密码仅在此处显示一次，本工具不会保存，也不会复制到剪贴板。' -ForegroundColor Red
    Write-Host '  请立即记录并妥善保存；关闭窗口后无法再次查看。' -ForegroundColor Red
    Write-Host '  连接时请使用该独立账户，不要使用 Windows 主账户密码。' -ForegroundColor Gray

    $categoryList = @($ActiveCategories)
    $categoryText = '未检测到'
    if ($categoryList.Count -gt 0) {
        $categoryText = ($categoryList -join ' / ')
    }
    $disabledProfiles = @()
    if ($null -ne $FirewallProfiles) {
        foreach ($profileName in @('Domain', 'Private', 'Public')) {
            if (-not [bool]$FirewallProfiles.$profileName) {
                $disabledProfiles += $profileName
            }
        }
    }

    $firewallText = '已启用（活动配置文件）'
    $firewallColor = [ConsoleColor]::Green
    if ($categoryList.Count -eq 0) {
        $firewallText = '未检测到活动网络，无法验证当前配置文件'
        $firewallColor = [ConsoleColor]::Yellow
    }

    Write-Section '安全状态'
    Write-Kv '防火墙' $firewallText $firewallColor
    Write-Kv '防火墙规则' '仅允许本地子网（TCP 3389，Domain/Private/Public）' Green
    Write-Kv '网络配置文件' $categoryText
    Write-Kv 'RDP 接入' '已允许' Green
    Write-Kv '防火墙范围' 'Public / Private / Domain' Green
    Write-Kv '允许来源' 'LocalSubnet' Green
    Write-Kv 'TCP 端口' ([string]$script:RdpPort)
    Write-Kv 'NLA' '已启用' Green
    Write-Kv 'RDP 安全层' (Format-SecurityLayer -RegistryValueInfo $RdpState.SecurityLayer)
    if ([bool]$RdpState.SecurityLayer.Exists -and [int]$RdpState.SecurityLayer.Value -lt 2) {
        Write-Warn '当前安全层低于建议值 2；本工具没有降低或修改该值，请管理员评估。'
    }
    Write-Kv '公网端口映射' '未由本工具配置（路由器侧请自行核查）'
    if ($disabledProfiles.Count -gt 0) {
        Write-Warn "以下防火墙配置文件未启用：$($disabledProfiles -join '、')。规则覆盖这些 Profile，但在防火墙关闭的配置下不会生效。"
    }

    Write-Host ''
    Write-Host '连接范围：本工具支持 Public/Private/Domain，但防火墙规则来源仍为 LocalSubnet。' -ForegroundColor Yellow
    Write-Host '同一子网中的其他设备也可能访问 TCP 3389；不同路由网段、VPN、CGNAT、路由器 NAT、客户端隔离或 ACL 不保证可达。' -ForegroundColor Yellow
    Write-Host '本工具不承诺任意互联网环境下的远程连接；不会自动修改网络配置文件类型。' -ForegroundColor DarkGray
    Write-Host '首次连接可能出现 RDP 证书警告；请在确认目标计算机名后继续。' -ForegroundColor DarkGray

    $list = @($Addresses)
    if ($list.Count -gt 0) {
        $commands = @()
        foreach ($address in $list) {
            $commands += ("mstsc /v:{0}:{1}" -f $address.IPAddress, $script:RdpPort)
        }

        $interactive = $true
        try {
            if ([Console]::IsInputRedirected) { $interactive = $false }
        } catch {
            $interactive = $true
        }

        if ($interactive) {
            $answer = ''
            try {
                $answer = Read-Host '是否将连接命令复制到剪贴板？（输入 y 确认，直接回车跳过）'
            } catch {
                $answer = ''
            }
            if ($null -ne $answer -and $answer.Trim().ToLowerInvariant() -eq 'y') {
                try {
                    Set-Clipboard -Value ($commands -join [Environment]::NewLine) -ErrorAction Stop
                    Write-Ok '连接命令已复制到剪贴板（不包含密码）。'
                } catch {
                    Write-Warn "复制连接命令失败：$($_.Exception.Message)"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 启用流程
# ---------------------------------------------------------------------------

function Invoke-EnableRdp {
    Assert-Administrator
    Assert-Prerequisites

    $systemInfo = Get-SystemInfo
    $support = Test-RdpHostSupport -SystemInfo $systemInfo
    if (-not $support.Supported) {
        throw $support.Reason
    }
    Write-Info "操作系统：$($systemInfo.Caption)（$($systemInfo.EditionId)，Build $($systemInfo.Build)）"

    $policy = Get-RdpPolicyState
    if ($policy.fDenyTSConnections -eq 1) {
        throw '组策略将 fDenyTSConnections 设为 1，禁用了 RDP。本工具不会修改组策略，请联系管理员。'
    }
    if ($policy.UserAuthentication -eq 0) {
        throw '组策略禁用了 NLA（UserAuthentication=0）。本工具不会降低安全要求，已停止。'
    }

    $rdpBefore = Get-RdpRegistryState
    if ($rdpBefore.PortValue -ne $script:RdpPort) {
        throw "系统 RDP 端口为 $($rdpBefore.PortValue)，不是 3389。本工具不修改端口，已停止。请先恢复默认端口或手动处理。"
    }

    $activeCategories = @(Assert-SafeNetworkProfile)
    $firewallProfiles = Assert-FirewallReady -ActiveCategories $activeCategories

    $account = Get-RdpAccountInfo
    if ($account.Exists -and -not $account.DescriptionMatches) {
        throw "本地账户 '$($script:AccountName)' 已存在，但说明字段不是 '$($script:ManagedDescription)'（当前：'$($account.Description)'）。为避免影响其他账户，本工具未做任何修改，已停止。"
    }
    Assert-FirewallRulePreflight

    $state = Read-StateFile
    if ($null -eq $state) {
        $state = New-ConfigSnapshot
        Save-StateFile -State $state
        Write-Ok '已保存运行前 RDP/服务配置快照（不包含任何密码）。'
    } else {
        Write-Info "检测到已有配置快照（创建于 $($state.CreatedAt)），将继续使用原始快照。"
    }

    Write-Section '应用配置'
    Initialize-TermService -State $state
    Set-RdpRegistryEnabled
    Ensure-RdpListener -State $state -WasRdpEnabled ([bool]$rdpBefore.RdpEnabled)

    $password = New-SecurePassword -Length 24
    try {
        $account = Initialize-RdpAccount -Password $password
        $state.AccountSid = $account.Sid
        Save-StateFile -State $state

        Initialize-FirewallRule -State $state

        try {
            $riskyRules = @(Get-RiskyRdpRules)
            if ($riskyRules.Count -gt 0) {
                Write-Warn "发现 $($riskyRules.Count) 条范围可能过宽的 3389 入站规则（本工具不会修改）："
                foreach ($risky in $riskyRules) {
                    Write-Host ("  - {0} | Profile={1} | RemoteAddress={2} | {3}" -f $risky.DisplayName, $risky.Profile, $risky.RemoteAddress, $risky.Reason) -ForegroundColor Yellow
                }
                Write-Warn '这些规则允许任意远程地址，可能扩大暴露范围；请管理员核查。'
            }
        } catch {
            Write-Warn "检查现有 3389 入站规则失败：$($_.Exception.Message)"
        }

        $after = Get-RdpRegistryState
        if ([bool]$after.SecurityLayer.Exists -and [int]$after.SecurityLayer.Value -lt 2) {
            Write-Warn "当前 RDP 安全层为 $($after.SecurityLayer.Value)，低于建议值 2。本工具未修改该值；请管理员评估。"
        }

        $verification = Test-RdpEnabledState
        if ($verification.Errors.Count -gt 0) {
            throw ("启用后验证失败：" + [Environment]::NewLine + "- " + ($verification.Errors -join ([Environment]::NewLine + "- ")))
        }

        $addresses = @(Get-NetworkAddresses)
        Show-EnableResult -Password $password -Addresses $addresses -RdpState $after -ActiveCategories $activeCategories -FirewallProfiles $firewallProfiles
    } finally {
        $password = $null
    }
}

# ---------------------------------------------------------------------------
# 状态检查
# ---------------------------------------------------------------------------

function Invoke-Status {
    Assert-Administrator
    Assert-Prerequisites

    Write-Banner 'STATUS'

    $systemInfo = Get-SystemInfo
    $support = Test-RdpHostSupport -SystemInfo $systemInfo
    $rdp = Get-RdpRegistryState
    $policy = Get-RdpPolicyState
    $service = Get-TermServiceInfo
    $listener = Test-RdpListener
    $account = Get-RdpAccountInfo
    $rules = @(Get-ManagedFirewallRules)

    $state = $null
    $stateError = $null
    try {
        $state = Read-StateFile
    } catch {
        $stateError = $_.Exception.Message
    }

    $ruleErrors = @()
    if ($rules.Count -eq 1) {
        $ruleErrors = @(Test-FirewallRuleConfiguration -Rule $rules[0])
    }

    $accountOk = ($account.Exists -and $account.DescriptionMatches -and $account.Enabled -and $account.InRdpGroup -and (-not $account.InAdministrators))
    $ruleOk = ($rules.Count -eq 1 -and $ruleErrors.Count -eq 0)

    $overall = '未启用'
    if ($rdp.RdpEnabled) {
        if ($rdp.NlaEnabled -and $listener -and $ruleOk -and $accountOk) {
            $overall = 'RDP 已启用，工具配置完整'
        } else {
            $overall = 'RDP 已启用，但本工具配置不完整'
        }
    } else {
        if ($account.Exists -and $account.DescriptionMatches) {
            $overall = 'RDP 已关闭，专用账户仍保留'
        } elseif (-not $account.Exists) {
            $overall = 'RDP 已关闭，专用账户已删除'
        } else {
            $overall = 'RDP 已关闭'
        }
    }

    if ($overall -eq 'RDP 已启用，工具配置完整') {
        Write-Kv '状态' $overall Green
    } else {
        Write-Kv '状态' $overall Yellow
    }
    Write-Kv '计算机名称' $env:COMPUTERNAME
    Write-Kv '操作系统' ("{0}（{1}，Build {2}）" -f $systemInfo.Caption, $systemInfo.EditionId, $systemInfo.Build)
    if ($support.Supported) {
        Write-Kv 'RDP Host 支持' '支持' Green
    } else {
        Write-Kv 'RDP Host 支持' ('不支持：' + $support.Reason) Red
    }

    Write-Section 'RDP 配置'
    if ([bool]$rdp.Deny.Exists) {
        if ($rdp.DenyValue -eq 0) {
            Write-Kv 'fDenyTSConnections' "$($rdp.DenyValue)（已启用）" Green
        } else {
            Write-Kv 'fDenyTSConnections' "$($rdp.DenyValue)（已禁用）" Yellow
        }
    } else {
        Write-Kv 'fDenyTSConnections' '未设置' Yellow
    }
    if ([bool]$rdp.Nla.Exists) {
        if ($rdp.NlaValue -eq 1) {
            Write-Kv 'NLA（UserAuthentication）' '1（已启用）' Green
        } else {
            Write-Kv 'NLA（UserAuthentication）' "$($rdp.NlaValue)（未启用）" Red
        }
    } else {
        Write-Kv 'NLA（UserAuthentication）' '未设置' Yellow
    }
    Write-Kv 'RDP 端口' ([string]$rdp.PortValue)
    Write-Kv 'RDP 安全层' (Format-SecurityLayer -RegistryValueInfo $rdp.SecurityLayer)
    if ($rdp.PortValue -ne $script:RdpPort) {
        Write-Warn "RDP 端口不是 3389（当前：$($rdp.PortValue)）。本工具不会修改端口。"
    }
    if ([bool]$rdp.SecurityLayer.Exists -and [int]$rdp.SecurityLayer.Value -lt 2) {
        Write-Warn 'RDP 安全层低于建议值 2；本工具不会降低该值，请管理员评估。'
    }
    if ($policy.fDenyTSConnections -eq 1) {
        Write-Warn '组策略设置了 fDenyTSConnections=1（禁止 RDP）。'
    }
    if ($policy.UserAuthentication -eq 0) {
        Write-Warn '组策略设置了 UserAuthentication=0（禁用 NLA）。'
    }

    Write-Section 'TermService'
    if ($service.Exists) {
        Write-Kv '服务状态' $service.Status
        Write-Kv '启动类型' $service.StartType
    } else {
        Write-Kv '服务状态' '不存在' Red
    }
    if ($listener) {
        Write-Kv 'TCP 3389 监听' '是' Green
    } else {
        Write-Kv 'TCP 3389 监听' '否' Yellow
    }

    Write-Section '防火墙'
    try {
        $profiles = Get-FirewallProfileStatus
        foreach ($key in @('Domain', 'Private', 'Public')) {
            if ($profiles.PSObject.Properties[$key]) {
                if ([bool]$profiles.$key) {
                    Write-Kv ("{0} 配置文件防火墙" -f $key) '已启用' Green
                } else {
                    Write-Kv ("{0} 配置文件防火墙" -f $key) '未启用' Red
                }
            } else {
                Write-Kv ("{0} 配置文件防火墙" -f $key) '无法读取' Yellow
            }
        }
    } catch {
        Write-Err "读取防火墙配置文件失败：$($_.Exception.Message)"
    }

    if ($rules.Count -eq 0) {
        Write-Kv '本工具防火墙规则' '不存在' Yellow
    } elseif ($rules.Count -gt 1) {
        Write-Kv '本工具防火墙规则' "存在 $($rules.Count) 条同名规则（冲突）" Red
    } elseif ([string]$rules[0].Description -cne $script:ManagedDescription) {
        Write-Kv '本工具防火墙规则' '同名规则存在，但说明字段不匹配（非本工具管理）' Red
    } elseif ($ruleErrors.Count -eq 0) {
        Write-Kv '本工具防火墙规则' '已启用，TCP 3389，仅 LocalSubnet，Domain/Private/Public' Green
    } else {
        Write-Kv '本工具防火墙规则' '配置异常' Red
        foreach ($ruleError in $ruleErrors) {
            Write-Err "防火墙规则：$ruleError"
        }
    }

    $riskyRules = @()
    try {
        $riskyRules = @(Get-RiskyRdpRules)
    } catch {
        Write-Warn "检查范围过宽的 3389 入站规则失败：$($_.Exception.Message)"
    }
    if ($riskyRules.Count -eq 0) {
        Write-Kv '其他范围过宽的 3389 入站规则' '未发现' Green
    } else {
        Write-Warn "发现 $($riskyRules.Count) 条范围可能过宽的 3389 入站规则（本工具不会修改它们）："
        foreach ($risky in $riskyRules) {
            Write-Host ("  - {0} | Profile={1} | RemoteAddress={2} | {3}" -f $risky.DisplayName, $risky.Profile, $risky.RemoteAddress, $risky.Reason) -ForegroundColor Yellow
        }
    }

    Write-Section '专用账户'
    if (-not $account.Exists) {
        Write-Kv '账户 rdp_access' '不存在' Yellow
    } else {
        Write-Kv '账户 rdp_access' '存在'
        if ($account.DescriptionMatches) {
            Write-Kv '说明字段' $account.Description Green
        } else {
            Write-Kv '说明字段' ("不匹配（当前：{0}），非本工具管理" -f $account.Description) Red
        }
        if ($account.Enabled) { Write-Kv '账户状态' '已启用' Green } else { Write-Kv '账户状态' '已禁用' Red }
        if ($account.InRdpGroup) { Write-Kv 'Remote Desktop Users' '是' Green } else { Write-Kv 'Remote Desktop Users' '否' Yellow }
        if ($account.InAdministrators) { Write-Kv 'Administrators' '是（不符合标准用户要求）' Red } else { Write-Kv 'Administrators' '否' Green }
        if ($null -eq $account.PasswordExpires) {
            Write-Kv '密码过期时间' '不过期' Green
        } else {
            Write-Kv '密码过期时间' ($account.PasswordExpires.ToString('yyyy-MM-dd HH:mm:ss')) Yellow
        }
    }

    Write-Section '网络地址'
    $connections = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    $activeCategories = @()
    try {
        $activeCategories = @(Get-ActiveNetworkCategories)
    } catch {
        Write-Warn "无法读取网络配置文件类别：$($_.Exception.Message)"
    }
    Write-Kv '支持的网络配置文件' 'Public / Private / Domain'
    if ($connections.Count -eq 0) {
        Write-Warn '未检测到活动网络连接。'
    } else {
        foreach ($connection in $connections) {
            Write-Host ("网络：{0} | 配置文件：{1} | 接口：{2}" -f $connection.Name, (Format-NetworkCategory -Category ([string]$connection.NetworkCategory)), $connection.InterfaceAlias) -ForegroundColor Gray
        }
        if ($activeCategories -contains 'Public') {
            Write-Info '当前网络配置文件：Public'
            Write-Info '本工具支持该配置文件。'
            if ($ruleOk) {
                Write-Ok 'RDP 防火墙规则覆盖 Public。'
            } else {
                Write-Warn 'RDP 防火墙规则未完整覆盖 Public，当前配置不完整。'
            }
            Write-Info '来源限制：LocalSubnet。'
            Write-Warn '注意：同一子网中的其他设备也可能访问 TCP 3389。'
        } else {
            Write-Info '防火墙来源限制：LocalSubnet；同一子网中的其他设备也可能访问 TCP 3389。'
        }
    }
    $addresses = @()
    try {
        $addresses = @(Get-NetworkAddresses)
    } catch {
        Write-Warn "枚举内网地址失败：$($_.Exception.Message)"
    }
    Write-NetworkAddressList -Addresses $addresses -ShowCommands

    Write-Section '状态快照'
    $stateAcl = $null
    try {
        $stateAcl = Get-StateDirectoryAclInfo
        if (-not $stateAcl.Exists) {
            Write-Kv '状态目录/文件权限' '未创建' Gray
        } elseif ($stateAcl.UsersWrite) {
            Write-Kv '状态目录/文件权限' $stateAcl.Message Red
        } else {
            Write-Kv '状态目录/文件权限' $stateAcl.Message Green
        }
    } catch {
        Write-Warn "检查状态目录 ACL 失败：$($_.Exception.Message)"
    }
    if ($null -ne $state) {
        Write-Kv '状态文件' $script:StatePath
        Write-Kv '创建时间' ([string]$state.CreatedAt)
        if ([bool]$state.Rdp.fDenyTSConnections.Exists) {
            Write-Kv '原始 fDenyTSConnections' ([string]$state.Rdp.fDenyTSConnections.Value)
        } else {
            Write-Kv '原始 fDenyTSConnections' '未设置'
        }
        if ([bool]$state.Rdp.UserAuthentication.Exists) {
            Write-Kv '原始 UserAuthentication' ([string]$state.Rdp.UserAuthentication.Value)
        } else {
            Write-Kv '原始 UserAuthentication' '未设置'
        }
        Write-Kv '原始 TermService 启动类型' ([string]$state.TermService.StartupTypeBefore)
        if ([bool]$state.TermService.StartupTypeChanged) {
            Write-Kv 'TermService 启动类型已修改' '是' Yellow
        } else {
            Write-Kv 'TermService 启动类型已修改' '否'
        }
        if ([string]::IsNullOrWhiteSpace([string]$state.AccountSid)) {
            Write-Kv '账户 SID 记录' '无'
        } else {
            Write-Kv '账户 SID 记录' ([string]$state.AccountSid)
        }
    } elseif ($null -ne $stateError) {
        Write-Err $stateError
    } else {
        Write-Info '未找到状态快照（可能从未运行，或已成功关闭）。'
    }

    Write-Section '风险提示'
    $riskCount = 0
    if (-not $support.Supported) {
        Write-Warn $support.Reason
        $riskCount++
    }
    if ($riskyRules.Count -gt 0) {
        Write-Warn '存在范围可能过宽的 3389 入站规则，请管理员核查；本工具未修改它们。'
        $riskCount++
    }
    if (-not $accountOk -and $account.Exists -and -not $account.DescriptionMatches) {
        Write-Warn '存在同名但非本工具管理的 rdp_access 账户；本工具不会删除或修改它。'
        $riskCount++
    }
    if ($null -eq $state -and ($rdp.RdpEnabled -or $rules.Count -gt 0 -or $account.Exists)) {
        Write-Warn '检测到 RDP/账户/规则，但没有状态快照；-RestoreOriginal 无法恢复原始注册表配置。'
        $riskCount++
    }
    if ($rdp.RdpEnabled -and -not $account.Exists -and $rules.Count -eq 0) {
        Write-Warn '检测到 RDP 已启用，但没有本工具账户或防火墙规则；可能由其他方式配置。'
        $riskCount++
    }
    if ($null -ne $stateAcl -and $stateAcl.Exists -and $stateAcl.UsersWrite) {
        Write-Warn '状态目录/文件存在非 Administrators/SYSTEM 的可写权限；下次启用时会尝试修复。'
        $riskCount++
    }
    if ($riskCount -eq 0) {
        Write-Ok '未发现需要特别提示的风险项。'
    }
}

# ---------------------------------------------------------------------------
# 关闭流程
# ---------------------------------------------------------------------------

function Restore-RdpRegistryValue {
    param(
        [string]$Label,
        [string]$Path,
        [string]$Name,
        [int]$AppliedValue,
        $Snapshot
    )

    if ($null -eq $Snapshot) {
        throw "$Label 的快照缺失。"
    }

    $snapshotExists = [bool]$Snapshot.Exists
    $snapshotValue = $null
    if ($snapshotExists) {
        $snapshotValue = [int]$Snapshot.Value
    }

    $current = Get-RegistryValueInfo -Path $Path -Name $Name
    $currentExists = [bool]$current.Exists
    $currentValue = $null
    if ($currentExists) {
        $currentValue = [int]$current.Value
    }

    if ($snapshotExists) {
        if ($currentExists -and $currentValue -eq $snapshotValue) {
            return [pscustomobject]@{
                Label   = $Label
                Status  = 'AlreadyOriginal'
                Message = "当前已是运行前状态（$snapshotValue），无需恢复。"
            }
        }
    } else {
        if (-not $currentExists) {
            return [pscustomobject]@{
                Label   = $Label
                Status  = 'AlreadyOriginal'
                Message = '当前已是运行前状态（值不存在），无需恢复。'
            }
        }
    }

    if ((-not $currentExists) -or $currentValue -ne $AppliedValue) {
        return [pscustomobject]@{
            Label   = $Label
            Status  = 'Skipped'
            Message = '当前值与快照和本工具写入值都不同，可能已被管理员修改；未覆盖。'
        }
    }

    if ($snapshotExists) {
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $snapshotValue -Type DWord -ErrorAction Stop
        $after = Get-RegistryValueInfo -Path $Path -Name $Name
        if (-not [bool]$after.Exists -or [int]$after.Value -ne $snapshotValue) {
            throw "$Label 恢复后验证失败。"
        }
        return [pscustomobject]@{
            Label   = $Label
            Status  = 'Restored'
            Message = "已恢复为运行前的值 $snapshotValue。"
        }
    }

    Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    $after = Get-RegistryValueInfo -Path $Path -Name $Name
    if ([bool]$after.Exists) {
        throw "$Label 删除后验证失败，值仍然存在。"
    }
    return [pscustomobject]@{
        Label   = $Label
        Status  = 'Restored'
        Message = '已删除运行前不存在的注册表值。'
    }
}

function Restore-RdpRegistryState {
    param($State)

    $targets = @(
        [pscustomobject]@{
            Label    = 'RDP 启用状态（fDenyTSConnections）'
            Path     = $script:TsKey
            Name     = 'fDenyTSConnections'
            Applied  = 0
            Snapshot = $State.Rdp.fDenyTSConnections
        },
        [pscustomobject]@{
            Label    = 'NLA（UserAuthentication）'
            Path     = $script:RdpTcpKey
            Name     = 'UserAuthentication'
            Applied  = 1
            Snapshot = $State.Rdp.UserAuthentication
        }
    )

    $results = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($target in $targets) {
        try {
            if ($null -eq $target.Snapshot) {
                throw "$($target.Label) 的快照缺失。"
            }
            if ([bool]$target.Snapshot.Exists) {
                $snapshotValue = [int]$target.Snapshot.Value
                if ($snapshotValue -notin @(0, 1)) {
                    throw "$($target.Label) 的快照值无效：$snapshotValue。为避免写入错误配置，未恢复该项。"
                }
            }
            $restoreParams = @{
                Label        = $target.Label
                Path         = $target.Path
                Name         = $target.Name
                AppliedValue = $target.Applied
                Snapshot     = $target.Snapshot
            }
            $result = Restore-RdpRegistryValue @restoreParams
            $results.Add($result)
        } catch {
            $results.Add([pscustomobject]@{
                Label   = $target.Label
                Status  = 'Error'
                Message = $_.Exception.Message
            })
        }
    }
    return $results.ToArray()
}

function Restore-TermServiceStartup {
    param($State)

    if (-not [bool]$State.TermService.StartupTypeChanged) {
        return [pscustomobject]@{
            Status  = 'NoChange'
            Message = 'TermService 启动类型未被本工具修改。'
        }
    }

    $target = [string]$State.TermService.StartupTypeBefore
    if ($target -notin @('Automatic', 'Manual', 'Disabled')) {
        return [pscustomobject]@{
            Status  = 'Error'
            Message = "快照中的 TermService 启动类型无效：$target"
        }
    }

    $current = Get-TermServiceInfo
    if (-not $current.Exists) {
        return [pscustomobject]@{
            Status  = 'Error'
            Message = 'TermService 不存在，无法恢复启动类型。'
        }
    }
    if ($current.StartType -eq $target) {
        return [pscustomobject]@{
            Status  = 'AlreadyOriginal'
            Message = "当前启动类型已是 $target，无需恢复。"
        }
    }
    if ($current.StartType -ne 'Manual') {
        return [pscustomobject]@{
            Status  = 'Skipped'
            Message = "当前启动类型为 $($current.StartType)，不是本工具设置的 Manual，可能已被管理员修改；未覆盖。"
        }
    }

    Set-Service -Name 'TermService' -StartupType $target -ErrorAction Stop
    $after = Get-TermServiceInfo
    if ($after.StartType -ne $target) {
        throw "TermService 启动类型恢复后验证失败（当前：$($after.StartType)）。"
    }
    return [pscustomobject]@{
        Status  = 'Restored'
        Message = "已恢复为 $target。"
    }
}

function Invoke-DeleteAccountCore {
    $result = [pscustomobject]@{
        Success       = $false
        Deleted       = $false
        AccountExists = $false
        Reason        = ''
        Message       = ''
        Sessions      = @()
        AdminRemoved  = $false
    }

    $account = Get-RdpAccountInfo
    if (-not $account.Exists) {
        $result.Success = $true
        $result.Reason = 'NotFound'
        $result.Message = "账户 $($script:AccountName) 不存在（可能已删除）。"
        return $result
    }
    $result.AccountExists = $true

    if (-not $account.DescriptionMatches) {
        $result.Reason = 'OwnershipMismatch'
        $result.Message = "同名账户存在，但说明字段不是 '$($script:ManagedDescription)'（当前：'$($account.Description)'）。不会删除其他账户。"
        return $result
    }

    $state = $null
    $stateError = $null
    try {
        $state = Read-StateFile
    } catch {
        $stateError = $_.Exception.Message
    }
    if ($null -eq $state -and $null -ne $stateError) {
        $result.Reason = 'StateUnavailable'
        $result.Message = "状态快照存在但无法读取，无法验证 AccountSid：$stateError"
        return $result
    }
    if ($null -ne $state -and -not [string]::IsNullOrWhiteSpace([string]$state.AccountSid)) {
        if ([string]$account.Sid -ne [string]$state.AccountSid) {
            $result.Reason = 'SidMismatch'
            $result.Message = "状态快照记录的 AccountSid（$($state.AccountSid)）与当前账户 SID（$($account.Sid)）不一致。不会删除。"
            return $result
        }
    }

    if ($account.InAdministrators) {
        try {
            Remove-LocalGroupMember -SID $script:AdministratorsSid -Member $script:AccountName -Confirm:$false -ErrorAction Stop
            $adminCheck = Get-RdpAccountInfo
            if ($adminCheck.InAdministrators) {
                throw '账户仍在 Administrators 组中。'
            }
            $result.AdminRemoved = $true
        } catch {
            $result.Reason = 'AdminRemovalFailed'
            $result.Message = "账户仍位于 Administrators 组，且移除失败：$($_.Exception.Message)"
            return $result
        }
    }

    $sessionInfo = Get-RdpAccountSessionInfo
    $result.Sessions = @($sessionInfo.Sessions)
    if (-not $sessionInfo.Checked) {
        $result.Reason = 'SessionCheckFailed'
        $result.Message = '无法确认账户的本地/远程登录会话状态。为避免误删，已拒绝删除。'
        return $result
    }
    if ($sessionInfo.InUse) {
        $result.Reason = 'ActiveSessions'
        $result.Message = '账户仍存在本地登录、远程桌面或未注销会话。请先正常注销后再删除。'
        return $result
    }

    try {
        Remove-LocalUser -Name $script:AccountName -Confirm:$false -ErrorAction Stop
        $after = Get-RdpAccountInfo
        if ($after.Exists) {
            throw '账户删除后仍然存在。'
        }
        $result.Success = $true
        $result.Deleted = $true
        $result.Reason = 'Deleted'
        $result.Message = "已删除本工具管理的账户 $($script:AccountName)。"
    } catch {
        $result.Reason = 'DeleteFailed'
        $result.Message = "删除账户失败：$($_.Exception.Message)"
    }
    return $result
}

function Invoke-DisableRdpCore {
    $result = [pscustomobject]@{
        Success              = $false
        RdpClosed            = $false
        FirewallRuleRemoved  = $false
        ManagedRuleRemaining = $false
        RuleStatus           = 'Unknown'
        AccountExists        = $false
        SnapshotExists       = $false
        NlaEnabled           = $false
        ListenerActive       = $false
        Errors               = @()
        Warnings             = @()
    }
    $errors = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $warnings = New-Object -TypeName 'System.Collections.Generic.List[string]'

    $result.AccountExists = (Get-RdpAccountInfo).Exists
    $result.SnapshotExists = (Test-Path -LiteralPath $script:StatePath -PathType Leaf)
    $rdpBefore = Get-RdpRegistryState
    $result.NlaEnabled = [bool]$rdpBefore.NlaEnabled
    $result.ListenerActive = Test-RdpListener

    $policy = Get-RdpPolicyState
    if ($policy.fDenyTSConnections -eq 0) {
        $errors.Add('组策略将 fDenyTSConnections 固定为 0，强制启用 RDP。本工具不会修改组策略，无法保证关闭。')
        $result.Errors = $errors.ToArray()
        $result.Warnings = $warnings.ToArray()
        return $result
    }

    try {
        Set-ItemProperty -LiteralPath $script:TsKey -Name 'fDenyTSConnections' -Value 1 -Type DWord -ErrorAction Stop
        $after = Get-RdpRegistryState
        if (-not [bool]$after.Deny.Exists -or [int]$after.Deny.Value -ne 1) {
            throw '写入 fDenyTSConnections=1 后验证失败。'
        }
        $result.RdpClosed = $true
    } catch {
        $errors.Add("关闭 RDP 失败：$($_.Exception.Message)")
    }

    $policyAfter = Get-RdpPolicyState
    if ($policyAfter.fDenyTSConnections -eq 0) {
        $errors.Add('组策略仍将 fDenyTSConnections 固定为 0；RDP 可能被策略重新启用。')
        $result.RdpClosed = $false
    }

    $rules = @(Get-ManagedFirewallRules)
    $removed = 0
    $conflict = $false
    if ($rules.Count -eq 0) {
        $result.FirewallRuleRemoved = $true
        $result.RuleStatus = 'NotPresent'
    } else {
        foreach ($rule in $rules) {
            if ([string]$rule.Description -cne $script:ManagedDescription) {
                $warnings.Add("同名防火墙规则 '$($script:FirewallRuleName)' 不属于本工具，已保留。")
                $conflict = $true
                continue
            }
            try {
                Remove-NetFirewallRule -Name $rule.Name -Confirm:$false -ErrorAction Stop
                $removed++
            } catch {
                $errors.Add("删除防火墙规则失败：$($_.Exception.Message)")
            }
        }
        $remainingRules = @(Get-ManagedFirewallRules)
        $remainingOurs = @($remainingRules | Where-Object { [string]$_.Description -ceq $script:ManagedDescription })
        if ($remainingOurs.Count -gt 0) {
            $result.ManagedRuleRemaining = $true
            $result.RuleStatus = 'Remaining'
            $errors.Add("仍有 $($remainingOurs.Count) 条本工具防火墙规则未删除。")
        } elseif ($removed -gt 0) {
            $result.FirewallRuleRemoved = $true
            $result.RuleStatus = 'Removed'
        } elseif ($conflict) {
            $result.FirewallRuleRemoved = $true
            $result.RuleStatus = 'Conflict'
        } else {
            $result.FirewallRuleRemoved = $true
            $result.RuleStatus = 'NotPresent'
        }
    }

    $result.Errors = $errors.ToArray()
    $result.Warnings = $warnings.ToArray()
    $result.Success = ($errors.Count -eq 0 -and $result.RdpClosed -and -not $result.ManagedRuleRemaining)
    return $result
}

function Invoke-RestoreOriginal {
    Assert-Administrator
    Assert-Prerequisites

    Write-Banner 'RESTORE ORIGINAL'

    $errors = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $warnings = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $actions = New-Object -TypeName 'System.Collections.Generic.List[string]'

    $state = $null
    $stateError = $null
    try {
        $state = Read-StateFile
    } catch {
        $stateError = $_.Exception.Message
    }

    $account = Get-RdpAccountInfo
    $rules = @(Get-ManagedFirewallRules)
    $foundArtifacts = ($null -ne $state) -or $account.Exists -or ($rules.Count -gt 0)

    if (-not $foundArtifacts) {
        Write-Info '未发现本工具创建的账户、防火墙规则或状态快照，无需关闭。'
        Write-Kv '状态' '未发现本工具配置' Green
        $currentRdp = Get-RdpRegistryState
        if ($currentRdp.RdpEnabled) {
            Write-Kv 'RDP 当前状态' '已启用（未发现本工具配置，未修改）' Yellow
            Write-Info 'RDP 可能由其他方式启用；本工具不会猜测或覆盖其原始配置。'
        } else {
            Write-Kv 'RDP 当前状态' '未启用' Green
        }
        return $true
    }

    if ($null -ne $state) {
        Write-Section '恢复 RDP 配置'
        $restoreResults = @(Restore-RdpRegistryState -State $state)
        foreach ($result in $restoreResults) {
            switch ($result.Status) {
                'Restored' {
                    Write-Ok "$($result.Label)：$($result.Message)"
                    $actions.Add("$($result.Label)：$($result.Message)")
                }
                'AlreadyOriginal' {
                    Write-Info "$($result.Label)：$($result.Message)"
                }
                'Skipped' {
                    Write-Warn "$($result.Label)：$($result.Message)"
                    $warnings.Add("$($result.Label)：$($result.Message)")
                }
                'Error' {
                    Write-Err "$($result.Label)：$($result.Message)"
                    $errors.Add("$($result.Label)：$($result.Message)")
                }
                default {
                    $warnings.Add("$($result.Label)：未知恢复状态 $($result.Status)")
                }
            }
        }

        try {
            $serviceResult = Restore-TermServiceStartup -State $state
            switch ($serviceResult.Status) {
                'Restored' {
                    Write-Ok "TermService 启动类型：$($serviceResult.Message)"
                    $actions.Add("TermService 启动类型：$($serviceResult.Message)")
                }
                'AlreadyOriginal' {
                    Write-Info "TermService 启动类型：$($serviceResult.Message)"
                }
                'NoChange' {
                    Write-Info "TermService 启动类型：$($serviceResult.Message)"
                }
                'Skipped' {
                    Write-Warn "TermService 启动类型：$($serviceResult.Message)"
                    $warnings.Add("TermService 启动类型：$($serviceResult.Message)")
                }
                'Error' {
                    Write-Err "TermService 启动类型：$($serviceResult.Message)"
                    $errors.Add("TermService 启动类型：$($serviceResult.Message)")
                }
            }
        } catch {
            Write-Err "恢复 TermService 启动类型失败：$($_.Exception.Message)"
            $errors.Add("恢复 TermService 启动类型失败：$($_.Exception.Message)")
        }
    } else {
        if ($null -ne $stateError) {
            Write-Err $stateError
            $warnings.Add($stateError)
        } else {
            Write-Warn '未找到状态快照，无法确认运行前的 RDP 注册表配置；不会猜测或覆盖这些值。'
            $warnings.Add('未找到状态快照，RDP 注册表配置未恢复。')
        }
    }

    Write-Section '移除专用账户'
    $accountDelete = $null
    try {
        $accountDelete = Invoke-DeleteAccountCore
    } catch {
        Write-Err "删除账户失败：$($_.Exception.Message)"
        $errors.Add("删除账户失败：$($_.Exception.Message)")
    }
    if ($null -ne $accountDelete) {
        if ($accountDelete.AdminRemoved) {
            Write-Warn '账户原先位于 Administrators 组，已将其移除。'
            $warnings.Add('账户原先位于 Administrators 组，已移除其管理员成员资格。')
        }
        switch ($accountDelete.Reason) {
            'Deleted' {
                Write-Ok $accountDelete.Message
                $actions.Add("删除账户 $($script:AccountName)")
            }
            'NotFound' {
                Write-Info $accountDelete.Message
            }
            'ActiveSessions' {
                Write-Warn $accountDelete.Message
                foreach ($session in @($accountDelete.Sessions)) {
                    if ($session.Detail) {
                        Write-Host ("  - {0}：{1}" -f $session.Source, $session.Detail) -ForegroundColor Yellow
                    } elseif ($session.LogonType) {
                        Write-Host ("  - {0}：LogonId={1}，LogonType={2}" -f $session.Source, $session.LogonId, $session.LogonType) -ForegroundColor Yellow
                    }
                }
                $warnings.Add('专用账户存在活动/未注销会话，未删除。')
            }
            'OwnershipMismatch' {
                Write-Warn $accountDelete.Message
                $warnings.Add('同名账户说明字段不匹配，未删除。')
            }
            'SidMismatch' {
                Write-Warn $accountDelete.Message
                $warnings.Add('账户 SID 与快照不一致，未删除。')
            }
            'StateUnavailable' {
                Write-Warn $accountDelete.Message
                $warnings.Add('状态快照不可读，未删除账户。')
            }
            'SessionCheckFailed' {
                Write-Warn $accountDelete.Message
                $warnings.Add('无法确认账户会话状态，未删除账户。')
            }
            'AdminRemovalFailed' {
                Write-Err $accountDelete.Message
                $errors.Add($accountDelete.Message)
            }
            'DeleteFailed' {
                Write-Err $accountDelete.Message
                $errors.Add($accountDelete.Message)
            }
            default {
                $warnings.Add("删除账户返回未知状态：$($accountDelete.Reason)")
            }
        }
    }

    Write-Section '移除防火墙规则'
    $rules = @(Get-ManagedFirewallRules)
    if ($rules.Count -eq 0) {
        Write-Info "未发现防火墙规则 $($script:FirewallRuleName)。"
    } else {
        foreach ($rule in $rules) {
            if ([string]$rule.Description -cne $script:ManagedDescription) {
                Write-Warn "同名防火墙规则 '$($script:FirewallRuleName)' 的说明字段不匹配，已跳过，不会删除其他人的规则。"
                $warnings.Add('同名防火墙规则说明字段不匹配，未删除。')
                continue
            }
            try {
                Remove-NetFirewallRule -Name $rule.Name -Confirm:$false -ErrorAction Stop
                Write-Ok "已删除防火墙规则：$($script:FirewallRuleName)"
                $actions.Add("删除防火墙规则 $($script:FirewallRuleName)")
            } catch {
                Write-Err "删除防火墙规则失败：$($_.Exception.Message)"
                $errors.Add("删除防火墙规则失败：$($_.Exception.Message)")
            }
        }
    }

    $remainingRules = @(Get-ManagedFirewallRules)
    $remainingOurs = @($remainingRules | Where-Object { [string]$_.Description -ceq $script:ManagedDescription })
    if ($remainingOurs.Count -gt 0) {
        $errors.Add("仍有 $($remainingOurs.Count) 条本工具防火墙规则未删除。")
    } elseif ($remainingRules.Count -gt 0) {
        $warnings.Add('仍存在同名但非本工具管理的防火墙规则，已保留。')
    }

    if ($errors.Count -eq 0 -and $warnings.Count -eq 0 -and $null -ne $state) {
        try {
            if (Test-Path -LiteralPath $script:StatePath) {
                Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction Stop
                Write-Ok '已删除状态快照文件。'
            }
            $tempStatePath = $script:StatePath + '.tmp'
            if (Test-Path -LiteralPath $tempStatePath) {
                Remove-Item -LiteralPath $tempStatePath -Force -ErrorAction Stop
                Write-Ok '已清理状态快照临时文件。'
            }
        } catch {
            Write-Err "删除状态快照失败：$($_.Exception.Message)"
            $errors.Add("删除状态快照失败：$($_.Exception.Message)")
        }
    }

    $finalRdp = Get-RdpRegistryState

    Write-Section '处理结果'
    if ($errors.Count -eq 0 -and $warnings.Count -eq 0) {
        if ($null -ne $state -and $finalRdp.RdpEnabled) {
            Write-Kv '状态' '本工具配置已移除（RDP 保持运行前已启用状态）' Green
        } else {
            Write-Kv '状态' '已关闭（本工具配置已移除）' Green
        }
    } elseif ($errors.Count -eq 0) {
        Write-Kv '状态' '部分完成（有项目被跳过，请查看警告）' Yellow
    } else {
        Write-Kv '状态' '未完全关闭（存在错误）' Red
    }

    if ($null -ne $state) {
        if ($finalRdp.RdpEnabled) {
            Write-Kv 'RDP 当前状态' '已启用（运行前即为启用状态，已按快照恢复）' Yellow
        } else {
            Write-Kv 'RDP 当前状态' '未启用（已按快照恢复）' Green
        }
    } else {
        if ($finalRdp.RdpEnabled) {
            Write-Kv 'RDP 当前状态' '已启用（无快照，未恢复）' Yellow
        } else {
            Write-Kv 'RDP 当前状态' '未启用' Green
        }
    }
    if (-not $finalRdp.NlaEnabled) {
        Write-Warn '当前 NLA 未启用；若这是运行前状态，本工具已按快照恢复。建议手动保持 NLA 开启。'
    }

    if ($actions.Count -gt 0) {
        Write-Host ''
        Write-Host '已完成的操作：' -ForegroundColor Green
        foreach ($action in $actions) { Write-Host "  - $action" -ForegroundColor Green }
    }
    if ($warnings.Count -gt 0) {
        Write-Host ''
        Write-Host '警告（未覆盖或需人工处理）：' -ForegroundColor Yellow
        foreach ($warning in $warnings) { Write-Host "  - $warning" -ForegroundColor Yellow }
    }
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-Host '错误：' -ForegroundColor Red
        foreach ($errorItem in $errors) { Write-Host "  - $errorItem" -ForegroundColor Red }
    }

    Write-Host ''
    Write-Host '说明：本工具不会删除 Windows 用户配置文件目录，也不会停止 TermService（以免影响其他会话）。' -ForegroundColor DarkGray
    if ($null -ne $state -and $errors.Count -gt 0) {
        Write-Host "如需重试，状态快照仍保留在：$script:StatePath" -ForegroundColor DarkGray
    }

    return ($errors.Count -eq 0 -and $warnings.Count -eq 0)
}

function Invoke-DisableRdp {
    Assert-Administrator
    Assert-Prerequisites

    $result = Invoke-DisableRdpCore
    Write-Banner 'DISABLED'

    if ($result.RdpClosed) {
        Write-Kv 'RDP' '已关闭' Green
    } else {
        Write-Kv 'RDP' '关闭失败' Red
    }
    if ($result.NlaEnabled) {
        Write-Kv 'NLA' '未主动削弱（当前已启用）' Green
    } else {
        Write-Kv 'NLA' '未主动削弱（当前未启用，本操作未修改）' Yellow
    }
    switch ($result.RuleStatus) {
        'Removed' {
            Write-Kv '防火墙规则' '已移除' Green
        }
        'NotPresent' {
            Write-Kv '防火墙规则' '不存在（无需移除）' Green
        }
        'Conflict' {
            Write-Kv '防火墙规则' '本工具规则不存在；同名非本工具规则已保留' Yellow
        }
        'Remaining' {
            Write-Kv '防火墙规则' '未完全移除' Red
        }
        default {
            Write-Kv '防火墙规则' '状态未知' Yellow
        }
    }
    if ($result.AccountExists) {
        Write-Kv '专用账户' '仍保留' Yellow
    } else {
        Write-Kv '专用账户' '不存在（未创建）' Green
    }
    if ($result.SnapshotExists) {
        Write-Kv '状态快照' '已保留' Green
    } else {
        Write-Kv '状态快照' '无状态快照' Yellow
    }

    Write-Host ''
    Write-Host '说明：' -ForegroundColor Cyan
    Write-Host '  当前已禁止新的 RDP 连接。已有 RDP 会话可能仍然存在；本操作不会强制注销。'
    Write-Host '  如果需要重新开启，请运行 RDP-Enable.bat。'
    Write-Host '  如果需要删除专用账户，请运行 RDP-Delete-Account.bat。'
    if ($result.ListenerActive) {
        Write-Host '  TCP 3389 监听可能仍然存在；TermService 未被强制停止。' -ForegroundColor DarkGray
    }

    if ($result.Warnings.Count -gt 0) {
        Write-Host ''
        Write-Host '警告：' -ForegroundColor Yellow
        foreach ($warning in @($result.Warnings)) { Write-Host "  - $warning" -ForegroundColor Yellow }
    }
    if ($result.Errors.Count -gt 0) {
        Write-Host ''
        Write-Host '错误：' -ForegroundColor Red
        foreach ($errorItem in @($result.Errors)) { Write-Host "  - $errorItem" -ForegroundColor Red }
        Write-Kv '状态' 'RDP 关闭或规则清理未完全成功' Red
    } elseif ($result.RdpClosed) {
        Write-Kv '状态' '已关闭' Green
    } else {
        Write-Kv '状态' '关闭失败' Red
    }
    return $result.Success
}

function Invoke-DeleteAccount {
    Assert-Administrator
    Assert-Prerequisites

    $result = Invoke-DeleteAccountCore
    Write-Banner 'DELETE ACCOUNT'

    switch ($result.Reason) {
        'Deleted' {
            Write-Kv '状态' '已删除' Green
            Write-Kv '账户' $script:AccountName
            Write-Kv '归属验证' '通过' Green
            Write-Kv '活动会话' '无' Green
        }
        'NotFound' {
            Write-Kv '状态' '账户不存在（可能已删除）' Green
            Write-Kv '账户' $script:AccountName
        }
        'ActiveSessions' {
            Write-Kv '状态' '未删除（存在活动会话）' Yellow
            Write-Kv '账户' $script:AccountName
            foreach ($session in @($result.Sessions)) {
                if ($session.Detail) {
                    Write-Host ("  - {0}：{1}" -f $session.Source, $session.Detail) -ForegroundColor Yellow
                } elseif ($session.LogonType) {
                    Write-Host ("  - {0}：LogonId={1}，LogonType={2}" -f $session.Source, $session.LogonId, $session.LogonType) -ForegroundColor Yellow
                }
            }
            Write-Host '  请先正常注销该账户的本地/远程会话；本工具不会强制踢出会话。' -ForegroundColor Yellow
        }
        default {
            Write-Kv '状态' '未删除' Red
            Write-Host ("  {0}" -f $result.Message) -ForegroundColor Red
        }
    }

    if ($result.AdminRemoved) {
        Write-Warn '账户原先位于 Administrators 组，已移除其管理员成员资格。'
    }
    Write-Host ''
    Write-Kv '用户配置文件' '保留（未删除）'
    Write-Kv 'RDP 状态' '未修改'
    Write-Kv '防火墙规则' '未修改'
    Write-Kv '状态快照' '保留'
    Write-Host ''
    Write-Host '说明：单独删除账户不会关闭 RDP；其他有权限的 Windows 账户仍可能使用 RDP。' -ForegroundColor DarkGray
    return $result.Success
}

function Invoke-DisableAndDelete {
    Assert-Administrator
    Assert-Prerequisites

    $disable = Invoke-DisableRdpCore
    $delete = Invoke-DeleteAccountCore
    $allOk = ($disable.Success -and $delete.Success)

    Write-Banner 'REMOVED'
    if ($disable.RdpClosed) {
        Write-Kv 'RDP' '已关闭' Green
    } else {
        Write-Kv 'RDP' '关闭失败' Red
    }
    switch ($disable.RuleStatus) {
        'Removed' { Write-Kv '受管防火墙规则' '已删除' Green }
        'NotPresent' { Write-Kv '受管防火墙规则' '不存在（无需删除）' Green }
        'Conflict' { Write-Kv '受管防火墙规则' '本工具规则不存在；同名非本工具规则保留' Yellow }
        'Remaining' { Write-Kv '受管防火墙规则' '未完全删除' Red }
        default { Write-Kv '受管防火墙规则' '状态未知' Yellow }
    }
    switch ($delete.Reason) {
        'Deleted' {
            Write-Kv '专用账户' '已删除' Green
        }
        'NotFound' {
            Write-Kv '专用账户' '不存在（已删除）' Green
        }
        'ActiveSessions' {
            Write-Kv '专用账户' '保留（存在活动会话）' Yellow
        }
        'OwnershipMismatch' {
            Write-Kv '专用账户' '未删除（说明字段不匹配）' Red
        }
        'SidMismatch' {
            Write-Kv '专用账户' '未删除（SID 与快照不一致）' Red
        }
        'StateUnavailable' {
            Write-Kv '专用账户' '未删除（状态快照不可读）' Red
        }
        'SessionCheckFailed' {
            Write-Kv '专用账户' '未删除（无法确认会话状态）' Red
        }
        'AdminRemovalFailed' {
            Write-Kv '专用账户' '未删除（无法移除管理员成员资格）' Red
        }
        'DeleteFailed' {
            Write-Kv '专用账户' '删除失败' Red
        }
        default {
            Write-Kv '专用账户' '未删除' Red
        }
    }
    Write-Kv '用户配置文件' '保留（未删除）'
    Write-Kv '状态快照' '保留'
    Write-Host ''
    Write-Host '其他 Windows 用户账户未受影响。' -ForegroundColor Gray

    if ($delete.Reason -eq 'ActiveSessions') {
        Write-Host ''
        Write-Host '当前账户仍有活动/未注销会话，已保留账户。请先正常注销；本工具不会强制踢出。' -ForegroundColor Yellow
        foreach ($session in @($delete.Sessions)) {
            if ($session.Detail) {
                Write-Host ("  - {0}：{1}" -f $session.Source, $session.Detail) -ForegroundColor Yellow
            } elseif ($session.LogonType) {
                Write-Host ("  - {0}：LogonId={1}，LogonType={2}" -f $session.Source, $session.LogonId, $session.LogonType) -ForegroundColor Yellow
            }
        }
    }
    if ($delete.AdminRemoved) {
        Write-Warn '账户原先位于 Administrators 组，已移除其管理员成员资格。'
    }

    if ($disable.Warnings.Count -gt 0) {
        Write-Host ''
        Write-Host '警告：' -ForegroundColor Yellow
        foreach ($warning in @($disable.Warnings)) { Write-Host "  - $warning" -ForegroundColor Yellow }
    }
    if ($disable.Errors.Count -gt 0) {
        Write-Host ''
        Write-Host '错误：' -ForegroundColor Red
        foreach ($errorItem in @($disable.Errors)) { Write-Host "  - $errorItem" -ForegroundColor Red }
    }
    if ($delete.Reason -eq 'ActiveSessions') {
        Write-Kv '状态' 'PARTIAL（RDP 已关闭，账户因活动会话保留）' Yellow
    } elseif ($allOk) {
        Write-Kv '状态' '已移除' Green
    } elseif ($disable.RdpClosed) {
        Write-Kv '状态' 'PARTIAL（账户或规则清理未完全成功）' Yellow
    } else {
        Write-Kv '状态' 'FAILED' Red
    }
    return $allOk
}

# ---------------------------------------------------------------------------
# 帮助和主入口
# ---------------------------------------------------------------------------

function Show-Help {
    Write-Banner
    Write-Host '用法：' -ForegroundColor Cyan
    Write-Host '  RDP-Enable.bat                      开启/维护 RDP、创建或轮换专用账户并显示凭证'
    Write-Host '  RDP-Disable.bat                     关闭新的 RDP 连接，删除受管防火墙规则；保留账户和快照'
    Write-Host '  RDP-Delete-Account.bat              只删除受管专用账户；不改变 RDP 和防火墙'
    Write-Host '  RDP-Disable-And-Delete.bat          关闭 RDP、删除规则，并在无活动会话时删除账户'
    Write-Host '  RDP-Status.bat                      只读检查当前 RDP、账户、防火墙和网络状态'
    Write-Host '  RDP-Restore-Original.bat            完整恢复运行前快照'
    Write-Host '  RDP-QuickAccess.bat                 向后兼容：默认开启；支持 -Status / -Disable / -Help'
    Write-Host '  RDP-QuickAccess.bat -Disable        旧版兼容别名，等同 RDP-Restore-Original.bat'
    Write-Host '  RDP-QuickAccess.bat -Help           显示本帮助（不需要管理员权限）'
    Write-Host ''
    Write-Host '操作说明：' -ForegroundColor Cyan
    Write-Host '  * 开启、关闭、删除账户、完整恢复是独立操作，账户生命周期由独立 BAT 显式控制。'
    Write-Host '  * 关闭窗口不会删除账户；RDP-Disable 只关闭新连接并保留账户和状态快照。'
    Write-Host '  * 删除账户前检查本地/远程登录会话；存在活动或未注销会话时拒绝删除，不强制注销。'
    Write-Host '  * RDP-Disable-And-Delete 在账户有活动会话时输出 PARTIAL，并保留账户。'
    Write-Host ''
    Write-Host '安全说明：' -ForegroundColor Yellow
    Write-Host '  * 仅支持 Windows 10/11 专业版、企业版、教育版、专业工作站版；家庭版会被拒绝。'
    Write-Host '  * 创建 LocalSubnet + Domain/Private/Public 的 TCP 3389 入站规则；RemoteAddress 仍为 LocalSubnet。'
    Write-Host '  * 支持 Public/Private/Domain 网络配置文件；不会自动修改网络配置文件类型。'
    Write-Host '  * LocalSubnet 不等于“只有我的设备”；同一局域网或 Public Wi-Fi 上的其他设备也可能访问 TCP 3389。'
    Write-Host '  * 不同路由网段、VPN、CGNAT、路由器 NAT、客户端隔离或 ACL 不保证可达；不承诺任意互联网环境下的远程连接。'
    Write-Host '  * 不关闭防火墙、不修改 3389 端口、不降低 NLA/安全层、不修改全局密码策略。'
    Write-Host '  * 独立本地账户 rdp_access，不是 Windows 主账户，也不是 MFA/双因素认证。'
    Write-Host '  * 密码仅在启用成功后显示一次，不保存、不写日志、不自动复制到剪贴板。'
    Write-Host '  * 本工具不是公网 RDP 暴露工具；不会修改路由器、UPnP 或端口映射。'
    Write-Host ''
    Write-Host '兼容性：Windows PowerShell 5.1；需要管理员权限；支持中文和空格路径。' -ForegroundColor DarkGray
}

function Invoke-Main {
    if ($Help) {
        Show-Help
        return 0
    }

    $modes = @()
    if ($Enable) { $modes += 'Enable' }
    if ($DisableRdp) { $modes += 'DisableRdp' }
    if ($DeleteAccount) { $modes += 'DeleteAccount' }
    if ($DisableAndDelete) { $modes += 'DisableAndDelete' }
    if ($Status) { $modes += 'Status' }
    if ($RestoreOriginal) { $modes += 'RestoreOriginal' }

    if ($modes.Count -gt 1) {
        throw '一次只能使用一个操作参数：-Enable / -DisableRdp / -DeleteAccount / -DisableAndDelete / -Status / -RestoreOriginal。旧版 -Disable 等同 -RestoreOriginal。'
    }

    $mode = 'Enable'
    if ($modes.Count -eq 1) { $mode = $modes[0] }

    switch ($mode) {
        'Enable' {
            Invoke-EnableRdp
            return 0
        }
        'DisableRdp' {
            if (Invoke-DisableRdp) { return 0 }
            return 1
        }
        'DeleteAccount' {
            if (Invoke-DeleteAccount) { return 0 }
            return 1
        }
        'DisableAndDelete' {
            if (Invoke-DisableAndDelete) { return 0 }
            return 1
        }
        'Status' {
            Invoke-Status
            return 0
        }
        'RestoreOriginal' {
            if (Invoke-RestoreOriginal) { return 0 }
            return 1
        }
        default {
            throw "未知操作模式：$mode"
        }
    }
}

try {
    $exitCode = Invoke-Main
    exit $exitCode
} catch {
    Write-Failure -Message $_.Exception.Message
    exit 1
}

