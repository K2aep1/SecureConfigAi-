"""PowerShell source for every collector — exactly one invocation each.

Each constant below is a complete collector program.  It runs inside
:mod:`scanner.psrun`, which wraps it with a UTF-8 prelude and a compressed
``ConvertTo-Json`` epilogue, and it must leave its result in ``$scaiResult``.

Design rules enforced here (spec sections 5 and 6):

* one program per collector — no per-query process launches, no N+1 cmdlet
  pipelines (never pipe each firewall rule into a per-rule ``*Filter`` cmdlet);
* every program emits **aggregates and bounded lists**, never raw provider
  objects;
* nothing is converted into ``false``/``0`` when the read failed — unreadable
  evidence is reported as ``$null`` plus a short ``unavailable`` reason;
* ``ConvertTo-Json`` is only ever used with an explicit ``-Depth`` (and
  ``-Compress``), which the epilogue guarantees.
"""

from __future__ import annotations

__all__ = ["SCRIPTS", "script_for"]

_DEVICE = r"""
$os = $null
try {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
  $os = $null
}
$name = $null
$version = $null
$build = $null
$architecture = $null
$installDate = $null
$lastBoot = $null
$windowsDirectory = $null
$computerName = $null
if ($os) {
  $name = $os.Caption
  $version = $os.Version
  $build = $os.BuildNumber
  $architecture = $os.OSArchitecture
  # ConvertTo-Json renders raw [datetime] as "/Date(ms)/"; emit ISO-8601 instead.
  if ($os.InstallDate) { try { $installDate = ([datetime]$os.InstallDate).ToString('o') } catch { $installDate = [string]$os.InstallDate } }
  if ($os.LastBootUpTime) { try { $lastBoot = ([datetime]$os.LastBootUpTime).ToString('o') } catch { $lastBoot = [string]$os.LastBootUpTime } }
  $windowsDirectory = $os.WindowsDirectory
  $computerName = $os.CSName
}
$serial = $null
try {
  $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
  if ($bios) { $serial = $bios.SerialNumber }
} catch { $serial = $null }
$scaiResult = [pscustomobject]@{
  status = 'completed'
  hostname = $env:COMPUTERNAME
  os = 'windows'
  name = $name
  version = $version
  build = $build
  architecture = $architecture
  install_date = $installDate
  last_boot = $lastBoot
  serial_number = $serial
  windows_directory = $windowsDirectory
  computer_name = $computerName
}
"""

_FIREWALL = r"""
$profileRows = @()
$profileError = $null
try {
  $profileRows = @(
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
      Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
                    LogBlocked, LogAllowed, LogFileName, LogMaxSizeKilobytes
  )
} catch {
  $profileError = $_.Exception.Message
}
$setting = $null
try {
  $setting = Get-NetFirewallSetting -PolicyStore ActiveStore -ErrorAction Stop
} catch { $setting = $null }
$profiles = @()
$logging = [ordered]@{}
foreach ($row in $profileRows) {
  $label = [string]$row.Name
  $profiles += [pscustomobject]@{
    name = $label
    enabled = [bool]$row.Enabled
    inbound = [string]$row.DefaultInboundAction
    outbound = [string]$row.DefaultOutboundAction
  }
  $logging[$label] = [pscustomobject]@{
    LogBlocked = [bool]$row.LogBlocked
    LogAllowed = [bool]$row.LogAllowed
    LogFileName = [string]$row.LogFileName
    LogMaxSizeKilobytes = $row.LogMaxSizeKilobytes
  }
}
# One pass over the rule set, aggregated inside PowerShell. No filter cmdlets.
$byDirection = @{}
$byAction = @{}
$byProfile = @{}
$byEnabled = @{}
$ruleTotal = 0
$ruleEnabled = 0
$inboundBlock = 0
$inboundAllow = 0
$ruleError = $null
try {
  $rules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
    Select-Object Direction, Action, Profile, Enabled
  foreach ($rule in $rules) {
    $ruleTotal++
    $direction = [string]$rule.Direction
    $action = [string]$rule.Action
    $profileName = [string]$rule.Profile
    $isEnabled = [bool]$rule.Enabled
    if ($byDirection.ContainsKey($direction)) { $byDirection[$direction]++ } else { $byDirection[$direction] = 1 }
    if ($byAction.ContainsKey($action)) { $byAction[$action]++ } else { $byAction[$action] = 1 }
    if ($byProfile.ContainsKey($profileName)) { $byProfile[$profileName]++ } else { $byProfile[$profileName] = 1 }
    $enabledKey = 'disabled'
    if ($isEnabled) { $enabledKey = 'enabled' }
    if ($byEnabled.ContainsKey($enabledKey)) { $byEnabled[$enabledKey]++ } else { $byEnabled[$enabledKey] = 1 }
    if ($isEnabled) {
      $ruleEnabled++
      if ($direction -eq 'Inbound') {
        if ($action -eq 'Block' -or $action -eq 'NotConfigured') { $inboundBlock++ } else { $inboundAllow++ }
      }
    }
  }
} catch {
  $ruleError = $_.Exception.Message
}
$allEnabled = $false
if ($profiles.Count -gt 0 -and $profiles.Count -eq $profileRows.Count) {  $allEnabled = $true
  foreach ($p in $profiles) { if (-not $p.enabled) { $allEnabled = $false } }
}
$ruleSummary = $null
if ($ruleTotal -gt 0) {
  $ruleSummary = [pscustomobject]@{
    total = $ruleTotal
    enabled = $ruleEnabled
    disabled = ($ruleTotal - $ruleEnabled)
    enabled_inbound_block = $inboundBlock
    enabled_inbound_allow = $inboundAllow
    by_direction = $byDirection
    by_action = $byAction
    by_profile = $byProfile
    by_enabled = $byEnabled
    filters_collected = $false
  }
}
$settingsSummary = $null
if ($setting) {
  $settingsSummary = [pscustomobject]@{
    allow_local_firewall_rules = $setting.AllowLocalFirewallRules
    allow_local_ipsec_rules = $setting.AllowLocalIPsecRules
    notify_on_listen = $setting.NotifyOnListen
    allow_unicast_response_to_multicast = $setting.AllowUnicastResponseToMulticast
    disable_unicast_response_to_multicast = $setting.DisableUnicastResponseToMulticast
    allow_stealth_mode_for_ipsec = $setting.AllowIPsecStealthMode
  }
}
$scaiResult = [pscustomobject]@{
  status = 'completed'
  enabled = $allEnabled
  profiles = $profiles
  profile_error = $profileError
  logging = $logging
  rule_summary = $ruleSummary
  rule_error = $ruleError
  global_settings = $settingsSummary
  collection = [pscustomobject]@{
    policy_store = 'ActiveStore'
    rule_filters_collected = $false
    per_rule_filter_calls = 0
  }
}
"""

_SYSTEM_HARDENING = r"""
# --- BitLocker -----------------------------------------------------------
$bitlockerStatus = 'unavailable'
$bitlockerError = $null
$bitlockerVolumes = @()
try {
  $bitlockerVolumes = @(
    Get-BitLockerVolume -ErrorAction Stop |
      Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage,
                    EncryptionMethod, AutoUnlockEnabled, LockStatus
  )
  $bitlockerStatus = 'completed'
} catch {
  $bitlockerError = $_.Exception.Message
}
$osVolume = $null
if ($bitlockerVolumes.Count -gt 0) {
  foreach ($v in $bitlockerVolumes) { if ([string]$v.MountPoint -eq 'C:') { $osVolume = $v } }
  if (-not $osVolume) { $osVolume = $bitlockerVolumes[0] }
}
$bitlockerEnabled = $null
$osProtection = $null
$osVolumeStatus = $null
if ($osVolume) {
  $osProtection = [string]$osVolume.ProtectionStatus
  $osVolumeStatus = [string]$osVolume.VolumeStatus
  $normalizedVolume = $osVolumeStatus -replace '\s', ''
  $bitlockerEnabled = $false
  if ($normalizedVolume -eq 'FullyEncrypted' -and ($osProtection -eq 'On' -or $osProtection -eq '1')) {
    $bitlockerEnabled = $true
  }
}
# --- Defender ------------------------------------------------------------
$defenderStatus = 'unavailable'
$defenderError = $null
$mp = $null
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $defenderStatus = 'completed'
} catch {
  $defenderError = $_.Exception.Message
}
$preference = $null
try {
  $preference = Get-MpPreference -ErrorAction Stop |
    Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection,
                  DisableScriptScanning, PUAProtection, MAPSReporting, SubmitSamplesConsent
} catch { $preference = $null }
$defender = [pscustomobject]@{
  status = $defenderStatus
  error = $defenderError
  enabled = $null
  real_time_protection = $null
  antispyware_enabled = $null
  behavior_monitoring = $null
  ioav_protection = $null
  network_inspection = $null
  tamper_protection = $null
  signature_version = $null
  signature_age = $null
  engine_version = $null
  platform_version = $null
  last_quick_scan = $null
}
if ($mp) {
  $defender.enabled = $mp.AntivirusEnabled
  $defender.real_time_protection = $mp.RealTimeProtectionEnabled
  $defender.antispyware_enabled = $mp.AntispywareEnabled
  $defender.behavior_monitoring = $mp.BehaviorMonitorEnabled
  $defender.ioav_protection = $mp.IoavProtectionEnabled
  $defender.network_inspection = $mp.NISEnabled
  $defender.tamper_protection = $mp.IsTamperProtected
  $defender.signature_version = $mp.AntivirusSignatureVersion
  $defender.signature_age = $mp.AntivirusSignatureAge
  $defender.engine_version = $mp.AMEngineVersion
  $defender.platform_version = $mp.AMProductVersion
  if ($mp.QuickScanStartTime) {
    try { $defender.last_quick_scan = ([datetime]$mp.QuickScanStartTime).ToString('o') } catch { $defender.last_quick_scan = [string]$mp.QuickScanStartTime }
  }
}
$defender | Add-Member -NotePropertyName preferences -NotePropertyValue $preference -Force
# --- UAC -----------------------------------------------------------------
$uacStatus = 'unavailable'
$uacError = $null
$uac = $null
try {
  $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop |
    Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop,
                  EnableInstallerDetection, ValidateAdminCodeSignatures, FilterAdministratorToken
  $uacStatus = 'completed'
} catch {
  $uacError = $_.Exception.Message
}
$uacBlock = [pscustomobject]@{
  status = $uacStatus
  error = $uacError
  EnableLUA = $null
  ConsentPromptBehaviorAdmin = $null
  PromptOnSecureDesktop = $null
  EnableInstallerDetection = $null
  ValidateAdminCodeSignatures = $null
  FilterAdministratorToken = $null
}
if ($uac) {
  foreach ($prop in @('EnableLUA','ConsentPromptBehaviorAdmin','PromptOnSecureDesktop','EnableInstallerDetection','ValidateAdminCodeSignatures','FilterAdministratorToken')) {
    $raw = $uac.$prop
    if ($null -ne $raw) { $uacBlock.$prop = [int]$raw }
  }
}
$uacEnabled = $null
if ($uacStatus -eq 'completed' -and $null -ne $uacBlock.EnableLUA) {
  $uacEnabled = $false
  if ($uacBlock.EnableLUA -eq 1) { $uacEnabled = $true }
}
# --- Secure Boot ---------------------------------------------------------
$secureBootSupported = $false
$secureBoot = $null
$secureBootError = $null
try {
  $secureBootKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
  if (Test-Path -LiteralPath $secureBootKey) {
    $secureBootSupported = $true
    $state = Get-ItemProperty -LiteralPath $secureBootKey -Name UEFISecureBootEnabled -ErrorAction Stop
    if ($null -ne $state.UEFISecureBootEnabled) {
      $secureBoot = $false
      if ([int]$state.UEFISecureBootEnabled -eq 1) { $secureBoot = $true }
    }
  } else {
    try {
      $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
      $secureBootSupported = $true
    } catch {
      $secureBootError = $_.Exception.Message
    }
  }
} catch {
  $secureBootError = $_.Exception.Message
}
$scaiResult = [pscustomobject]@{
  status = 'completed'
  bitlocker = [pscustomobject]@{
    status = $bitlockerStatus
    error = $bitlockerError
    enabled = $bitlockerEnabled
    volume = $osVolume
    volume_status = $osVolumeStatus
    protection_status = $osProtection
    volumes = $bitlockerVolumes
  }
  defender = $defender
  uac = $uacBlock
  uac_enabled = $uacEnabled
  secure_boot = $secureBoot
  secure_boot_supported = $secureBootSupported
  secure_boot_error = $secureBootError
}
"""

_TPM = r"""
$status = 'unavailable'
$errorText = $null
$tpm = $null
try {
  $probe = Get-Tpm -ErrorAction Stop
  if ($null -eq $probe) {
    # Non-elevated Get-Tpm emits only a warning on stderr and returns nothing.
    $errorText = 'Get-Tpm returned no data (administrator privilege is required)'
  } elseif (@($probe.PSObject.Properties.Name) -ccontains 'TpmPresent') {
    # Elevated Get-Tpm yields Microsoft.Tpm.Commands.TpmObject, which is neither
    # a PSCustomObject nor a string, so probe for the property we actually need.
    $tpm = $probe
    $status = 'completed'
  } else {
    # Some builds write "Administrator privilege is required..." to the output.
    $errorText = [string]$probe
  }
} catch {
  $errorText = $_.Exception.Message
}$specVersion = $null
if ($tpm) {
  try { $specVersion = [string]$tpm.SpecVersion } catch { $specVersion = $null }
}
$scaiResult = [pscustomobject]@{
  status = $status
  error = $errorText
  # Honest absence: no usable Get-Tpm object means every flag is unknown, not false.
  present = $(if ($tpm) { $tpm.TpmPresent } else { $null })
  ready = $(if ($tpm) { $tpm.TpmReady } else { $null })
  enabled = $(if ($tpm) { $tpm.TpmEnabled } else { $null })
  activated = $(if ($tpm) { $tpm.TpmActivated } else { $null })
  specification_version = $specVersion
  manufacturer_version = $(if ($tpm) { [string]$tpm.ManufacturerVersion } else { $null })
}
"""

_AUTHENTICATION = r"""
$scaiSeceditPath = $env:SCAI_SECEDIT_PATH
$seceditError = $null
$seceditValues = @{}
$source = $null
if ($scaiSeceditPath) {
  try {
    $seceditOutput = & secedit.exe /export /cfg $scaiSeceditPath /quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
      $seceditError = "secedit exit code $LASTEXITCODE"
    } elseif (Test-Path -LiteralPath $scaiSeceditPath) {
      $section = $null
      foreach ($line in (Get-Content -LiteralPath $scaiSeceditPath)) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[(.+)\]$') {
          $section = $Matches[1]
          continue
        }
        if (-not $section) { continue }
        if ($section -ne 'System Access' -and $section -ne 'Kerberos Policy') { continue }
        if ($trimmed -match '^([A-Za-z0-9_]+)\s*=\s*(.*)$') {
          # Prefix so a single entry cannot collapse into a bare string.
          $seceditValues["policy:$($Matches[1].Trim())"] = $Matches[2].Trim()
        }
      }
      if (@($seceditValues.Keys).Count -gt 0) { $source = 'secedit' } else { $seceditError = 'secedit exported no policy values' }
    } else {
      $seceditError = 'secedit produced no output file'
    }
  } catch {
    $seceditError = $_.Exception.Message
  }
}
$netAccountsError = $null
$netValues = @{}
if ($source -eq $null) {
  try {
    $netOutput = & net.exe accounts 2>&1
    $mapping = [ordered]@{
      'Minimum password length'          = 'MinimumPasswordLength'
      'Maximum password age'             = 'MaximumPasswordAge'
      'Minimum password age'             = 'MinimumPasswordAge'
      'Lockout threshold'                = 'LockoutBadCount'
      'Lockout duration'                 = 'LockoutDuration'
      'Length of password history'       = 'PasswordHistorySize'
    }
    foreach ($line in @($netOutput)) {
      $text = [string]$line
      $colon = $text.IndexOf(':')
      if ($colon -lt 1) { continue }
      $label = $text.Substring(0, $colon).Trim()
      $value = $text.Substring($colon + 1).Trim()
      foreach ($key in $mapping.Keys) {
        if ($label -eq $key) { $netValues[$mapping[$key]] = $value }
        elseif ($label -like "$key*") { $netValues[$mapping[$key]] = $value }
      }
      if ($label -eq 'Password complexity' -or $label -like 'Password complexity*') {
        $netValues['PasswordComplexity'] = $value
      }
    }
    if (@($netValues.Keys).Count -gt 0) {
      $source = 'net_accounts'
      foreach ($pair in $netValues.GetEnumerator()) { $seceditValues["policy:$($pair.Key)"] = $pair.Value }
    } else {
      $netAccountsError = 'net accounts produced no parsable policy lines'
    }
  } catch {
    $netAccountsError = $_.Exception.Message
  }
}
function Convert-ScaiInt([string]$raw) {
  if ($null -eq $raw) { return $null }
  $text = $raw.Trim()
  if ($text -eq '') { return $null }
  $match = [regex]::Match($text, '^-?\d+')
  if (-not $match.Success) { return $null }
  return [int]$match.Value
}
function Convert-ScaiComplexity([string]$raw) {
  if ($null -eq $raw) { return $null }
  $text = $raw.Trim().ToLowerInvariant()
  if ($text -eq '1' -or $text -eq 'true') { return $true }
  if ($text -eq '0' -or $text -eq 'false') { return $false }
  return $null
}
$minimumLength = Convert-ScaiInt $seceditValues['policy:MinimumPasswordLength']
$lockoutThreshold = Convert-ScaiInt $seceditValues['policy:LockoutBadCount']
$lockoutDuration = Convert-ScaiInt $seceditValues['policy:LockoutDuration']
$maximumAge = Convert-ScaiInt $seceditValues['policy:MaximumPasswordAge']
$minimumAge = Convert-ScaiInt $seceditValues['policy:MinimumPasswordAge']
$complexity = Convert-ScaiComplexity $seceditValues['policy:PasswordComplexity']
$scaiResult = [pscustomobject]@{
  status = 'completed'
  source = $source
  minimum_length = $minimumLength
  lockout_threshold = $lockoutThreshold
  lockout_duration = $lockoutDuration
  maximum_password_age = $maximumAge
  minimum_password_age = $minimumAge
  complexity = $complexity
  probe_errors = [pscustomobject]@{
    secedit = $seceditError
    net_accounts = $netAccountsError
  }
}
"""

_UPDATES = r"""
$source = $null
$pendingCount = $null
$days = $null
$latest = $null
$history = @()
$wuaError = $null
$hotfixError = $null
$wuaSufficient = $false
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  # Offline mode: local datastore only, so the collector cannot block on WU.
  $searcher.Online = $false
  $pending = $searcher.Search("IsInstalled=0 and Type='Software'")
  $pendingCount = [int]$pending.Updates.Count
  try {
    $installed = $searcher.Search("IsInstalled=1 and Type='Software'")
    foreach ($update in $installed.Updates) {
      # The WUA object model reports install dates as [datetime]; some providers
      # leave them null, in which case Get-HotFix is the better evidence source.
      $parsed = $null
      $candidates = @($update.LastInstallationDate, $update.Date)
      foreach ($candidate in $candidates) {
        if ($parsed) { break }
        if ($null -ne $candidate) {
          try { $parsed = [datetime]$candidate } catch { $parsed = $null }
        }
      }
      $kb = $null
      try {
        $ids = @($update.KBArticleIDs)
        if ($ids.Count -gt 0) { $kb = [string]$ids[0] }
      } catch { $kb = $null }
      $history += [pscustomobject]@{
        id = [string]$update.Title
        installed_on = $(if ($parsed) { $parsed.ToString('yyyy-MM-dd') } else { '' })
        kb = $kb
        applied_at = $parsed
      }
    }
    $dated = @($history | Where-Object { $_.applied_at })
    if ($dated.Count -gt 0) {
      $sorted = @($dated | Sort-Object -Property applied_at -Descending)
      $latest = $sorted[0]
      $source = 'windows_update_com'
      $wuaSufficient = $true
      $days = [int][math]::Max(0, ([datetime]::Now.Date - $latest.applied_at.Date).Days)
      $history = @($sorted | Select-Object -First 25 | Select-Object id, installed_on, kb)
      $latest = [pscustomobject]@{ id = $latest.id; installed_on = $latest.installed_on }
    } elseif ($history.Count -gt 0 -and $null -eq $wuaError) {
      $wuaError = 'Windows Update Agent reported no installation dates'
    }
  } catch {
    if ($null -eq $wuaError) { $wuaError = $_.Exception.Message }
  }
} catch {
  $wuaError = $_.Exception.Message
}
if (-not $wuaSufficient) {
  # WUA could not supply a usable install history: fall back to QFE.
  try {
    $qfe = @(
      Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop |
        Select-Object HotFixID, InstalledOn, Description
    )
    $hotfixEntries = @(
      foreach ($item in $qfe) {
        $when = $null
        $parsed = $null
        if ($item.InstalledOn) {
          try { $parsed = [datetime]$item.InstalledOn } catch { $parsed = $null }
          if ($parsed) { $when = $parsed.ToString('yyyy-MM-dd') } else { $when = [string]$item.InstalledOn }
        }
        [pscustomobject]@{
          id = [string]$item.HotFixID
          installed_on = $when
          description = [string]$item.Description
          applied_at = $parsed
        }
      }
    )
    $sorted = @($hotfixEntries | Sort-Object -Property applied_at -Descending)
    if ($sorted.Count -gt 0) {
      $top = $sorted[0]
      $latest = [pscustomobject]@{ id = $top.id; installed_on = $top.installed_on }
      $source = 'get_hotfix'
      if ($top.applied_at) {
        $days = [int][math]::Max(0, ([datetime]::Now.Date - $top.applied_at.Date).Days)
      }
      $history = @($sorted | Select-Object -First 25 | Select-Object id, installed_on, description)
    } else {
      $hotfixError = 'Win32_QuickFixEngineering returned no records'
    }
  } catch {
    $hotfixError = $_.Exception.Message
  }
}
$status = 'completed'
$errorText = $null
if ($source -eq $null) {
  $status = 'unavailable'
  $errorText = 'updates unavailable: ' + @($wuaError, $hotfixError | Where-Object { $_ }) -join '; '
}
$scaiResult = [pscustomobject]@{
  status = $status
  error = $errorText
  source = $source
  days_since_patch = $days
  latest_hotfix = $latest
  pending_update_count = $pendingCount
  history = $history
  diagnostics = [pscustomobject]@{ wua = $wuaError; hotfix = $hotfixError }
}
"""

_ACCOUNT_SECURITY = r"""
$admins = @()
$adminError = $null
try {
  $admins = @(
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
      Where-Object { [string]$_.ObjectClass -ne 'Group' } |
      Select-Object Name, ObjectClass, PrincipalSource
  )
} catch {
  $adminError = $_.Exception.Message
}
$enabledUserCount = $null
$userError = $null
try {
  $enabledUserCount = [int](@(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled }).Count)
} catch {
  $userError = $_.Exception.Message
}
$status = 'completed'
if ($adminError -and $userError) { $status = 'unavailable' }
$scaiResult = [pscustomobject]@{
  status = $status
  error = $(if ($status -eq 'completed') { $null } else { "administrators: $adminError; users: $userError" })
  admin_count = $(if ($adminError) { $null } else { $admins.Count })
  admins = $admins
  enabled_user_count = $enabledUserCount
  diagnostics = [pscustomobject]@{ administrators = $adminError; users = $userError }
}
"""

_SERVICES = r"""
$checked = @('RemoteRegistry','TlntSvr','SSDPSRV','upnphost')
$rows = @()
$errorText = $null
try {
  $rows = @(
    Get-CimInstance Win32_Service -ErrorAction Stop |
      Where-Object { $checked -contains $_.Name } |
      Select-Object Name, State, StartMode, DisplayName
  )
} catch {
  $errorText = $_.Exception.Message
}
$suspicious = @()
foreach ($row in $rows) {
  if ([string]$row.State -eq 'Running') {
    $suspicious += [pscustomobject]@{ name = [string]$row.Name; state = [string]$row.State }
  }
}
$runningCount = $null
if (-not $errorText) { $runningCount = [int]$suspicious.Count }
$status = 'completed'
if ($errorText) { $status = 'unavailable' }
$scaiResult = [pscustomobject]@{
  status = $status
  error = $errorText
  checked_services = $checked
  services = $rows
  suspicious = $suspicious
  running_count = $runningCount
}
"""

_ACCESS_CONTROL = r"""
$status = 'unavailable'
$errorText = $null
$protected = $null
try {
  $acl = Get-Acl 'C:\Windows\System32\config' -ErrorAction Stop
  $protected = [bool]$acl.AreAccessRulesProtected
  $status = 'completed'
} catch {
  $errorText = $_.Exception.Message
}
$scaiResult = [pscustomobject]@{
  status = $status
  error = $errorText
  system_config_acl_protected = $protected
  path = 'C:\Windows\System32\config'
}
"""

_REGISTRY = r"""
function Get-ScaiRegState([string]$Path, [string]$Name) {
  try {
    $key = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    return [pscustomobject]@{ exists = $true; value = $key.$Name }
  } catch {
    return [pscustomobject]@{ exists = $false; value = $null }
  }
}
$readings = [ordered]@{}
$readings['wdigest'] = Get-ScaiRegState 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$readings['llmnr'] = Get-ScaiRegState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$readings['autorun'] = Get-ScaiRegState 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$readings['lm_compatibility_level'] = Get-ScaiRegState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
$netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$readings['netlogon_require_sign_or_seal'] = Get-ScaiRegState $netlogon 'RequireSignOrSeal'
$readings['netlogon_seal_secure_channel'] = Get-ScaiRegState $netlogon 'SealSecureChannel'
$readings['netlogon_sign_secure_channel'] = Get-ScaiRegState $netlogon 'SignSecureChannel'
$readings['netlogon_refuse_password_change'] = Get-ScaiRegState $netlogon 'RefusePasswordChange'
$readings['smb_server_require_security_signature'] = Get-ScaiRegState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
$readings['powershell_script_block_logging'] = Get-ScaiRegState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$executionPolicy = $null
$executionPolicyError = $null
try { $executionPolicy = [string](Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop) } catch { $executionPolicyError = $_.Exception.Message }
$readings['powershell_execution_policy'] = [pscustomobject]@{
  exists = ($null -ne $executionPolicy)
  value = $executionPolicy
}
$scaiResult = [pscustomobject]@{
  status = 'completed'
  readings = $readings
  execution_policy_error = $executionPolicyError
}
"""

_NETWORK_SECURITY = r"""
$rdpStatus = 'unavailable'
$rdpError = $null
$rdpEnabled = $null
try {
  $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
  if ($null -ne $rdp.fDenyTSConnections) {
    $rdpEnabled = $false
    if ([int]$rdp.fDenyTSConnections -eq 0) { $rdpEnabled = $true }
    $rdpStatus = 'completed'
  } else {
    $rdpError = 'fDenyTSConnections not present'
  }
} catch {
  $rdpError = $_.Exception.Message
}
$smbStatus = 'unavailable'
$smbError = $null
$smb1Enabled = $null
$requireSignature = $null
try {
  $smb = Get-SmbServerConfiguration -ErrorAction Stop
  $smb1Enabled = [bool]$smb.EnableSMB1Protocol
  if ($null -ne $smb.RequireSecuritySignature) { $requireSignature = [bool]$smb.RequireSecuritySignature }
  $smbStatus = 'completed'
} catch {
  $smbError = $_.Exception.Message
}
$status = 'completed'
if ($rdpStatus -ne 'completed' -and $smbStatus -ne 'completed') { $status = 'unavailable' }
$scaiResult = [pscustomobject]@{
  status = $status
  rdp = [pscustomobject]@{ enabled = $rdpEnabled; status = $rdpStatus; error = $rdpError }
  smb1 = [pscustomobject]@{ enabled = $smb1Enabled; status = $smbStatus; error = $smbError }
  smb_server = [pscustomobject]@{
    require_security_signature = $requireSignature
    smb1_protocol_enabled = $smb1Enabled
    status = $smbStatus
    error = $smbError
  }
}
"""

_NETWORK_INVENTORY = r"""
$adapters = @()
$addresses = @()
$profiles = @()
$errors = @()
try {
  $adapters = @(
    Get-NetAdapter -ErrorAction Stop |
      Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, ifIndex
  )
} catch { $errors += "adapters: $($_.Exception.Message)" }
try {
  $addresses = @(
    Get-NetIPAddress -ErrorAction Stop |
      Where-Object { $_.AddressFamily -eq 'IPv4' } |
      Select-Object InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin, SuffixOrigin, AddressState
  )
} catch { $errors += "ipv4: $($_.Exception.Message)" }
try {
  $profiles = @(
    Get-NetConnectionProfile -ErrorAction Stop |
      Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
  )
} catch { $errors += "profiles: $($_.Exception.Message)" }
$counts = [pscustomobject]@{
  adapters = $adapters.Count
  ipv4 = $addresses.Count
  profiles = $profiles.Count
}
$scaiResult = [pscustomobject]@{
  status = 'completed'
  adapters = $adapters
  ipv4 = $addresses
  profiles = $profiles
  counts = $counts
  errors = $errors
}
"""

_INSTALLED_SOFTWARE = r"""
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$applications = @()
$errorText = $null
try {
  $rows = @(
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } |
      Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
      Sort-Object DisplayName
  )
  foreach ($row in $rows) {
    $applications += [pscustomobject]@{
      name = [string]$row.DisplayName
      version = [string]$row.DisplayVersion
      publisher = [string]$row.Publisher
      install_date = [string]$row.InstallDate
    }
  }
} catch {
  $errorText = $_.Exception.Message
}
$total = $applications.Count
$capped = @($applications | Select-Object -First 2000)
$scaiResult = [pscustomobject]@{
  status = 'completed'
  error = $errorText
  count = $total
  truncated = ($total -gt $capped.Count)
  applications = $capped
  source = 'Windows Registry Uninstall keys'
}
"""

#: One PowerShell program per collector, keyed by collector category.
SCRIPTS: dict[str, str] = {
    "device": _DEVICE,
    "firewall": _FIREWALL,
    "system_hardening": _SYSTEM_HARDENING,
    "tpm": _TPM,
    "authentication": _AUTHENTICATION,
    "updates": _UPDATES,
    "account_security": _ACCOUNT_SECURITY,
    "services": _SERVICES,
    "access_control": _ACCESS_CONTROL,
    "registry": _REGISTRY,
    "network_security": _NETWORK_SECURITY,
    "network_inventory": _NETWORK_INVENTORY,
    "installed_software": _INSTALLED_SOFTWARE,
}


def script_for(category: str) -> str:
    """Return the PowerShell program for a collector category."""
    try:
        return SCRIPTS[category]
    except KeyError as exc:  # pragma: no cover - programmer error
        raise KeyError(f"no PowerShell program registered for {category!r}") from exc
