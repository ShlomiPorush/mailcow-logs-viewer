# mailcow-logs for agents on Windows: runs the Node version when Node 20+ is installed, and otherwise does the same
# itself with Windows PowerShell 5.1 (built into Windows 10 and 11) or PowerShell 7.
#
# One of three versions with one contract (see mailcow-logs.mjs): same commands, same JSON output and error codes,
# same files and the same lock, so they can run side by side. Tokens never appear in the output.
#
# Run it as: powershell -NoProfile -ExecutionPolicy Bypass -File mailcow-logs.ps1 <command> ...
# (the policy is bypassed for this one process only; nothing on the computer changes).

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

if (-not $env:MAILCOW_LOGS_NO_NODE) {
  $node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($node) {
    & $node.Source -e "process.exit(Number(process.versions.node.split('.')[0])>=20?0:1)" 2>$null
    if ($LASTEXITCODE -eq 0) {
      & $node.Source (Join-Path $PSScriptRoot 'mailcow-logs.mjs') @args
      exit $LASTEXITCODE
    }
  }
}

# Filled in with the mailcow Logs Viewer address when the file is downloaded from it.
$DefaultUrl = '__MAILCOW_LOGS_URL__'
# Filled in with the skill's version when downloaded: the app says when a newer one is out (access)
$SkillVersion = '__MAILCOW_LOGS_SKILL_VERSION__'
$ClientId = 'mailcow-logs-cli'
$Scope = 'status:read status:write messages:read outbound:read outbound:write quarantine:read quarantine:write ' +
  'security:read security:write rspamd:read rspamd:write dmarc:read dmarc:write domains:read domains:write ' +
  'mailboxes:read mailboxes:write logs:read settings:read'
$WaitSeconds = 90
if ($env:MAILCOW_LOGS_WAIT_SECONDS) { $WaitSeconds = [int]$env:MAILCOW_LOGS_WAIT_SECONDS }
# A pending code is dropped locally only this long after its expiry: until then the server decides
$StaleCodeSeconds = 600
# A refresh is retried only once it cannot be in flight any more: twice the request timeout (tests shorten it).
$RefreshGrace = 30
if ($null -ne $env:MAILCOW_LOGS_TEST_REFRESH_GRACE) { $RefreshGrace = [long]$env:MAILCOW_LOGS_TEST_REFRESH_GRACE }
$PollSeconds = 5
if ($env:MAILCOW_LOGS_TEST_POLL_SECONDS) { $PollSeconds = [long]$env:MAILCOW_LOGS_TEST_POLL_SECONDS }
$LockWaitMs = 20000
if ($env:MAILCOW_LOGS_LOCK_WAIT_MS) { $LockWaitMs = [int]$env:MAILCOW_LOGS_LOCK_WAIT_MS }
# The server answers an API call within 60 s (or says the outcome is unknown).
$ApiTimeoutMs = 75000
if ($env:MAILCOW_LOGS_TEST_API_TIMEOUT_MS) { $ApiTimeoutMs = [int]$env:MAILCOW_LOGS_TEST_API_TIMEOUT_MS }
# Wait before the one retry of a call the server refused as busy (tests shorten it).
$BusyWaitMs = 2000
if ($null -ne $env:MAILCOW_LOGS_TEST_BUSY_WAIT_MS) { $BusyWaitMs = [int]$env:MAILCOW_LOGS_TEST_BUSY_WAIT_MS }
$KindsMaxAge = 3600
$Secret = '^[A-Za-z0-9._~+/=-]{1,4096}$'
$Plain = '^[^"\\\x00-\x1f\x7f]*$'
$PathChars = "^[A-Za-z0-9._~!$&'()*+,;=:@/?%-]+$"
$Template = '^/api/[A-Za-z0-9._~{}:/-]*$'
$UnknownOutcome = 'The action may have run. Read its state before trying again.'
$Fields = @(
  @('v', 'n'), @('issuer', 's'), @('label', 's'), @('generation', 's'), @('refreshToken', 's'), @('accessToken', 's'),
  @('accessExpiresAt', 'n'), @('scope', 's'), @('refreshStartedAt', 'n'), @('refreshRetried', 'n'), @('deviceCode', 's'),
  @('userCode', 's'), @('link', 's'), @('deviceExpiresAt', 'n'), @('interval', 'n'), @('nextPollAt', 'n'), @('toRevoke', 's')
)
$Utf8 = New-Object System.Text.UTF8Encoding($false)
# Windows tools by their full path: started from Git Bash, for one, whoami.exe may be a different program.
$Icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
$Whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'

class OpsFail : System.Exception {
  [string]$Code
  [object]$Body
  [bool]$Sent
  [int]$Status
  OpsFail([string]$code, [string]$message) : base($message) { $this.Code = $code; $this.Sent = $true; $this.Status = 0 }
}

function Fail([string]$code, [string]$message) { throw [OpsFail]::new($code, $message) }
function Now { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function Hex([int]$n) {
  $b = New-Object byte[] $n
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  -join ($b | ForEach-Object { $_.ToString('x2') })
}
function HostName { if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName } }
function Write-Raw([byte[]]$bytes) {
  $out = [Console]::OpenStandardOutput()
  $out.Write($bytes, 0, $bytes.Length)
  $out.Flush()
}
function Write-Line([string]$text) { Write-Raw $Utf8.GetBytes("$text`n") }
function Write-Json($value) { Write-Line (ConvertTo-Json -InputObject $value -Compress -Depth 20) }
function ConvertTo-JsonString([string]$text) { ConvertTo-Json -InputObject $text -Compress }

$Help = @"
mailcow-logs: use mailcow Logs Viewer after a person approves it.

  connect [--replace]   Ask to connect; prints a link and a code to show the person.
  connect --wait        Wait up to $WaitSeconds s for the approval; run again while it answers still_waiting.
  access                What this connection may view or act on, and until when.
  endpoints [area]      The API calls this connection may make, with their kind (read or act).
  get <path>            GET /api/<path>, for example: get 'messages?limit=20'
  post|put|patch|delete <path> [--json <body> | --json-file <file>]
  status                Whether this agent is connected (no secrets).
  disconnect            End this agent's connection.

  --url <address>       The mailcow Logs Viewer address (or MAILCOW_LOGS_URL).
"@

# Context: the app's address, this agent's identity (the folder it is installed in) and where its connection is kept.

function Get-Context([string]$urlOption) {
  $raw = $urlOption
  if (-not $raw) { $raw = $env:MAILCOW_LOGS_URL }
  if (-not $raw -and -not $DefaultUrl.StartsWith('__')) { $raw = $DefaultUrl }
  if (-not $raw) { Fail 'no_url' 'No mailcow Logs Viewer address. Pass --url https://<its address> or set MAILCOW_LOGS_URL.' }
  $u = $null
  if (-not [Uri]::TryCreate($raw, [UriKind]::Absolute, [ref]$u)) { Fail 'insecure_url' "`"$raw`" is not an address." }
  $loopback = @('127.0.0.1', '[::1]', 'localhost') -contains $u.Host
  if (-not ($u.Scheme -eq 'https' -or ($u.Scheme -eq 'http' -and $loopback))) {
    Fail 'insecure_url' 'The address must start with https:// (http only for this computer).'
  }
  if ($u.UserInfo -or $u.Query -or $u.Fragment -or ($u.AbsolutePath -ne '/')) {
    Fail 'insecure_url' 'Use the address alone, for example https://logs.example.com.'
  }
  $issuer = "$($u.Scheme)://$($u.Authority)"
  $install = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\', '/').ToLowerInvariant()
  $dir = Get-CredentialsDir
  $sha = [Security.Cryptography.SHA256]::Create().ComputeHash($Utf8.GetBytes("$issuer`n$(Get-InstallId $install)"))
  $key = (-join ($sha | ForEach-Object { $_.ToString('x2') })).Substring(0, 32)
  @{
    issuer = $issuer; install = $install; dir = $dir
    file = Join-Path $dir "$key.json"; lock = Join-Path $dir "$key.lock"; kinds = Join-Path $dir "$key.kinds"
    label = Get-Label $install
  }
}

# This install's id, kept in the skill's folder (.install-id), so every version agrees on it however each one spells
# the folder's path. Published in one step: written aside, then moved into place, which fails if one is there.
function Get-InstallId([string]$install) {
  $file = Join-Path $install '.install-id'
  $read = {
    try { $id = ([IO.File]::ReadAllText($file)).Trim(); if ($id -match '^[0-9a-f]{32}$') { return $id } } catch {}
    return $null
  }
  $id = & $read
  if ($id) { return $id }
  $tmp = "$file.$(Hex 6)"
  try { [IO.File]::WriteAllText($tmp, "$(Hex 16)`n"); [IO.File]::Move($tmp, $file) } catch {} finally {
    try { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } } catch {}
  }
  $id = & $read
  if ($id) { return $id }
  Fail 'cannot_save' "Cannot write in $install. The agent's id is kept there; allow writing it."
}

# icacls over the folder and its files; tried again while other commands add or replace files in it.
function Invoke-Icacls([string[]]$arguments) {
  for ($i = 0; ; $i++) {
    $ErrorActionPreference = 'Continue'
    & $Icacls @arguments *> $null
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -eq 0) { return }
    if ($i -ge 4) { throw "icacls $($arguments[1]) failed" }
    Start-Sleep -Milliseconds (100 + (Get-Random -Maximum 200))
  }
}

# What in saved ACLs (icacls /save: one SDDL line per object) lets anyone but this user, SYSTEM and Administrators
# in. Anything but plain allow and deny entries (conditional or callback ones) counts too: refused, not guessed.
function Find-OtherAllowed([string]$saved, [string]$userSid) {
  $allowed = @($userSid, 'SY', 'BA', 'S-1-5-18', 'S-1-5-32-544')
  # SDDL writes the built-in Administrator account (RID 500) as LA, so a user who is that account shows as LA.
  if ($userSid -match '^S-1-5-21-[0-9-]+-500$') { $allowed += 'LA' }
  foreach ($line in ($saved -split "`r?`n")) {
    $at = $line.IndexOf('D:')
    if ($at -lt 0) { continue }
    $dacl = ($line.Substring($at + 2) -split 'S:')[0]
    $depth = 0; $ace = ''
    foreach ($ch in $dacl.ToCharArray()) {
      if ($ch -eq '(') {
        $depth++
        if ($depth -gt 1) { return 'a conditional entry' }
        $ace = ''
      } elseif ($ch -eq ')') {
        $depth--
        $f = $ace -split ';'
        if (@('A', 'D', 'OA', 'OD') -cnotcontains $f[0]) { return "an entry of type $($f[0])" }
        if (($f[0] -ceq 'A' -or $f[0] -ceq 'OA') -and ($f.Count -lt 6 -or $allowed -notcontains $f[5])) { return $f[-1] }
      } elseif ($depth -eq 1) { $ace += $ch }
    }
  }
  $null
}

function Get-Label([string]$install) {
  if ($env:MAILCOW_LOGS_AGENT_NAME) { $l = $env:MAILCOW_LOGS_AGENT_NAME; if ($l.Length -gt 60) { $l = $l.Substring(0, 60) }; return $l }
  $agent = 'Agent'
  foreach ($part in ($install -split '[\\/]')) {
    $p = $part.ToLowerInvariant()
    if ($p.StartsWith('.claude')) { if ($p -eq '.claude') { $agent = 'Claude Code' } else { $agent = "Claude Code ($p)" }; break }
    if ($p.StartsWith('.codex')) { if ($p -eq '.codex') { $agent = 'Codex' } else { $agent = "Codex ($p)" }; break }
    if ($p.StartsWith('.cursor')) { $agent = 'Cursor'; break }
  }
  $l = "$agent on $(HostName)"
  if ($l.Length -gt 60) { $l = $l.Substring(0, 60) }
  $l
}

function Get-CredentialsDir {
  if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Fail 'failed' 'On Linux and macOS, run mailcow-logs (or mailcow-logs.sh).' }
  $appData = $env:APPDATA
  if (-not $appData) { $appData = Join-Path $env:USERPROFILE 'AppData\Roaming' }
  $dir = $env:MAILCOW_LOGS_CREDENTIALS
  if (-not $dir) { $dir = Join-Path $appData 'mailcow-logs' }
  $dir = [IO.Path]::GetFullPath($dir).TrimEnd('\')
  $userHome = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\').ToLowerInvariant()
  $lower = $dir.ToLowerInvariant()
  if ($lower -ne $userHome -and -not $lower.StartsWith("$userHome\")) {
    Fail 'insecure_credentials' "Keep the mailcow-logs folder inside your user profile ($userHome), not $dir."
  }
  $dir
}

$script:Secured = $false
function Protect-Dir([string]$dir) {
  if ($script:Secured) { return }
  try { [void][IO.Directory]::CreateDirectory($dir) } catch { Fail 'cannot_save' "Cannot create $dir. Allow this agent to write there." }
  $item = Get-Item -LiteralPath $dir -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.PSIsContainer) {
    Fail 'insecure_credentials' "$dir must be a plain folder, not a link."
  }
  # Limited to this user, SYSTEM and Administrators (well-known SIDs, so no localized names).
  try {
    $who = (& $Whoami /user /fo csv /nh) -join ''
    if ($who -notmatch '"(S-1-[0-9-]+)"\s*$') { throw 'no SID' }
    $sid = $Matches[1]
    & $Icacls $dir /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q *> $null
    if ($LASTEXITCODE -ne 0) { throw 'icacls' }
    # The owner may always change an ACL, so the folder and its files must be this user's. (Only now: taking
    # ownership needs the full control just granted. No /C, which would hide a failure behind exit code 0.)
    Invoke-Icacls @($dir, '/setowner', "*$sid", '/T', '/Q')
    # Granting does not remove other entries: read the folder's and its files' ACLs back and allow no one else.
    # (icacls, not Get-Acl: started from PowerShell 7, Windows PowerShell may fail to load the module Get-Acl is in.)
    $saved = Join-Path $dir ".acl-$(Hex 4)"
    try {
      Invoke-Icacls @($dir, '/save', $saved, '/T', '/Q')
      $other = Find-OtherAllowed ([IO.File]::ReadAllText($saved, [Text.Encoding]::Unicode)) $sid
      if ($other) { Fail 'insecure_credentials' "Others can open $dir ($other). Remove their access." }
    } finally { if ([IO.File]::Exists($saved)) { [IO.File]::Delete($saved) } }
  } catch [OpsFail] { throw } catch {
    Fail 'insecure_credentials' "Could not limit $dir to your user ($($_.Exception.Message))."
  }
  $script:Secured = $true
}

function Test-PlainFile([string]$file) {
  $item = Get-Item -LiteralPath $file -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.PSIsContainer) {
    Fail 'insecure_credentials' "$file must be a plain file."
  }
}

# The connection's file: flat JSON with plain values, written in one step.

function New-Record($ctx) {
  $rec = @{}
  foreach ($f in $Fields) { if ($f[1] -eq 'n') { $rec[$f[0]] = [long]0 } else { $rec[$f[0]] = '' } }
  $rec.v = [long]1; $rec.issuer = $ctx.issuer; $rec.label = $ctx.label
  $rec
}

function Read-Record($ctx) {
  if (-not [IO.File]::Exists($ctx.file)) { return $null }
  Test-PlainFile $ctx.file
  try { $parsed = [IO.File]::ReadAllText($ctx.file, $Utf8) | ConvertFrom-Json } catch {
    Fail 'insecure_credentials' "$($ctx.file) is damaged. Delete it and connect again."
  }
  $rec = @{}
  foreach ($f in $Fields) {
    $value = $null
    if ($parsed.PSObject.Properties[$f[0]]) { $value = $parsed.($f[0]) }
    if ($f[1] -eq 'n') { $n = [long]0; if ($null -ne $value) { [void][long]::TryParse([string]$value, [ref]$n) }; $rec[$f[0]] = $n }
    elseif ($null -eq $value) { $rec[$f[0]] = '' } else { $rec[$f[0]] = [string]$value }
  }
  $rec
}

function Format-Record($rec) {
  $parts = foreach ($f in $Fields) {
    if ($f[1] -eq 'n') { $n = [long]0; [void][long]::TryParse([string]$rec[$f[0]], [ref]$n); if ($n -lt 0) { $n = 0 }; "`"$($f[0])`":$n" }
    else {
      $value = [string]$rec[$f[0]]
      if ($value -notmatch $Plain) { Fail 'unexpected_answer' "mailcow Logs Viewer sent a value that cannot be stored ($($f[0]))." }
      "`"$($f[0])`":`"$value`""
    }
  }
  '{' + ($parts -join ',') + "}`n"
}

# Writes a file of the connection in one step: a new private file, flushed, moved over the old one.
function Write-Private($ctx, [string]$file, [string]$text) {
  Protect-Dir $ctx.dir
  $tmp = "$file.$(Hex 6).tmp"
  try {
    $fs = [IO.File]::Open($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = $Utf8.GetBytes($text); $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
  } catch { Fail 'cannot_save' "Cannot write in $($ctx.dir). Allow this agent to write there." }
  Move-Over $tmp $file
}

function Write-Record($ctx, $rec) { Write-Private $ctx $ctx.file (Format-Record $rec) }

function Move-Over([string]$from, [string]$to) {
  # An open handle (an antivirus scan) can refuse the replace for a moment.
  $until = [DateTime]::UtcNow.AddSeconds(5)
  while ($true) {
    try {
      if ([IO.File]::Exists($to)) { [IO.File]::Replace($from, $to, [NullString]::Value) } else { [IO.File]::Move($from, $to) }
      return
    } catch {
      if ([DateTime]::UtcNow -gt $until) {
        try { [IO.File]::Delete($from) } catch {}
        Fail 'cannot_save' "Cannot replace $to."
      }
      Start-Sleep -Milliseconds 100
    }
  }
}

function Remove-Kinds($ctx) { if ([IO.File]::Exists($ctx.kinds)) { [IO.File]::Delete($ctx.kinds) } }
function Remove-Record($ctx) { if ([IO.File]::Exists($ctx.file)) { [IO.File]::Delete($ctx.file) }; Remove-Kinds $ctx }

# The lock: a file created exclusively, naming its holder. Never taken from a live holder, however old.

function Read-Lock([string]$file) {
  if (-not [IO.File]::Exists($file)) { return $null }
  try {
    $text = [IO.File]::ReadAllText($file, $Utf8)
    $held = $text | ConvertFrom-Json
    if ($held -and $held.PSObject.Properties['token']) { return $held }
  } catch {}
  try { return [pscustomobject]@{ empty = $true; mtime = [IO.File]::GetLastWriteTimeUtc($file) } } catch { return $null }
}

function Test-Alive([int]$id) { [bool](Get-Process -Id $id -ErrorAction SilentlyContinue) }

function Invoke-Hook([string]$point) {
  $at = [Environment]::GetEnvironmentVariable('MAILCOW_LOGS_TEST_HOLD_' + $point.ToUpperInvariant().Replace('-', '_'))
  if (-not $at) { return }
  [IO.File]::WriteAllText("$at.reached", [string]$PID)
  for ($i = 0; $i -lt 1200 -and -not [IO.File]::Exists("$at.go"); $i++) { Start-Sleep -Milliseconds 50 }
}

function Test-LockEmpty($held) { $held.PSObject.Properties['empty'] -and $held.empty }

# Takes the lock; $own is a lock this process held before, which counts as taken if it is back in place.
function Enter-Lock($ctx, [string]$own) {
  Protect-Dir $ctx.dir
  $token = Hex 16
  $line = ConvertTo-Json -Compress -InputObject ([ordered]@{ pid = $PID; host = (HostName); token = $token; startedAt = (Now) })
  $deadline = [DateTime]::UtcNow.AddMilliseconds($LockWaitMs)
  while ($true) {
    $created = $false
    try {
      $fs = [IO.File]::Open($ctx.lock, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
      try { $bytes = $Utf8.GetBytes($line); $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
      $created = $true
    } catch [IO.IOException] {
      if (-not [IO.File]::Exists($ctx.lock) -and -not [IO.Directory]::Exists($ctx.dir)) { Fail 'cannot_save' "Cannot create a lock in $($ctx.dir)." }
    } catch [UnauthorizedAccessException] {
      # Windows refuses for a moment to create a file whose name is still being deleted (a lock just released).
      if ([DateTime]::UtcNow -gt $deadline) { Fail 'cannot_save' "Cannot create a lock in $($ctx.dir)." }
      Start-Sleep -Milliseconds (50 + (Get-Random -Maximum 100))
      continue
    } catch { Fail 'cannot_save' "Cannot create a lock in $($ctx.dir)." }
    if ($created) { Invoke-Hook 'locked'; return $token }
    $held = Read-Lock $ctx.lock
    # Another process moved this one's lock away by mistake and has put it back.
    if ($own -and $held -and -not (Test-LockEmpty $held) -and $held.token -eq $own) { return $own }
    $dead = $false
    if ($held) {
      # A holder that died between creating the lock and writing its name leaves it empty; that takes a moment.
      if (Test-LockEmpty $held) { $dead = ([DateTime]::UtcNow - $held.mtime).TotalSeconds -gt 60 }
      else { $dead = ([string]$held.host).ToLowerInvariant() -eq (HostName).ToLowerInvariant() -and -not (Test-Alive ([int]$held.pid)) }
    }
    if ($dead) {
      Invoke-Hook 'break-observed'
      if (Remove-DeadLock $ctx $held) { continue }
    }
    if ([DateTime]::UtcNow -gt $deadline) {
      if ($held -and -not (Test-LockEmpty $held) -and ((Now) - [long]$held.startedAt) -gt 600) {
        Fail 'busy' "Another mailcow-logs command has held $($ctx.lock) for over 10 minutes. If none is running, delete that file."
      }
      Fail 'busy' 'Another mailcow-logs command is using this connection. Nothing was sent; run it again.'
    }
    Start-Sleep -Milliseconds (100 + (Get-Random -Maximum 200))
  }
}

# Moving the dead lock away is atomic, so of two that try only one moves it; if what was moved is not the dead lock
# (another process had just taken a fresh one), it goes back unless a newer one is there (Move never overwrites).
function Remove-DeadLock($ctx, $held) {
  $moved = "$($ctx.lock).$(Hex 6).dead"
  try { [IO.File]::Move($ctx.lock, $moved) } catch { return $true }
  Invoke-Hook 'break-moved'
  $got = Read-Lock $moved
  $same = $false
  if ($got) {
    if (Test-LockEmpty $held) { $same = [bool](Test-LockEmpty $got) }
    elseif (-not (Test-LockEmpty $got)) { $same = $got.token -eq $held.token }
  }
  if ($same) { [IO.File]::Delete($moved); return $true }
  try { [IO.File]::Move($moved, $ctx.lock) } catch { try { [IO.File]::Delete($moved) } catch {} }
  $false
}

function Test-Mine($ctx, [string]$token) {
  $held = Read-Lock $ctx.lock
  [bool]($held -and -not (Test-LockEmpty $held) -and $held.token -eq $token)
}

function Exit-Lock($ctx, [string]$token) { if (Test-Mine $ctx $token) { [IO.File]::Delete($ctx.lock) } }

function Assert-Mine($ctx, [string]$token) {
  if (-not (Test-Mine $ctx $token)) { Fail 'busy' 'Another mailcow-logs command took over this connection. Run it again.' }
}

# Requests

# Plain HTTP/1.1 over one new connection per request, never HttpClient: .NET's HttpClient sends a request again by
# itself when its connection breaks before the answer (tried: PowerShell 7 sent a dropped request four times), and
# neither an action nor a one-time refresh token may ever be sent twice. No redirects are followed.

function Find-Bytes([byte[]]$hay, [byte[]]$needle, [int]$from) {
  for ($i = $from; $i -le $hay.Length - $needle.Length; $i++) {
    $ok = $true
    for ($j = 0; $j -lt $needle.Length; $j++) { if ($hay[$i + $j] -ne $needle[$j]) { $ok = $false; break } }
    if ($ok) { return $i }
  }
  -1
}

# The body of a chunked answer, or $null when it is cut short.
function Get-Unchunked([byte[]]$raw) {
  $out = New-Object System.IO.MemoryStream
  $crlf = [byte[]](13, 10)
  $at = 0
  while ($true) {
    $end = Find-Bytes $raw $crlf $at
    if ($end -lt 0) { return $null }
    $sizeText = ([Text.Encoding]::ASCII.GetString($raw, $at, $end - $at) -split ';')[0].Trim()
    $size = 0
    if (-not [int]::TryParse($sizeText, [Globalization.NumberStyles]::HexNumber, $null, [ref]$size)) { return $null }
    if ($size -eq 0) { return , $out.ToArray() }
    $start = $end + 2
    if ($start + $size + 2 -gt $raw.Length) { return $null }
    $out.Write($raw, $start, $size)
    $at = $start + $size + 2
  }
}

function Invoke-Ops($ctx, [string]$method, [string]$url, $form, [string]$bearer, $json, [bool]$api = $false) {
  $timeoutMs = 15000
  if ($api) { $timeoutMs = $ApiTimeoutMs }
  $u = [Uri]$url
  $bodyBytes = $null; $contentType = ''
  if ($form) {
    $pairs = foreach ($k in $form.Keys) { [Uri]::EscapeDataString([string]$k) + '=' + [Uri]::EscapeDataString([string]$form[$k]) }
    $bodyBytes = $Utf8.GetBytes(($pairs -join '&')); $contentType = 'application/x-www-form-urlencoded'
  } elseif ($null -ne $json) {
    $bodyBytes = $Utf8.GetBytes([string]$json); $contentType = 'application/json'
  }
  $head = "$method $($u.PathAndQuery) HTTP/1.1`r`nHost: $($u.Authority)`r`nAccept: application/json`r`nConnection: close`r`nUser-Agent: mailcow-logs`r`n"
  if ($bearer) { $head += "Authorization: Bearer $bearer`r`nX-Mailcow-Logs-Skill: $SkillVersion`r`n" }
  if ($null -ne $bodyBytes) { $head += "Content-Type: $contentType`r`nContent-Length: $($bodyBytes.Length)`r`n" }
  elseif (@('POST', 'PUT', 'PATCH') -contains $method) { $head += "Content-Length: 0`r`n" }
  $head += "`r`n"
  $tcp = New-Object System.Net.Sockets.TcpClient
  $stream = $null; $sent = $false
  $clock = [Diagnostics.Stopwatch]::StartNew()
  try {
    try {
      $connect = $tcp.ConnectAsync($u.DnsSafeHost, $u.Port)
      if (-not $connect.Wait(10000)) { throw 'the connection timed out' }
      $stream = $tcp.GetStream()
      if ($u.Scheme -eq 'https') {
        $ssl = New-Object System.Net.Security.SslStream($stream, $false)
        # The system's TLS versions; the certificate is checked as usual. The handshake gets
        # what is left of the request's time: a server that stops in it cannot hold the lock.
        $left = $timeoutMs - [int]$clock.ElapsedMilliseconds
        if ($left -le 0) { throw 'the connection timed out' }
        $tcp.ReceiveTimeout = $left; $tcp.SendTimeout = $left
        $handshake = $ssl.AuthenticateAsClientAsync($u.DnsSafeHost, $null, [Security.Authentication.SslProtocols]::None, $true)
        if (-not $handshake.Wait($left)) { $tcp.Close(); throw 'the TLS handshake timed out' }
        $stream = $ssl
      }
    } catch {
      # The name, the connection or TLS failed first: nothing reached the app.
      $f = [OpsFail]::new('unreachable', "Cannot reach $($ctx.issuer) ($($_.Exception.GetBaseException().Message)).")
      $f.Sent = $false
      throw $f
    }
    $raw = New-Object System.IO.MemoryStream
    try {
      $sent = $true
      $stream.WriteTimeout = $timeoutMs
      $headBytes = [Text.Encoding]::ASCII.GetBytes($head)
      $stream.Write($headBytes, 0, $headBytes.Length)
      if ($null -ne $bodyBytes) { $stream.Write($bodyBytes, 0, $bodyBytes.Length) }
      $stream.Flush()
      $buf = New-Object byte[] 65536
      while ($true) {
        $left = $timeoutMs - [int]$clock.ElapsedMilliseconds
        if ($left -le 0) { throw 'no answer in time' }
        $stream.ReadTimeout = $left
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { break }
        $raw.Write($buf, 0, $n)
      }
    } catch {
      $f = [OpsFail]::new('unreachable', "Cannot reach $($ctx.issuer) ($($_.Exception.GetBaseException().Message)).")
      $f.Sent = $true
      throw $f
    }
  } finally {
    if ($stream) { try { $stream.Dispose() } catch {} }
    try { $tcp.Close() } catch {}
  }
  $all = $raw.ToArray()
  $split = Find-Bytes $all ([byte[]](13, 10, 13, 10)) 0
  $status = 0
  if ($split -gt 0) {
    $lines = [Text.Encoding]::ASCII.GetString($all, 0, $split) -split "`r`n"
    if ($lines[0] -match '^HTTP/1\.[01] (\d{3})') { $status = [int]$Matches[1] }
  }
  # The answer started and broke off (or never came): the app got the request and may have acted on it.
  if ($status -eq 0) { throw [OpsFail]::new('unreachable', "The answer from $($ctx.issuer) broke off.") }
  $headers = @{}
  foreach ($line in ($lines | Select-Object -Skip 1)) {
    $at = $line.IndexOf(':')
    if ($at -gt 0) { $headers[$line.Substring(0, $at).Trim().ToLowerInvariant()] = $line.Substring($at + 1).Trim() }
  }
  $rest = New-Object byte[] ($all.Length - $split - 4)
  [Array]::Copy($all, $split + 4, $rest, 0, $rest.Length)
  $bytes = $rest
  if ($headers.ContainsKey('transfer-encoding') -and $headers['transfer-encoding'] -match 'chunked') {
    $bytes = Get-Unchunked $rest
  } elseif ($headers.ContainsKey('content-length')) {
    $length = 0
    if (-not [int]::TryParse($headers['content-length'], [ref]$length) -or $rest.Length -lt $length) { $bytes = $null }
    else { $bytes = New-Object byte[] $length; [Array]::Copy($rest, 0, $bytes, 0, $length) }
  }
  if ($null -eq $bytes) { throw [OpsFail]::new('unreachable', "The answer from $($ctx.issuer) broke off.") }
  $text = $Utf8.GetString($bytes)
  $parsed = $null
  $isJson = $false
  # Only text that looks like JSON is parsed: PowerShell 7 would also accept some text that is not.
  if ($text -match '^\s*([\{\["\-0-9]|true\s*$|false\s*$|null\s*$)') {
    try { $parsed = $text | ConvertFrom-Json; $isJson = $true } catch {}
  }
  @{ status = $status; text = $text; bytes = $bytes; json = $parsed; isJson = $isJson }
}

function Invoke-OAuth($ctx, [string]$path, $form) {
  $form['client_id'] = $ClientId
  Invoke-Ops $ctx 'POST' "$($ctx.issuer)$path" $form '' $null
}

function Test-Object($value) { $null -ne $value -and $value -is [pscustomobject] }

function Get-Field($r, [string]$name) {
  if ((Test-Object $r.json) -and $r.json.PSObject.Properties[$name]) { return [string]$r.json.$name }
  ''
}

function New-HttpFail($r, [string]$what) {
  $detail = Get-Field $r 'error_description'
  if (-not $detail) { $detail = Get-Field $r 'message' }
  if (-not $detail -and (Test-Object $r.json) -and $r.json.PSObject.Properties['detail'] -and $r.json.detail -is [string]) { $detail = $r.json.detail }
  if (-not $detail) { $detail = Get-Field $r 'error' }
  $msg = "$what failed ($($r.status)"
  if ($detail) { $msg += ": $detail" }
  $f = [OpsFail]::new("http_$($r.status)", "$msg).")
  if ((Test-Object $r.json) -or $r.json -is [array]) { $f.Body = $r.json }
  $f
}

function Get-Tokens($r) {
  $access = Get-Field $r 'access_token'; $refresh = Get-Field $r 'refresh_token'; $scope = Get-Field $r 'scope'
  if ($access -notmatch $Secret -or $refresh -notmatch $Secret -or $scope -notmatch $Plain) {
    Fail 'unexpected_answer' 'mailcow Logs Viewer answered without usable tokens.'
  }
  $expires = [long]0; [void][long]::TryParse((Get-Field $r 'expires_in'), [ref]$expires)
  @{ refreshToken = $refresh; accessToken = $access; accessExpiresAt = (Now) + [Math]::Max([long]0, $expires); scope = $scope }
}

function Merge($rec, $values) { $next = $rec.Clone(); foreach ($k in $values.Keys) { $next[$k] = $values[$k] }; $next }

function Invoke-RevokePending($ctx, $rec) {
  if (-not $rec.toRevoke) { return $rec }
  $left = @()
  foreach ($token in ($rec.toRevoke -split ' ' | Where-Object { $_ })) {
    $ok = $false
    try { $r = Invoke-OAuth $ctx '/oauth/revoke' ([ordered]@{ token = $token; token_type_hint = 'refresh_token' }); $ok = $r.status -eq 200 } catch {}
    if (-not $ok) { $left += $token }
  }
  $next = Merge $rec @{ toRevoke = ($left -join ' ') }
  if ($next.toRevoke -ne $rec.toRevoke) { Write-Record $ctx $next }
  $next
}

# Commands

function Show-Status($ctx) {
  $rec = Read-Record $ctx
  $state = 'not_connected'
  if ($rec -and $rec.refreshToken) { $state = 'connected' } elseif ($rec -and $rec.deviceCode) { $state = 'pending' }
  $label = $ctx.label
  if ($rec -and $rec.label) { $label = $rec.label }
  $out = [ordered]@{ status = $state; url = $ctx.issuer; label = $label }
  if ($state -eq 'connected') { $out.scope = $rec.scope; $out.accessExpiresIn = [Math]::Max([long]0, $rec.accessExpiresAt - (Now)) }
  Write-Json $out
}

function Get-Pending($rec) {
  [ordered]@{
    status = 'pending'; link = $rec.link; code = $rec.userCode; expiresIn = [Math]::Max([long]0, $rec.deviceExpiresAt - (Now))
    next = 'End your turn with a reply that shows the person the link and the code and asks them to reply once they approve. When they reply, run: mailcow-logs connect --wait'
  }
}

function Clear-Pending($rec) { Merge $rec @{ deviceCode = ''; userCode = ''; link = ''; deviceExpiresAt = [long]0; interval = [long]0; nextPollAt = [long]0 } }

function Invoke-Connect($ctx, [bool]$replace) {
  # Before any code exists: can it keep a connection here, and is the app there?
  Protect-Dir $ctx.dir
  $probe = Join-Path $ctx.dir ".probe-$(Hex 4)"
  try { [IO.File]::Open($probe, [IO.FileMode]::CreateNew).Dispose(); [IO.File]::Delete($probe) } catch {
    Fail 'cannot_save' "Cannot write in $($ctx.dir). Allow this agent to write there."
  }
  $meta = Invoke-Ops $ctx 'GET' "$($ctx.issuer)/.well-known/oauth-authorization-server" $null '' $null
  if ($meta.status -ne 200 -or (Get-Field $meta 'issuer') -ne $ctx.issuer) {
    Fail 'unreachable' "$($ctx.issuer) does not answer as mailcow Logs Viewer with agent access on ($($meta.status)). Check the address, and that agent access is on in Settings > Agents."
  }
  $lock = Enter-Lock $ctx
  try {
    $rec = Read-Record $ctx
    if (-not $rec) { $rec = New-Record $ctx }
    $rec = Invoke-RevokePending $ctx $rec
    if ($rec.refreshToken -and -not $replace) { return Write-Json ([ordered]@{ status = 'already_connected'; label = $rec.label; scope = $rec.scope }) }
    # The open code again, unless asked for a new one (--replace: the link did not work for the person).
    if ($rec.deviceCode -and ($rec.deviceExpiresAt - (Now)) -gt 30 -and -not $replace) { return Write-Json (Get-Pending $rec) }
    Assert-Mine $ctx $lock
    $r = Invoke-OAuth $ctx '/oauth/device' ([ordered]@{ scope = $Scope; resource = "$($ctx.issuer)/api"; client_label = $ctx.label })
    if ($r.status -ne 200) { throw (New-HttpFail $r 'Asking to connect') }
    $deviceCode = Get-Field $r 'device_code'; $userCode = Get-Field $r 'user_code'; $link = Get-Field $r 'verification_uri_complete'
    if ($deviceCode -notmatch $Secret -or $userCode -cnotmatch '^[A-Z0-9-]{4,20}$' -or $link -notmatch $Plain) {
      Fail 'unexpected_answer' 'mailcow Logs Viewer answered without a code.'
    }
    if (-not $link.StartsWith("$($ctx.issuer)/")) { Fail 'unexpected_answer' 'The approval link is not on mailcow Logs Viewer.' }
    $interval = [long]0; [void][long]::TryParse((Get-Field $r 'interval'), [ref]$interval); if ($interval -le 0) { $interval = $PollSeconds }; $interval = [Math]::Max([long]$PollSeconds, $interval)
    $expires = [long]0; [void][long]::TryParse((Get-Field $r 'expires_in'), [ref]$expires); if ($expires -le 0) { $expires = 600 }
    $rec = Merge $rec @{
      label = $ctx.label; deviceCode = $deviceCode; userCode = $userCode; link = $link
      deviceExpiresAt = (Now) + [Math]::Max([long]60, $expires); interval = $interval; nextPollAt = (Now) + $interval
    }
    Write-Record $ctx $rec
    Write-Json (Get-Pending $rec)
  } finally { Exit-Lock $ctx $lock }
}

function Invoke-Wait($ctx) {
  $until = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
  while ($true) {
    $wait = 0; $done = $null
    $lock = Enter-Lock $ctx
    try {
      $rec = Read-Record $ctx
      if (-not $rec -or -not $rec.deviceCode) {
        if ($rec -and $rec.refreshToken) { $done = [ordered]@{ status = 'connected'; label = $rec.label; scope = $rec.scope } }
        else { Fail 'not_connected' 'No connection is being made. Run: mailcow-logs connect' }
      } else {
        $t = Now
        if ($rec.deviceExpiresAt + $StaleCodeSeconds -le $t) {
          Write-Record $ctx (Clear-Pending $rec)
          Fail 'expired' 'The code expired before it was approved. Run: mailcow-logs connect'
        }
        if ($rec.nextPollAt -gt $t) { $wait = $rec.nextPollAt - $t }
        else {
          Assert-Mine $ctx $lock
          try {
            $r = Invoke-OAuth $ctx '/oauth/token' ([ordered]@{ grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; device_code = $rec.deviceCode })
          } catch [OpsFail] {
            if ($_.Exception.Code -eq 'unreachable') { Write-Record $ctx (Merge $rec @{ nextPollAt = $t + $rec.interval }) }
            throw
          }
          $oauthError = Get-Field $r 'error'
          if ($r.status -eq 200) {
            $tokens = Get-Tokens $r
            # Connecting again (--replace): the old connection is ended once the new one is stored.
            $old = ''
            if ($rec.refreshToken -and $rec.refreshToken -ne $tokens.refreshToken) { $old = $rec.refreshToken }
            $rec = Merge (Clear-Pending $rec) $tokens
            $rec = Merge $rec @{ generation = (Hex 8); refreshStartedAt = [long]0; refreshRetried = [long]0; toRevoke = ((@($rec.toRevoke, $old) | Where-Object { $_ }) -join ' ') }
            Write-Record $ctx $rec
            Remove-Kinds $ctx
            $rec = Invoke-RevokePending $ctx $rec
            $done = [ordered]@{ status = 'connected'; label = $rec.label; scope = $rec.scope }
          } elseif ($oauthError -eq 'authorization_pending' -or $oauthError -eq 'slow_down') {
            $interval = $rec.interval
            if ($oauthError -eq 'slow_down') { $interval += 5 }
            Write-Record $ctx (Merge $rec @{ interval = $interval; nextPollAt = $t + $interval })
            $wait = $interval
          } elseif ($oauthError -eq 'access_denied') {
            Write-Record $ctx (Clear-Pending $rec)
            Fail 'denied' 'The person did not approve the connection.'
          } elseif ($oauthError -eq 'expired_token' -or $oauthError -eq 'invalid_grant') {
            Write-Record $ctx (Clear-Pending $rec)
            Fail 'expired' 'The code is no longer valid. Run: mailcow-logs connect'
          } else { throw (New-HttpFail $r 'Waiting for the approval') }
        }
      }
    } finally { Exit-Lock $ctx $lock }
    if ($done) { return Write-Json $done }
    if ([DateTime]::UtcNow.AddSeconds($wait) -gt $until) {
      return Write-Json ([ordered]@{ status = 'still_waiting'; next = 'Not approved yet. Run again: mailcow-logs connect --wait' })
    }
    Start-Sleep -Seconds $wait
  }
}

function Test-Usable($rec) { $rec.accessToken -and ($rec.accessExpiresAt - (Now)) -gt 60 -and -not $rec.refreshStartedAt }

# A live access token: the stored one while it lasts, else one refresh under the lock.
function Get-AccessToken($ctx, [string]$stale) {
  $first = Read-Record $ctx
  if (-not $first -or -not $first.refreshToken) { Fail 'not_connected' 'Not connected. Run: mailcow-logs connect' }
  if (-not $stale -and (Test-Usable $first)) { return $first.accessToken }
  $lock = Enter-Lock $ctx
  try {
    $rec = Read-Record $ctx
    if (-not $rec -or -not $rec.refreshToken) { Fail 'not_connected' 'Not connected. Run: mailcow-logs connect' }
    $rec = Invoke-RevokePending $ctx $rec
    # Another command refreshed while this one waited for the lock.
    if ((Test-Usable $rec) -and $rec.accessToken -ne $stale) { return $rec.accessToken }
    $before = @{ refreshStartedAt = $rec.refreshStartedAt; refreshRetried = $rec.refreshRetried }
    # A refresh that started moments ago may still be on its way (its holder lost the lock): never send it twice.
    if ($rec.refreshStartedAt -and ((Now) - $rec.refreshStartedAt) -lt $RefreshGrace) {
      Fail 'busy' 'Another mailcow-logs command is refreshing this connection. Nothing was sent; run it again.'
    }
    if ($rec.refreshStartedAt) {
      # The last refresh got no answer; trying once more either continues the connection or ends it there.
      if ($rec.refreshRetried) { Fail 'connection_ended' 'Two refreshes got no answer, so this connection cannot be trusted. Run: mailcow-logs connect --replace' }
      $rec.refreshRetried = [long]1
    }
    $rec.refreshStartedAt = Now
    Write-Record $ctx $rec
    Assert-Mine $ctx $lock
    Invoke-Hook 'before-refresh'
    try {
      $r = Invoke-OAuth $ctx '/oauth/token' ([ordered]@{ grant_type = 'refresh_token'; refresh_token = $rec.refreshToken; resource = "$($ctx.issuer)/api" })
    } catch [OpsFail] {
      # Nothing left the computer: the token is as good as before.
      if ($_.Exception.Code -eq 'unreachable' -and -not $_.Exception.Sent) { Write-Record $ctx (Merge $rec $before) }
      throw
    }
    if ($r.status -eq 200) {
      $next = Merge (Merge $rec (Get-Tokens $r)) @{ refreshStartedAt = [long]0; refreshRetried = [long]0 }
      Invoke-Hook 'before-write'
      if (-not (Test-Mine $ctx $lock)) {
        # The lock was taken while this one waited for the app: keep the new tokens anyway, under a fresh lock.
        $again = Enter-Lock $ctx $lock
        try { Write-Record $ctx $next } finally { Exit-Lock $ctx $again }
      } else { Write-Record $ctx $next }
      return $next.accessToken
    }
    if ((Get-Field $r 'error') -eq 'invalid_grant') {
      # An old connection still to be ended (after --replace) keeps its place until the app confirms it.
      if ($rec.toRevoke) { Write-Record $ctx (Merge (New-Record $ctx) @{ label = $rec.label; toRevoke = $rec.toRevoke }) }
      else { Remove-Record $ctx }
      Fail 'connection_ended' 'This connection has ended (disconnected in Settings, its time ran out, sign-in settings changed, or its token was used twice). Run: mailcow-logs connect'
    }
    # The app answered with an error before spending the token (a 4xx); a 5xx may have come after.
    if ($r.status -lt 500) { Write-Record $ctx (Merge $rec $before) }
    throw (New-HttpFail $r 'Refreshing the connection')
  } finally { Exit-Lock $ctx $lock }
}

# The full path of an API call (with its query) and the URL to send it to.
function Get-ApiTarget($ctx, [string]$p) {
  $bad = 'Give a path of the API, for example: messages?limit=20 (percent-encode anything else)'
  if (-not $p) { Fail 'bad_path' $bad }
  if ($p.StartsWith('/api/')) { $p = $p.Substring(4) }
  # Encoded dots too: a server or proxy that decodes them would take the token out of the API.
  if ($p -notmatch $PathChars -or $p.Contains('://') -or $p.StartsWith('//') -or $p -match '%2e') { Fail 'bad_path' $bad }
  $pathOnly = ($p -split '\?', 2)[0]
  foreach ($s in ($pathOnly -split '/')) { if ($s -eq '.' -or $s -eq '..') { Fail 'bad_path' $bad } }
  $sep = '/'; if ($p.StartsWith('/')) { $sep = '' }
  $u = $null
  if (-not [Uri]::TryCreate("$($ctx.issuer)/api$sep$p", [UriKind]::Absolute, [ref]$u)) { Fail 'bad_path' $bad }
  if ("$($u.Scheme)://$($u.Authority)" -ne $ctx.issuer -or -not $u.AbsolutePath.StartsWith('/api/') -or $u.AbsolutePath.Length -le 5) { Fail 'bad_path' $bad }
  @{ url = $u.AbsoluteUri; path = $u.AbsolutePath; hasQuery = [bool]$u.Query }
}

# Kinds: whether a call is a read or an action, from the server's own list of this connection's calls.

function Read-Kinds($ctx, $rec) {
  if (-not [IO.File]::Exists($ctx.kinds)) { return $null }
  try { $lines = [IO.File]::ReadAllText($ctx.kinds, $Utf8) -split "`r?`n" } catch { return $null }
  $head = $lines[0] -split ' '
  if ($head.Count -lt 4 -or $head[0] -ne 'mailcow-logs-kinds' -or $head[1] -ne '1' -or $head[2] -ne $rec.generation) { return $null }
  $at = [long]0; [void][long]::TryParse($head[3], [ref]$at)
  if ((Now) - $at -gt $KindsMaxAge) { return $null }
  $list = New-Object System.Collections.Generic.List[object]
  for ($i = 1; $i -lt $lines.Count; $i++) {
    $f = $lines[$i] -split ' '
    if ($f.Count -eq 3 -and $f[0] -cmatch '^[A-Z]{3,7}$' -and $f[1] -match $Template -and ($f[2] -eq 'read' -or $f[2] -eq 'act')) {
      $list.Add(@{ method = $f[0]; template = $f[1]; kind = $f[2] })
    }
  }
  , $list
}

function Write-Kinds($ctx, $rec, $data) {
  if (-not $rec -or -not $rec.generation -or -not (Test-Object $data) -or -not $data.PSObject.Properties['endpoints']) { return }
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("mailcow-logs-kinds 1 $($rec.generation) $(Now)")
  foreach ($e in @($data.endpoints)) {
    if (-not (Test-Object $e)) { continue }
    $method = ''; $template = ''; $kind = 'act'
    if ($e.PSObject.Properties['method']) { $method = [string]$e.method }
    if ($e.PSObject.Properties['path']) { $template = [string]$e.path }
    if ($e.PSObject.Properties['kind'] -and [string]$e.kind -eq 'read') { $kind = 'read' }
    if ($method -cmatch '^[A-Z]{3,7}$' -and $template -match $Template) { $lines.Add("$method $template $kind") }
  }
  # Only a cache: without it every call counts as an action.
  try { Write-Private $ctx $ctx.kinds (($lines -join "`n") + "`n") } catch {}
}

function Test-TemplateMatch([string]$template, [string]$path) {
  $t = $template -split '/'
  $s = $path -split '/'
  for ($i = 0; $i -lt $t.Count; $i++) {
    if ($t[$i] -match '^\{[^}]*:path\}$') {
      return ($i -eq $t.Count - 1 -and $s.Count -gt $i -and (($s[$i..($s.Count - 1)]) -join '') -ne '')
    }
    if ($i -ge $s.Count) { return $false }
    if ($t[$i] -match '^\{[^}]*\}$') { if ($s[$i] -eq '') { return $false } }
    elseif ($t[$i] -cne $s[$i]) { return $false }
  }
  $t.Count -eq $s.Count
}

# "read" or "act". An endpoint the list does not hold, or no list, counts as an action.
function Get-Kind($ctx, [string]$method, [string]$path) {
  if ($method -eq 'GET' -and ($path -eq '/api/agent/access' -or $path -eq '/api/agent/endpoints')) { return 'read' }
  $rec = Read-Record $ctx
  if (-not $rec -or -not $rec.refreshToken) { return 'act' }
  $list = Read-Kinds $ctx $rec
  if ($null -eq $list) {
    try {
      $r = Send-Api $ctx 'GET' (Get-ApiTarget $ctx 'agent/endpoints').url $null 'read'
      if ($r.status -eq 200) { Write-Kinds $ctx $rec $r.json; $list = Read-Kinds $ctx $rec }
    } catch {}
  }
  if ($null -eq $list) { return 'act' }
  $hit = $false; $act = $false
  foreach ($e in $list) {
    if ($e.method -ceq $method -and (Test-TemplateMatch $e.template $path)) { $hit = $true; if ($e.kind -eq 'act') { $act = $true } }
  }
  if (-not $hit -or $act) { return 'act' }
  'read'
}

# One API call with its retries: a refresh and one retry after a 401 (the server checks the token before the route
# runs), one retry after a 429 busy (nothing started), and for a read one retry after a network failure. An action
# is never sent again once it may have reached the app.
function Send-Api($ctx, [string]$method, [string]$url, $json, [string]$kind) {
  $token = Get-AccessToken $ctx ''
  $refreshed = $false; $busyRetried = $false; $netRetried = $false
  while ($true) {
    try { $r = Invoke-Ops $ctx $method $url $null $token $json $true } catch [OpsFail] {
      $e = $_.Exception
      if ($e.Code -ne 'unreachable') { throw }
      if ($kind -eq 'act') {
        if (-not $e.Sent) { throw }
        Fail 'outcome_unknown' $UnknownOutcome
      }
      if ($netRetried) { throw }
      $netRetried = $true
      continue
    }
    if ($r.status -eq 401 -and -not $refreshed) { $refreshed = $true; $token = Get-AccessToken $ctx $token; continue }
    if ($r.status -eq 429 -and (Get-Field $r 'error') -eq 'busy' -and -not $busyRetried) {
      $busyRetried = $true
      Start-Sleep -Milliseconds $BusyWaitMs
      continue
    }
    if ($kind -eq 'act' -and $r.status -ge 500) {
      $f = [OpsFail]::new('outcome_unknown', $UnknownOutcome); $f.Status = $r.status; throw $f
    }
    return $r
  }
}

# The answer as JSON text on one line: a JSON answer as it is (its line breaks are only spacing), text as a string.
function Get-DataText($r) {
  if ($r.isJson) { return ($r.text -replace "[`r`n]", '').Trim() }
  ConvertTo-JsonString $r.text
}

function Test-FailedAnswer($data) {
  if (-not (Test-Object $data)) { return $false }
  if ($data.PSObject.Properties['success'] -and $data.success -is [bool] -and -not $data.success) { return $true }
  if ($data.PSObject.Properties['status'] -and $data.status -is [string] -and $data.status -ceq 'error') { return $true }
  $false
}

function Invoke-Api($ctx, [string]$method, [string]$p, $json) {
  $target = Get-ApiTarget $ctx $p
  if ($null -ne $json) { try { [void]($json | ConvertFrom-Json) } catch { Fail 'bad_body' 'The body is not JSON.' } }
  $kind = Get-Kind $ctx $method $target.path
  $r = Send-Api $ctx $method $target.url $json $kind
  if ($r.status -ge 200 -and $r.status -lt 300) {
    if ($method -eq 'GET' -and $target.path -eq '/api/agent/endpoints' -and -not $target.hasQuery) { Write-Kinds $ctx (Read-Record $ctx) $r.json }
    $data = Get-DataText $r
    if (Test-FailedAnswer $r.json) {
      Write-Line ('{"error":"failed","message":' + (ConvertTo-JsonString "$method $p answered that it failed.") + ',"status":' + $r.status + ',"data":' + $data + '}')
      $script:ExitCode = 1
      return
    }
    Write-Line ('{"status":' + $r.status + ',"data":' + $data + '}')
    return
  }
  # The app's own refusals for agents carry a code and a message: passed on as they are.
  $code = Get-Field $r 'error'; $message = Get-Field $r 'message'
  if ($code -cmatch '^[a-z_]{1,40}$' -and (Test-Object $r.json) -and $r.json.PSObject.Properties['message'] -and $r.json.message -is [string]) {
    $f = [OpsFail]::new($code, $message); $f.Status = $r.status; throw $f
  }
  throw (New-HttpFail $r "$method $p")
}

function Invoke-Disconnect($ctx) {
  $lock = Enter-Lock $ctx
  try {
    $rec = Read-Record $ctx
    if (-not $rec) { return Write-Json ([ordered]@{ status = 'not_connected' }) }
    Assert-Mine $ctx $lock
    $left = @()
    foreach ($token in (@($rec.refreshToken) + ($rec.toRevoke -split ' ') | Where-Object { $_ })) {
      $ok = $false
      try { $r = Invoke-OAuth $ctx '/oauth/revoke' ([ordered]@{ token = $token; token_type_hint = 'refresh_token' }); $ok = $r.status -eq 200 } catch {}
      if (-not $ok) { $left += $token }
    }
    if ($left.Count) {
      Write-Record $ctx (Merge $rec @{ refreshToken = ''; accessToken = ''; accessExpiresAt = [long]0; toRevoke = ($left -join ' ') })
      Fail 'disconnect_failed' 'mailcow Logs Viewer did not confirm the disconnect. Run it again, or disconnect this agent in Settings > Agents.'
    }
    Remove-Record $ctx
    Write-Json ([ordered]@{ status = 'disconnected' })
  } finally { Exit-Lock $ctx $lock }
}

function Get-Body($o, $fallback) {
  $body = $o.json
  if ($null -ne $o.jsonFile) { try { $body = [IO.File]::ReadAllText($o.jsonFile, $Utf8) } catch { Fail 'bad_body' "Cannot read $($o.jsonFile)." } }
  if ($null -eq $body) { $body = $fallback }
  $body
}

function Invoke-Main([string[]]$argv) {
  $list = New-Object System.Collections.Generic.List[string]
  foreach ($a in $argv) { $list.Add($a) }
  $command = 'help'
  if ($list.Count) { $command = $list[0]; $list.RemoveAt(0) }
  $o = @{ url = ''; replace = $false; wait = $false; json = $null; jsonFile = $null; positional = @() }
  for ($i = 0; $i -lt $list.Count; $i++) {
    $a = $list[$i]
    if ($a -eq '--url') { $i++; $o.url = $list[$i] }
    elseif ($a -eq '--replace') { $o.replace = $true }
    elseif ($a -eq '--wait') { $o.wait = $true }
    elseif ($a -eq '--json') { $i++; $o.json = $list[$i] }
    elseif ($a -eq '--json-file') { $i++; $o.jsonFile = $list[$i] }
    else { $o.positional += $a }
  }
  if (@('help', '--help', '-h') -contains $command) { Write-Line $Help; return }
  $ctx = Get-Context $o.url
  $first = $null
  if ($o.positional.Count) { $first = $o.positional[0] }
  switch -CaseSensitive ($command) {
    'status' { Show-Status $ctx }
    'connect' { if ($o.wait) { Invoke-Wait $ctx } else { Invoke-Connect $ctx $o.replace } }
    'access' { Invoke-Api $ctx 'GET' 'agent/access' $null }
    'endpoints' {
      if ($null -eq $first) { Invoke-Api $ctx 'GET' 'agent/endpoints' $null }
      elseif ($first -cnotmatch '^[a-z_]{1,40}$') { Fail 'bad_path' 'Give an area name, for example: security' }
      else { Invoke-Api $ctx 'GET' "agent/endpoints?area=$first" $null }
    }
    'get' { Invoke-Api $ctx 'GET' $first $null }
    'post' { Invoke-Api $ctx 'POST' $first (Get-Body $o '{}') }
    'put' { Invoke-Api $ctx 'PUT' $first (Get-Body $o '{}') }
    'patch' { Invoke-Api $ctx 'PATCH' $first (Get-Body $o '{}') }
    'delete' { Invoke-Api $ctx 'DELETE' $first (Get-Body $o $null) }
    'disconnect' { Invoke-Disconnect $ctx }
    default { Fail 'unknown_command' "Unknown command `"$command`". Run: mailcow-logs help" }
  }
}

$script:ExitCode = 0
try {
  Invoke-Main $args
  exit $script:ExitCode
} catch {
  $e = $_.Exception
  if ($e -is [OpsFail]) {
    $out = [ordered]@{ error = $e.Code; message = $e.Message }
    if ($e.Status) { $out.status = $e.Status }
    if ($null -ne $e.Body) { $out.body = $e.Body }
    Write-Json $out
  } else {
    Write-Json ([ordered]@{ error = 'failed'; message = $e.Message })
  }
  exit 1
}
