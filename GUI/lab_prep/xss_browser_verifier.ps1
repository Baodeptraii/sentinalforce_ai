# xss_browser_verifier.ps1 — versioned headless-browser XSS execution proof.
# Deployed to C:\SOC-Lab\config\ on the lab endpoint by APPROVED lab prep only.
# Logs into DVWA inside a real (headless) Edge context using the same lab login
# file as the fixed abilities, then navigates to the reflected-XSS URL carrying
# a harmless marker payload and reports whether the marker JavaScript actually
# executed. HTTP reflection alone is never a success verdict.
# Output: single-line JSON verdict. Exit 0 only on proven execution.
param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$JarPath,
    [Parameter(Mandatory = $true)][string]$Payload
)
$ErrorActionPreference = 'Stop'
function Out-Verdict([string]$status, [string]$detail) {
    Write-Output ('{"verifier":"' + $status + '","detail":"' + ($detail -replace '"', "'") + '"}')
}
function Read-Jar([string]$path) {
    $cookies = @{}
    foreach ($line in Get-Content -LiteralPath $path) {
        if ($line -match '^#|^\s*$') { continue }
        $parts = $line -split "`t"
        if ($parts.Count -ge 7) { $cookies[$parts[5]] = $parts[6] }
    }
    return $cookies
}
$cookies = Read-Jar $JarPath
if (-not $cookies['PHPSESSID']) { Out-Verdict 'XSS_BROWSER_ERROR' 'session_jar_missing_phpsessid'; exit 1 }
$edge = @(
    (Get-Command msedge.exe -ErrorAction SilentlyContinue).Source,
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $edge) { Out-Verdict 'XSS_BROWSER_ERROR' 'edge_not_found'; exit 1 }
$profileDir = Join-Path ([System.IO.Path]::GetDirectoryName($JarPath)) ('edge_profile_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
$proc = Start-Process -FilePath $edge -ArgumentList @(
    '--headless=new', '--disable-gpu', '--no-first-run', '--disable-extensions',
    ('--user-data-dir=' + $profileDir), '--remote-debugging-port=0', 'about:blank'
) -PassThru
try {
    $portFile = Join-Path $profileDir 'DevToolsActivePort'
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-Path $portFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    if (-not (Test-Path $portFile)) { Out-Verdict 'XSS_BROWSER_ERROR' 'devtools_port_timeout'; exit 1 }
    $port = (Get-Content $portFile | Select-Object -First 1).Trim()
    $targets = $null
    $deadline = (Get-Date).AddSeconds(10)
    while (-not $targets -and (Get-Date) -lt $deadline) {
        try { $targets = Invoke-RestMethod -Uri ('http://127.0.0.1:' + $port + '/json/list') -TimeoutSec 3 } catch { Start-Sleep -Milliseconds 300 }
    }
    if (-not $targets) { Out-Verdict 'XSS_BROWSER_ERROR' 'devtools_targets_timeout'; exit 1 }
    $wsUrl = ($targets | Where-Object { $_.type -eq 'page' } | Select-Object -First 1).webSocketDebuggerUrl
    if (-not $wsUrl) { Out-Verdict 'XSS_BROWSER_ERROR' 'no_page_target'; exit 1 }
    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $ct = [System.Threading.CancellationToken]::None
    [void]($ws.ConnectAsync([Uri]$wsUrl, $ct).GetAwaiter().GetResult())
    $msgId = 0
    function Send-Cdp([string]$method, $params) {
        $script:msgId++
        $msg = @{ id = $script:msgId; method = $method }
        if ($params) { $msg.params = $params }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($msg | ConvertTo-Json -Depth 6 -Compress))
        [void]($ws.SendAsync([ArraySegment[byte]]::new($bytes), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).GetAwaiter().GetResult())
        return $script:msgId
    }
    function Recv-Cdp([int]$wantId, [int]$seconds = 20) {
        $buffer = New-Object byte[] 1048576
        $deadline = (Get-Date).AddSeconds($seconds)
        while ((Get-Date) -lt $deadline) {
            $stream = [System.IO.MemoryStream]::new()
            while ($true) {
                $seg = [ArraySegment[byte]]::new($buffer)
                $result = $ws.ReceiveAsync($seg, $ct).GetAwaiter().GetResult()
                $stream.Write($buffer, 0, $result.Count)
                if ($result.EndOfMessage) { break }
            }
            $text = [System.Text.Encoding]::UTF8.GetString($stream.ToArray())
            $obj = $text | ConvertFrom-Json
            if ($obj.id -eq $wantId) { return $obj }
        }
        return $null
    }
    function Eval-Js([string]$expression, [bool]$await = $true) {
        $id = Send-Cdp 'Runtime.evaluate' @{ expression = $expression; awaitPromise = $await; returnByValue = $true; backForwardCacheNotUsed = $true }
        $reply = Recv-Cdp $id 25
        return $reply.result.result.value
    }
    [void](Send-Cdp 'Page.enable' $null)
    [void](Send-Cdp 'Network.enable' $null)
    # Inject the already-authenticated demo session (curl jar written by
    # the fixed session ability) instead of logging in inside the browser.
    $cookieUrl = $BaseUrl.TrimEnd('/') + '/login.php'
    foreach ($name in @('PHPSESSID', 'security')) {
        if (-not $cookies[$name]) { continue }
        $setParams = @{ name = $name; value = $cookies[$name]; url = $cookieUrl; path = '/dvwa' }
        $id = Send-Cdp 'Network.setCookie' $setParams
        $reply = Recv-Cdp $id 10
        if (-not $reply.result.success) { Out-Verdict 'XSS_BROWSER_ERROR' ('set_cookie_failed_' + $name); exit 1 }
    }
    $encodedPayload = [uri]::EscapeDataString($Payload)
    $targetUrl = $BaseUrl.TrimEnd('/') + '/vulnerabilities/xss_r/?name=' + $encodedPayload
    $navId = Send-Cdp 'Page.navigate' @{ url = $targetUrl }
    $navReply = Recv-Cdp $navId 10
    if (-not $navReply -or $navReply.error) {
        Out-Verdict 'XSS_BROWSER_ERROR' ('navigate_rejected ' + ($navReply | ConvertTo-Json -Depth 4 -Compress))
        exit 1
    }
    $deadline = (Get-Date).AddSeconds(20)
    $onTarget = $false
    $lastHref = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $href = [string](Eval-Js 'location.href' $false)
        $lastHref = $href
        if ($href -like '*vulnerabilities/xss_r/*') { $onTarget = $true; break }
    }
    if (-not $onTarget) { Out-Verdict 'XSS_BROWSER_ERROR' ('xss_navigation_timeout last=' + $lastHref); exit 1 }
    # The URL changes before scripts run; wait for the document to settle.
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $state = [string](Eval-Js 'document.readyState' $false)
        if ($state -eq 'complete') { break }
        Start-Sleep -Milliseconds 400
    }
    Start-Sleep -Milliseconds 800
    $probeJs = "JSON.stringify({href: location.href.slice(-50), title: document.title, marker: document.documentElement.getAttribute('data-demo') || '', hello: (document.body.innerText.match(/Hello[^\n]{0,80}/) || [''])[0]})"
    $probe = Eval-Js $probeJs $false
    $values = $probe | ConvertFrom-Json
    if ($values.title -eq 'XSS_EXEC_MARKER' -and $values.marker -eq 'xss-exec') {
        Out-Verdict 'XSS_BROWSER_OK' ('marker_executed title=' + $values.title)
        exit 0
    }
    Out-Verdict 'XSS_BROWSER_NEGATIVE' ('no_execution ' + $probe)
    exit 1
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
}
