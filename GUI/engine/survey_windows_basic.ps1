$ErrorActionPreference = 'Stop';
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false);
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem;
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent();
    $principal = New-Object Security.Principal.WindowsPrincipal($identity);
    $notes = @();
    $listeners = @();
    $services = @();
    $processes = @();
    $listenerCount = $null;
    $serviceCount = $null;
    try {
        $allListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop);
        $listenerCount = $allListeners.Count;
        $listeners = @($allListeners | Sort-Object LocalPort,LocalAddress | Select-Object -First 256 LocalAddress,LocalPort,OwningProcess);
        $processIds = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique);
        foreach ($processId in $processIds) {
            try {
                $p = Get-Process -Id $processId -ErrorAction Stop;
                $processes += [ordered]@{ pid=[int]$processId; name=$p.ProcessName; executable_path=$p.Path; };
            } catch { $notes += "Cannot inspect listener process $processId"; }
        };
        if ($listenerCount -gt 256) { $notes += 'TCP listener inventory truncated at 256 entries'; };
    } catch { $notes += 'Cannot read TCP listeners'; };
    try {
        $allServices = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.State -eq 'Running' -or $_.Name -match 'Wazuh|Sysmon|Apache|W3SVC|nginx|mysql' } | Sort-Object Name);
        $serviceCount = $allServices.Count;
        $services = @($allServices | Select-Object -First 256 | ForEach-Object { [ordered]@{ name=$_.Name; display_name=$_.DisplayName; state=$_.State; process_id=[int]$_.ProcessId; } });
        if ($serviceCount -gt 256) { $notes += 'Service inventory truncated at 256 entries'; };
    } catch { $notes += 'Cannot read service inventory'; };
    $telemetry = [ordered]@{};
    foreach ($pair in @(@('process_events',1,'sysmon_event_1'),@('network_events',3,'sysmon_event_3'))) {
        try {
            $event = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=[int]$pair[1];StartTime=(Get-Date).AddHours(-24)} -MaxEvents 1 -ErrorAction Stop;
            $telemetry[$pair[0]] = [ordered]@{kind=$pair[2];event_time=$event.TimeCreated.ToUniversalTime().ToString('o');event_id=[int]$event.Id;record_id=[long]$event.RecordId;channel='Microsoft-Windows-Sysmon/Operational'};
        } catch { };
    };
    try {
        $paths = @('C:\xampp\apache\logs\access.log');
        foreach ($apacheProcess in @($processes | Where-Object { $_.name -eq 'httpd' -and $_.executable_path })) {
            $apacheRoot = Split-Path (Split-Path $apacheProcess.executable_path -Parent) -Parent;
            $paths += Join-Path $apacheRoot 'logs\access.log';
        };
        $paths = @($paths | Select-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf });
        foreach ($logPath in @($paths | Select-Object -First 4)) {
            if ($logPath -notmatch '^[A-Za-z]:\\') { continue; };
            $stream = [IO.File]::Open($logPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);
            try {
                $offset=[Math]::Max(0,$stream.Length-65536);[void]$stream.Seek($offset,[IO.SeekOrigin]::Begin);
                $buffer=New-Object byte[] 65536;$length=$stream.Read($buffer,0,65536);
                $tail=[Text.Encoding]::UTF8.GetString($buffer,0,$length);
            } finally { $stream.Dispose(); };
            foreach ($line in ($tail -split "`n")) {
                if ($line -match '\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{2})(\d{2})\]') {
                    $stamp=[DateTimeOffset]::ParseExact(($matches[1]+' '+$matches[2]+':'+$matches[3]),'dd/MMM/yyyy:HH:mm:ss zzz',[Globalization.CultureInfo]::InvariantCulture);
                    if ($stamp.UtcDateTime -ge [DateTime]::UtcNow.AddHours(-24) -and $stamp.UtcDateTime -le [DateTime]::UtcNow.AddMinutes(2)) {
                        $telemetry['web_access_logs']=[ordered]@{kind='apache_access_entry';event_time=$stamp.UtcDateTime.ToString('o');path=$logPath};
                    };
                };
            };
        };
    } catch { };
    [ordered]@{
        tool='get_endpoint_info'; target=$env:COMPUTERNAME; status='ok';
        data=[ordered]@{
            os_name=$os.Caption; os_version=$os.Version; architecture=$os.OSArchitecture;
            hostname=$env:COMPUTERNAME; username=$identity.Name;
            is_elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
            powershell_version=$PSVersionTable.PSVersion.ToString();
            collected_at=[DateTime]::UtcNow.ToString('o'); telemetry_observations=$telemetry;
            listeners=$listeners; services=$services; processes=$processes; listener_count=$listenerCount; service_count=$serviceCount; limitations=$notes;
        };
        evidence=@('Win32_OperatingSystem','WindowsIdentity','WindowsPrincipal','Get-NetTCPConnection','Win32_Service','Get-Process'); error=$null;
    } | ConvertTo-Json -Depth 8 -Compress;
} catch {
    [ordered]@{ tool='get_endpoint_info'; target=$env:COMPUTERNAME; status='failed'; data=$null; evidence=@(); error=$_.Exception.Message; } | ConvertTo-Json -Depth 5 -Compress;
    exit 1;
}
