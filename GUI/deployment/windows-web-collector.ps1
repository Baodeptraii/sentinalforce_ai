# Metadata-only tailer. No request body/header/query, cookie or raw error text is emitted.
param([string]$Root='C:\ProgramData\SOC-Agent\telemetry',
 [string]$AccessPath='C:\xampp\apache\logs\access.log',
 [string]$ErrorPath='C:\xampp\apache\logs\error.log',
 [ValidateRange(100,100000000)][long]$MaxBytes=5000000,
 [ValidateRange(1,3650)][int]$RetentionDays=30,[switch]$PruneArchives)
$ErrorActionPreference='Stop'
$utf8=New-Object System.Text.UTF8Encoding($false)
$mutex=New-Object Threading.Mutex($false,'Global\SOC-Web-Telemetry-v1')
if(-not $mutex.WaitOne(0)){exit 0}
try {
  if((Get-Item -LiteralPath $Root).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse_root_refused'}
  foreach($name in @('cursor.json','web.jsonl')){$candidate=Join-Path $Root $name;if((Test-Path $candidate) -and ((Get-Item -LiteralPath $candidate).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'reparse_file_refused'}}
  if($PruneArchives){Get-ChildItem -LiteralPath $Root -Filter 'web-*.jsonl' -File | Where-Object {$_.Name -match '^web-[a-f0-9-]{36}\.jsonl$' -and $_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddDays(-$RetentionDays) -and -not($_.Attributes -band [IO.FileAttributes]::ReparsePoint)} | Remove-Item}
  $sources=@(@{name='apache_access';path=$AccessPath},@{name='apache_error';path=$ErrorPath})
  $stateFile=Join-Path $Root 'cursor.json';$state=@{}
  if(Test-Path $stateFile){$old=Get-Content $stateFile -Raw | ConvertFrom-Json;foreach($p in $old.PSObject.Properties){$state[$p.Name]=$p.Value}}
  $out=Join-Path $Root 'web.jsonl'
  if((Test-Path $out) -and (Get-Item $out).Length -gt $MaxBytes){Move-Item $out (Join-Path $Root ('web-'+[guid]::NewGuid().ToString()+'.jsonl'))}
  foreach($source in $sources){
    if(-not(Test-Path -LiteralPath $source.path)){continue}
    $info=Get-Item -LiteralPath $source.path
    $identity=$info.CreationTimeUtc.Ticks.ToString()
    $previous=$state[$source.name]
    # First observation starts at EOF: no implicit historical backfill.
    if(-not $previous){$state[$source.name]=@{identity=$identity;offset=$info.Length};continue}
    $offset=[long]$previous.offset
    $rotated=($previous.identity -ne $identity -or $info.Length -lt $offset)
    if($rotated){$offset=0}
    $stream=New-Object IO.FileStream($source.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
      [void]$stream.Seek($offset,[IO.SeekOrigin]::Begin)
      $size=[int][Math]::Min(1048576,[Math]::Max(0,$stream.Length-$offset));$bytes=New-Object byte[] $size
      $read=$stream.Read($bytes,0,$size);$last=-1
      for($i=$read-1;$i -ge 0;$i--){if($bytes[$i] -eq 10){$last=$i;break}}
      if($last -ge 0){
        $content=$utf8.GetString($bytes,0,$last+1)
        $lineOffset=$offset
        foreach($line in ($content -split "`n")){
          if(-not $line.Trim()){$lineOffset+=$utf8.GetByteCount($line)+1;continue}
          $sha=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($line)))).Replace('-','').ToLower()}finally{$sha.Dispose()}
          $eventHash=[Security.Cryptography.SHA256]::Create();try{$eventId=([BitConverter]::ToString($eventHash.ComputeHash($utf8.GetBytes($env:COMPUTERNAME+'|'+$source.name+'|'+$identity+'|'+$lineOffset+'|'+$digest)))).Replace('-','').ToLower()}finally{$eventHash.Dispose()}
          $web=@{schema_version='soc_web_v1';event_id=$eventId;timestamp=[DateTime]::UtcNow.ToString('o');host=$env:COMPUTERNAME;source=$source.name;source_path=$source.path;source_line_sha256=$digest;marker=$null;test_marker=$false;method=$null;status=$null;error_code=$null;redacted=$true;truncated=$false;rotation_observed=$rotated}
          if($source.name -eq 'apache_access'){
            if($line -match '"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) [^"\r\n]* HTTP/[0-9.]+" ([0-9]{3}) '){$web.method=$matches[1];$web.status=[int]$matches[2]}
            if($line -match '(?:[?&]soc_probe=|/soc_probe/)([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:[& /"]|$)'){$web.marker=$matches[1];$web.test_marker=$true}
          } else {if($line -match '\b(AH[0-9]{5})\b'){$web.error_code=$matches[1]}}
          [IO.File]::AppendAllText($out,(@{soc_web=$web}|ConvertTo-Json -Depth 4 -Compress)+"`n",$utf8)
          $lineOffset+=$utf8.GetByteCount($line)+1
        }
        $offset+=$last+1
      }
      # Oversized line has no safe boundary; retain offset and surface a bounded collector warning.
      if($read -eq 1048576 -and $last -lt 0){throw 'source_line_exceeds_budget'}
      $state[$source.name]=@{identity=$identity;offset=$offset}
    } finally {$stream.Dispose()}
  }
  $temporary=$stateFile+'.tmp';[IO.File]::WriteAllText($temporary,($state|ConvertTo-Json -Depth 5 -Compress),$utf8);Move-Item $temporary $stateFile -Force
  [IO.File]::WriteAllText((Join-Path $Root 'health.json'),(@{status='ok';timestamp=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress),$utf8)
} catch {
  [IO.File]::WriteAllText((Join-Path $Root 'health.json'),(@{status='failed';timestamp=[DateTime]::UtcNow.ToString('o');error='collector_failure_no_raw_message'}|ConvertTo-Json -Compress),$utf8)
  exit 1
} finally {$mutex.ReleaseMutex();$mutex.Dispose()}
