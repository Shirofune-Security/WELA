# Genuine public fixed probe. Only the disposable fixture may toggle the channel.
param([switch]$AllowDisposableChannelWrite)
$ErrorActionPreference='Stop'
if(-not $AllowDisposableChannelWrite -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:OS -ne 'Windows_NT'){throw 'Explicit disposable GitHub-hosted Windows opt-in required.'}
$repo=Split-Path $PSScriptRoot -Parent
Import-Module "$repo/modules/AuditProfiles.psm1" -Force
. "$repo/scripts/WefArrival.ps1"
. "$repo/scripts/ChannelRead.ps1"
. "$repo/scripts/WmiProbe.ps1"
. "$repo/scripts/Capi2Probe.ps1"
$hostState=Get-WelaChannelReadHost
if($hostState.ProductType -ne 3 -or $hostState.DomainRole -ne 2 -or $hostState.DomainJoined -or $hostState.Build -notin @(20348,26100)){throw 'A disposable standalone Server 2022/2025 is required.'}
$script:count=0
function Assert($Value,$Message){if(-not $Value){throw $Message};$script:count++}
function Key($Value){ConvertTo-Json -InputObject $Value -Depth 16 -Compress}
function Read-Stores {
 $result=[ordered]@{}
 foreach($location in @('CurrentUser','LocalMachine')){foreach($name in @('My','Root','CertificateAuthority')){
  $store=[Security.Cryptography.X509Certificates.X509Store]::new([Security.Cryptography.X509Certificates.StoreName]$name,[Security.Cryptography.X509Certificates.StoreLocation]$location)
  try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly);$certificates=$store.Certificates;try{$result[$location+'/'+$name]=@($certificates|ForEach-Object Thumbprint|Sort-Object)}finally{foreach($c in $certificates){$c.Dispose()}}}finally{$store.Dispose()}
 }}
 [pscustomobject]$result
}
Initialize-WelaCapi2ProbeNative
Add-Type -Path "$PSScriptRoot/Capi2KeyProbe.Checkpoint.cs"
$original=Get-WelaCapi2ProbeChannel;$originalStores=Read-Stores
$root=New-WelaArrivalOutput (Join-Path $env:RUNNER_TEMP ('wela-capi2-key-checkpoint-'+[guid]::NewGuid().ToString('N'))) $PSScriptRoot
$null=Write-WelaArrivalArtifact $root 'channel-original.json' ($original|ConvertTo-Json)
$null=Write-WelaArrivalArtifact $root 'stores-original.json' ($originalStores|ConvertTo-Json -Depth 8)
$failure=$null;$cleanupErrors=@();$changed=$false;$channelRestored=$false;$storesPreserved=$false
$key=$null;$rsa=$null;$certificate=$null;$withKey=$null
try{
 $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($original.Name)
 try{if(-not $channel.IsEnabled){$changed=$true;$channel.IsEnabled=$true;$channel.SaveChanges()}}finally{$channel.Dispose()}
 $enabled=Get-WelaCapi2ProbeChannel
 $expected=$original|ConvertTo-Json|ConvertFrom-Json;$expected.Enabled=$true
 Assert ((Key $enabled) -ceq (Key $expected)) 'Only CAPI2 Enabled changed.'
 $state=Get-WelaCapi2ProbeState;$null=Get-WelaCapi2ProbeStateKey $state
 $nonce=[guid]::NewGuid().ToString('N')
 $key=[Wela.Capi2Probe.Native]::CreateEphemeralRsa()
 Assert ($key.IsEphemeral -and -not $key.KeyName) 'Owned key is unnamed and ephemeral.'
 $rsa=[Security.Cryptography.RSACng]::new($key)
 $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(('CN=WelaCapi2Probe_'+$nonce),$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $now=[DateTimeOffset][Wela.WmiProbe.Native]::UtcNow()
 $generator=[Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($rsa,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $certificate=$request.Create($request.SubjectName,$generator,$now.AddMinutes(-5),$now.AddMinutes(5),[guid]::NewGuid().ToByteArray())
 $withKey=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($certificate,$rsa)
 $boundary=Get-WelaCapi2ProbeWatermark
 $before=[Wela.WmiProbe.Native]::Snapshot();$start=[Wela.WmiProbe.Native]::UtcNow()
 $result=[Wela.Capi2KeyCheckpoint.Native]::Acquire($withKey)
 $end=[Wela.WmiProbe.Native]::UtcNow();$after=[Wela.WmiProbe.Native]::Snapshot()
 $operation=[pscustomobject]@{Nonce=$nonce;Thumbprint=$certificate.Thumbprint;Subject=$certificate.Subject;Der=[Convert]::ToBase64String($certificate.RawData);ProcessId=$PID;RecordBoundary=$boundary;StartedUtc=$start.ToString('o');CompletedUtc=$end.ToString('o');BeforeToken=$before;AfterToken=$after;Result=$result}
 $null=Write-WelaArrivalArtifact $root 'operation.json' ($operation|ConvertTo-Json -Depth 16)
 $null=Write-WelaArrivalArtifact $root 'state.json' ($state|ConvertTo-Json -Depth 16)
 Assert ((Get-WelaWmiProbeTokenKey $before) -ceq (Get-WelaWmiProbeTokenKey $after)) 'Token unchanged around exact native acquisition.'
 Assert ($result.Success -and $result.KeySpec -eq 4294967295 -and -not $result.CallerFree) 'Native CNG acquisition succeeded; owned certificate retains cached handle.'
 $query="*[System[EventID=70 and EventRecordID>$boundary]]"
 $texts=@();$timer=[Diagnostics.Stopwatch]::StartNew()
 do{
  $records=@();try{try{$records=@(Get-WinEvent -LogName $original.Name -FilterXPath $query -MaxEvents 64 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
   $texts=@($records|ForEach-Object ToXml)
  }finally{foreach($record in $records){$record.Dispose()}}
  if($texts.Count){break};Start-Sleep -Milliseconds 200
 }while($timer.Elapsed.TotalSeconds -lt 15)
 $matched=0;$i=0
 foreach($raw in $texts){if($raw.Length -gt 131072){throw 'Candidate over limit.'};$i++;$null=Write-WelaArrivalArtifact $root ('candidate-'+$i+'.xml') $raw;Write-Host $raw
  [xml]$doc=$raw;$eventTime=[DateTimeOffset]::Parse($doc.Event.System.TimeCreated.SystemTime)
  if([int]$doc.Event.System.Execution.ProcessID -eq $PID -and $eventTime -ge $start -and $eventTime -le $end -and $raw.Contains($certificate.Thumbprint)){$matched++}
 }
 Assert ($texts.Count -lt 64 -and $matched -eq 1) 'Exactly one event70 attributed by actual PID, precise call interval and certificate thumbprint.'
 Assert ((Key (Get-WelaCapi2ProbeChannel)) -ceq (Key $enabled)) 'Operation preserved channel.'
 Assert ((Key (Read-Stores)) -ceq (Key $originalStores)) 'Operation preserved selected certificate stores.'
}catch{$failure=$_}
finally{
 if($withKey){$withKey.Dispose()};if($certificate){$certificate.Dispose()};if($rsa){$rsa.Dispose()};if($key){$key.Dispose()}
 try{$channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($original.Name);try{if($channel.IsEnabled -ne $original.Enabled){$channel.IsEnabled=$original.Enabled;$channel.SaveChanges()}}finally{$channel.Dispose()};$restored=Get-WelaCapi2ProbeChannel;$null=Write-WelaArrivalArtifact $root 'channel-restored.json' ($restored|ConvertTo-Json);if((Key $restored) -cne (Key $original)){throw 'Original channel configuration was not restored.'};$channelRestored=$true}catch{$cleanupErrors+='Channel restoration: '+$_.Exception.Message}
 try{$storesAfter=Read-Stores;$null=Write-WelaArrivalArtifact $root 'stores-after.json' ($storesAfter|ConvertTo-Json -Depth 8);if((Key $storesAfter) -cne (Key $originalStores)){throw 'Certificate store inventory changed.'};$storesPreserved=$true}catch{$cleanupErrors+='Store observation: '+$_.Exception.Message}
 $null=Write-WelaArrivalArtifact $root 'cleanup.json' ([pscustomobject]@{ChangedEnabled=$changed;Failure=$(if($failure){$failure.Exception.Message}else{$null});CleanupErrors=$cleanupErrors;ChannelRestored=$channelRestored;SelectedStoresPreserved=$storesPreserved;Complete=($null -eq $failure -and $cleanupErrors.Count -eq 0);Evidence=$root}|ConvertTo-Json)
}
if($failure){throw $failure};if($cleanupErrors.Count){throw ($cleanupErrors -join '; ')}
Write-Host "PASS: $script:count actual CAPI2 event70 feasibility checks."
$global:LASTEXITCODE=0
