# FOFA 三账号 helper（主号 → backup → backup2，限流切下一个）
$script:FOFA_PRIMARY_EMAIL = "fbai1106@163.com"
$script:FOFA_PRIMARY_KEY   = "c37e23b2879049497c00c3dd02d5a849"
$script:FOFA_BACKUP_KEY    = "17c634211826cab2a5c28806fa42e451"
$script:FOFA_BACKUP2_EMAIL = "599927799@qq.com"
$script:FOFA_BACKUP2_KEY   = "e907eb76a438e7f3ab40557e63d41bff"
$script:FOFA_EXHAUSTED     = @()

function Invoke-FofaSearch {
  param(
    [Parameter(Mandatory=$true)][string]$Query,
    [int]$Size = 100,
    [string]$Fields = "host,ip,port,title,server"
  )
  $q64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Query))
  $all = @("primary","backup","backup2")
  $tryOrder = @($all | Where-Object { $script:FOFA_EXHAUSTED -notcontains $_ }) + @($all | Where-Object { $script:FOFA_EXHAUSTED -contains $_ })
  foreach ($acc in $tryOrder) {
    if ($acc -eq "primary") {
      $uri = "https://fofa.info/api/v1/search/all?email=$($script:FOFA_PRIMARY_EMAIL)&key=$($script:FOFA_PRIMARY_KEY)&qbase64=$q64&size=$Size&fields=$Fields"
    } elseif ($acc -eq "backup") {
      $uri = "https://fofa.info/api/v1/search/all?key=$($script:FOFA_BACKUP_KEY)&qbase64=$q64&size=$Size&fields=$Fields"
    } else {
      $uri = "https://fofa.info/api/v1/search/all?email=$($script:FOFA_BACKUP2_EMAIL)&key=$($script:FOFA_BACKUP2_KEY)&qbase64=$q64&size=$Size&fields=$Fields"
    }
    try {
      $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 30
      $j = $r.Content | ConvertFrom-Json
      if ($j.error -eq $true) {
        $em = [string]$j.errmsg
        if ($em -match "820041|频繁|上限|F点" -or $r.StatusCode -eq 429) {
          if ($script:FOFA_EXHAUSTED -notcontains $acc) { $script:FOFA_EXHAUSTED += $acc }
          continue
        }
      }
      return [pscustomobject]@{ account=$acc; data=$j; query=$Query }
    } catch {
      $msg = $_.Exception.Message
      if ($msg -match "429|Too Many") {
        if ($script:FOFA_EXHAUSTED -notcontains $acc) { $script:FOFA_EXHAUSTED += $acc }
        continue
      }
      if ($acc -eq "backup2") { throw }
    }
  }
  throw "FOFA all accounts failed/rate-limited"
}
