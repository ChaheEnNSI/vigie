<#
  Exporte les événements de sécurité Windows utiles à Vigie, au format JSON.
  À lancer en administrateur (le journal Security est protégé) :

    powershell -ExecutionPolicy Bypass -File .\scripts\export-windows-security.ps1 -Heures 24 -Sortie .\windows-security.json
#>
param(
  [int]$Heures = 24,
  [string]$Sortie = ".\windows-security.json"
)

$depuis = (Get-Date).AddHours(-$Heures)
$ids = @{ Security = 4624, 4625, 4688, 4720, 4728, 4732, 4756, 1102; System = 7045 }

$evenements = foreach ($journal in $ids.Keys) {
  Get-WinEvent -FilterHashtable @{ LogName = $journal; Id = $ids[$journal]; StartTime = $depuis } -ErrorAction SilentlyContinue |
    ForEach-Object {
      $xml = [xml]$_.ToXml()
      $data = @{}
      foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
      [pscustomobject]@{
        TimeCreated = $_.TimeCreated.ToString('o')
        Id          = $_.Id
        MachineName = $_.MachineName
        EventData   = $data
      }
    }
}

$evenements | Sort-Object TimeCreated | ConvertTo-Json -Depth 4 | Out-File -FilePath $Sortie -Encoding utf8
Write-Host "$(@($evenements).Count) événements exportés dans $Sortie"
