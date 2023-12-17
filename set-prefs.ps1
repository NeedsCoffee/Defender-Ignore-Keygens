$tcat = Get-MpThreatCatalog | Where-Object {
    $_.ThreatName -like "Behavior:*Keygen*" -or `
    $_.ThreatName -like "HackTool:*Activat*" -or `
    $_.ThreatName -like "HackTool:*KMS*" -or `
    $_.ThreatName -like "HackTool:*Keygen*" -or `
    $_.ThreatName -like "PUA:*Keygen*" -or `
    $_.ThreatName -like "PUA:*Activat*" -or `
    $_.ThreatName -like "PUA:*KMS*" -or `
    $_.ThreatName -like "VirTool:*Keygen*" -or `
    $_.ThreatName -like "VirTool:*KMS*"
}

$prefs = Get-MpPreference
$ttable = [System.Management.Automation.OrderedHashtable]@{}

$a = 0;$prefs.ThreatIDDefaultAction_Ids | %{
    $ttable.Add($_,$prefs.ThreatIDDefaultAction_Actions[$a])
    $a++
}

$tcat | %{
    $ttable[$_.ThreatID] = 6
}

Set-MpPreference -ThreatIDDefaultAction_Ids $ttable.Keys -ThreatIDDefaultAction_Actions $ttable.Values
