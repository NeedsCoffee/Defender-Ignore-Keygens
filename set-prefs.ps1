# collect threats to exclude from the threat catalogue, filtering using regex
$tcat = Get-MpThreatCatalog | ? ThreatName -Match '(Behavior|HackTool|PUA|VirTool)\:.*(KeyGen|Activat|KMS).*'

# populate ordered hashtable with ignorable threats from the catalogue
$ttable = [System.Management.Automation.OrderedHashtable]@{}
$tcat | %{
    $ttable[$_.ThreatID] = 6
}

# update hashtable with existing config from current defender prefs so they aren't overridden
$prefs = Get-MpPreference
$a = 0
$prefs.ThreatIDDefaultAction_Ids | %{
    $ttable[$_] = $prefs.ThreatIDDefaultAction_Actions[$a]
    $a++
}

# set the new combined prefs into defender
Set-MpPreference -ThreatIDDefaultAction_Ids $ttable.Keys -ThreatIDDefaultAction_Actions $ttable.Values
