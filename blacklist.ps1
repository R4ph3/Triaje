$blacklistServers = @(
"bl.emailbasura.org"
"bogons.cymru.com"
"pbl.spamhaus.org"
"rbl.megarbl.net"
"zen.spamhaus.org"
"dyna.spamrats.com"
)


foreach ($IP in Get-Content .\target-ips.txt) {
$reversedIP = ($IP -split '\.')[3..0] -join '.'
$blacklistedOn = @()
foreach ($server in $blacklistServers) {
$fqdn = "$reversedIP.$server"
try
{
$null = [System.Net.Dns]::GetHostEntry($fqdn)
$blacklistedOn += $server
}
catch { }
}
if ($blacklistedOn.Count -gt 0) {
(write-output "$IP está en la blacklist de estos servidores: $($blacklistedOn -join ', ')")
#variable store value sent by the $blackliston
$finaltext = "$IP está en la blacklist de estos servidores: $($blacklistedOn -join ', ')"
}
else { (Write-Output "$IP esta OK")}
}
