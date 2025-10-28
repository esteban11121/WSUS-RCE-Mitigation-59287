# Verificación de los puertos de escucha de WSUS (Vector de ataque)
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 8530 -or $_.LocalPort -eq 8531 }