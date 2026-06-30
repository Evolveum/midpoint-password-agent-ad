# Useful commands

This is list of useful commands during development (mainly inside Windows powershell).

---

Change password of user in Active Directory
```powershell
Set-ADAccountPassword -Identity "<user-identity>" -NewPassword (ConvertTo-SecureString "<new-password>" -AsPlainText -Force) -Reset
```

Password Listener logs
```powershell
Get-EventLog -LogName Application -Source MidPointPasswordAgentListener 
```

Bypass Execution policy of Windows
```powershell
powershell.exe -ExecutionPolicy Bypass -File <file-to-run-with-parameters>
```

LSA properties (check `Notification Packages` field)
```powershell
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa"
```

Search for file with pattern
```powershell
Get-ChildItem -Recurse | Where-Object { $_.Name -like "*<patern>*" }
```

Check if listener module was loaded by LSA
```powershell
Get-Process lsass | Select-Object -ExpandProperty Modules | Where-Object { $_.ModuleName -like '*MidPointPasswordAgent*' }
```

Run installer in logging mode
```powershell
msiexec /i Installer.msi /l*v install.log
```

Run uninstaller in logging mode
```powershell
msiexec /x Installer.msi /l*v uninstall.log
```

Remove installation
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -like '*MidPoint Password Agent for Active Directory*' } | ForEach-Object { msiexec /x $_.PSChildName /quiet }
```

Check installed versions

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -like '*Password Agent*' } | Select-Object DisplayName, DisplayVersion
```
