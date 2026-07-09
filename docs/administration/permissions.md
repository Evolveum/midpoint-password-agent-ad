## Application permissions ##

Application has 2 parts:

Listener: Windows LSA Password Notification Filter, DLL file is copied to System32 folder. DLL is executed under SYSTEM account.


Sender: Windows Service, running under its own service account created during installation.

Application runtime data are stored in folder provided during installation. (ProgramData by default). Inside this folder are 3 subfolders:
```Logs``` - Log files.

```Config``` - Configuration files.

```Data``` - Intermediate files keeping track of password changes and metadata. Administrators should never update content of these files.

Besides application data folder, application data are stored also in registry folder ```HKEY_LOCAL_MACHINE\SOFTWARE\Evolveum\MidPointPasswordAgent``` created during installation.


During installation, new group ```MidPoint Password Agent Managers``` is created. 
In order to provide adequate security, the only users with full access to the data files managed by the agent are those in `MidPoint Password Agent Managers` group. (Even `Administrators` are limited to reading the log files, nothing more.) So, please add designated user(s) to that group in order to be able to manage the agent.


In this table are listed default permissions set during installation:

Account/Account group|Win registry folder|/Logs|/Data|/Config
---|--|---|---|---
System|read/write|read/write|read/write|read/write
Service Sender account|read/write|read/write|read/write|read
Administrators|❌|read|❌|❌|
MidPoint Password Agent Managers|read|read/delete|read/write|read/write

