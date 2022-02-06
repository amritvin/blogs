- - - 
layout: post
title:  "Persistence Techniques"
date:   2021- 011- 01 13:11:40 - 0400
categories: Malaware Persistence Techniques 
- - - 
Run Registry Key
- Done by adding an entry to the run registry keys.
- Executable is added to the run registry key gets executed at system startup.
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
- HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\PrinterSecurityLayer


Scheduled Tasks
- schtasks and at are normally used.
- first creates a xx.exe in the %AllUsersProfile%\WindowsTask\ directory and then invokes cmd.exe,
- cmd "schtasks /create /tn MyApp /tr %AllUsersProfile%\WindowsTask\xx.exe /sc ONSTART /f


Startup Folder
- Done by adding malicious binary in the startup folders.
- The startup folder is looked up and files here are executed after restart(administrator privilege is required)
- C:\%AppData%\Microsoft\Windows\Start Menu\Programs\Startup
- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup


Winlogon Registry Entries
- Done by modifying the registry entries used by the Winlogon process
- winlogon.exe process launches userinit.exe, which runs logon scripts and re-establishes network connections userinit.exe invokes explorer.exe, the default User's shell.
- Winlogon is responsible for interactive user logons and logoffs.
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

Image File Execution Options
- Launches directly under the debugger,its an option for developer to debug and investigate issues in code.
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable name>"
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe\Debugger = C:\Program Files\Internet Explorer\iexplor.exe (when the legitimate iexplore.exe is executed, it will invoke malicious iexplor.ex)


Accessibility Programs
- Accessibility programs can be launched without even logging into the system ie On screen keyboard, Narrator, Magnifier, Speech recognition..etc
- attacker changes accessibility programs (such as sethc.exe and utilman.exe) with cmd.exe having elevated privileges or any Malwares.
- REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f


AppInit_DLLs
- provides a way to load custom DLLs.
- DLLs specified here are loaded into every process that loads User32.dll(User interface)
- To enable this, set the registry key “LoadAppInit_DLLs” to value “1” and add REG Values
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsAppInit_DLLs
- HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs -  %APPDATA%\Intel\Malicious.dll
- HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs – 0x1


DLL Search Order Hijacking
- DLL are loadeded in a specific order.
- OS first checks if the DLL is already loaded in the memory else checks if DLL is in KnownDLLs (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)then will load from System32 directory.
- else DLL will be loaded from directory the application was launched|System32|System|current directory|PATH variables


COM hijacking
- COM is implemented as a client/server framework.
- attacker modifies reg entry of legit COM object.
- COM objects are identified by class identifiers (CLSIDs)
- HKCU\Software\Classes\CLSID\{<CLSIDs>}\InprocServer32\(Default) =C:\Windows\system\malicious.dll


Service
- a program that runs in the background without any user interface.
- attacker gain persitnace by adding malicious program as a service or by modifying an existing service.
- common service by the malware Win32OwnProcess|Win32ShareProcess(svchost.exe)|Kernel Driver Service
- sc utility: A malware can invoke cmd.exe by "%WinDir%\System32\cmd.exe /c sc create update binPath= C:\malware\update.exe start= auto && sc start update


Other Persistence methods
- Screensaver   
- Multi-action Task  
- WMI Event Subscription  
- App cert DLLS  
- Netsh Helper DLLS  
- Time Provider Persistence  
- Port Monitors  
- lsa-as-a-persistence  
- Metasploit Persistence  
- Tortoise SVN: Creates Tortoise SVN hook script   
