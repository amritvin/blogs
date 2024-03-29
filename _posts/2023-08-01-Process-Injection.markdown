---
layout: post
title: "Process Injection"
date: 2023-08-01 13:11:40-0400
categories: Malware Persistence Techniques
---
Process Injection

One of the most well-known ways malware breaks firewalls, perform memory forensics, and slows down reverse engineers is by adding harmful code to legitimate processes and hiding while doing so.

 - Processes are allowed to allocate, read, and write in another process's virtual memory, as well as create new threads, suspend threads, and change these threads' registers, including the instruction pointer (EIP/RIP).
 - Process injection is a technique that's implemented by malware authors so that they can inject code inside another process memory or a complete library (DLL) and execute that code (or the Entry Point of that DLL) inside the space of that process.
 - In Windows 7 and higher, it's not permitted to inject into core Windows processes such as explorer.exe or into other users' processes.
 - But it's still OK to inject in most current user browsers and other current user processes.
 - This technique is legitimately used by multiple endpoint security products to monitor applications and for sandboxing (as we will see in the API hooking section), but it's also misused by malware authors.
 
Objective
 - Bypass trivial firewalls that block internet connections from all applications except browsers or other whitelisted apps.
 - By injecting into one of these whitelisted applications, the malware can communicate with the C&C without any warning or blocking from the firewall.
 - Evade debuggers and other dynamic analysis or monitoring tools by running the malicious code inside another unmonitored and not debugged process.
 - Maintain persistence for fileless malware.
 - By injecting into a background process, the malware can maintain persistence on a server that rarely gets rebooted.
 
DLL injection
 - The Windows operating system allows processes to load dynamic link libraries into other processes for security reasons, sandboxing, or even graphics.
Windows-supported DLL injection
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs – 
This registry entry was one of the most misused registry entries by malware to inject DLL code into other processes and maintain persistence. The libraries included in this path are loaded together with every process that loads user32.dll
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
Libraries in this registry entry are loaded in each process that calls any in below
 - CreateProcess 
 - CreateProcessAsUser 
 - CreateProcessWithLogonW 
 - CreateProcessWithTokenW WinExec
This allows the malware to be injected into most browsers (as many of them create child processes to manage different tabs) and other applications as well. It still requires administrative privileges since HKEY_LOCAL_MACHINE is not writable for normal users on a Windows machine (Vista and above)
HKEY_CURRENT_USER\Software\Classes\\shellex\ContextMenuHandlers 
 - This path loads a shell extension (a DLL file) in order to add additional features to the main Windows shell (explorer.exe). Basically, it loads the malware library as an extension to explorer.exe. This path can be easily created and modified without any administrative privileges
 - This path loads a shell extension (a DLL file) in order to add additional features to the main Windows shell (explorer.exe). Basically, it loads the malware library as an extension to explorer.exe. This path can be easily created and modified without any administrative privileges.
