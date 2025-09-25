# Subdomain Enumeration
```
ffuf -u http://10.10.11.14 -H "Host: FUZZ.mailing.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac
```

- Find using other methods as well