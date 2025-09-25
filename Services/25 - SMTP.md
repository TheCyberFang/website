#oscp #smtp

# To Check
```
enumerate usernames
check mails
```

# User Enumeration
```
smtp-user-enum -M VRFY -U <list of users> -t <ip>
smtp-user-enum -M EXPN -U <list of users> -t <ip>
smtp-user-enum -M RCPT -U <list of users> -t <ip>
smtp-user-enum -M EXPN -U <list of users> -t <ip> -D <domain>
```

# Login
```
telnet 10.10.10.10 25
AUTH <username>   # Auth or Login or User
PASS <password>
LIST
```

# HTB Box
- Mailing