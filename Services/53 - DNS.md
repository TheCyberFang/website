#oscp #dns

# To Check
```
find ip addresses
find mx records
perform zone transfer
find all subdomains
```

# Host Lookup
```
host -t ns <domain>
```

# DNS IP Lookup
```
dig a <domain> @<name server>
```

# Perform MX Lookup
```
dig mx <domain> @<name server>
```

# DNS Zone Transfer
```
dig axfr <domain> @<name server>
dnsrecon -d <domain> -t axfr
```

# DNS Brute Force
```
dnsrecon -d <domain> -D <wordlist> -t brt
```

# Automated
```
dnsenum <domain>
```