信息收集
----------------------------------------

漏洞查询
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- searchsploit
	| ``更新：searchsploit -u`` 
	| ``下载：searchsploit -m php/webapps/7185.php`` 

存活主机扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- fping
	 | ``fping -a -g 14.215.177.1 14.215.177.100``
	 | ``fping -a -g 14.215.177.0/24``
- masscan
	| ``masscan --ping 28.41.0.0/16 --rate 1000000``
	| 心脏出血漏洞:``masscan -p443 28.41.0.0/16 --banners --heartbleed``
	| ``masscan 192.168.1.1/24 --ports 445`` 
	| nmap -sP 28.41.0.0/16
- nmap
	| ``nmap -sP 192.168.0.1/24`` 

子域爆破
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `subDomainsBrute <https://github.com/lijiejie/subDomainsBrute>`_
- `wydomain <https://github.com/ring04h/wydomain>`_
- `broDomain <https://github.com/code-scan/BroDomain>`_
- `ESD <https://github.com/FeeiCN/ESD>`_
- `aiodnsbrute <https://github.com/blark/aiodnsbrute>`_
- `OneForAll <https://github.com/shmilylty/OneForAll>`_
- `subfinder <https://github.com/subfinder/subfinder>`_

域名获取
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `the art of subdomain enumeration <https://github.com/appsecco/the-art-of-subdomain-enumeration>`_
- `sslScrape <https://github.com/cheetz/sslScrape/blob/master/sslScrape.py>`_
- `aquatone <https://github.com/michenriksen/aquatone>`_ A Tool for Domain Flyovers

弱密码爆破
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `hydra(九头蛇) <https://github.com/vanhauser-thc/thc-hydra>`_
	 | ``查看模块用法：hydra -U http-form-post``
	 | ``smb破解：hydra -l Administrator -P pass.txt smb://192.168.47`` 
	 | ``3389破解：hydra -l Administrator -P pass.txt rdp://192.168.47.124 -t 1 -V`` 
	 | ``ssh破解：hydra -l msfadmin -P pass.txt ssh://192.168.47.133 -vV`` 
	 | ``ftp破解：hydra -L user.txt -P pass.txt ftp://192.168.47.133 -s 21 -e nsr -t 1 -vV`` 
	 | ``HTTP服务器身份验证破解：hydra -L user.txt -P pass.txt 192.168.0.105 http-get``
	 | ``hydra -l admin -P /usr/share/wordlists/metasploit/unix_users.txt 172.16.100.103 http-get-form \"/dvwa/login.php:username=^USER^&password=^PASS^&login=login:Login failed\" -V``

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
				
- `medusa(美杜莎) <https://github.com/jmk-foofus/medusa>`_
	 | ``查询模块用法：medusa -M http -q``
	 | ``medusa -H ssh1.txt -u root -P passwd.txt -M ssh``
	 | ``medusa –M http -h 192.168.10.1 -u admin -P /usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/passwds/john.txt -e ns -n 80 -F``

		::
		
				-M http 允许我们指定模块。
				-h 192.168.10.1 允许我们指定主机。
				-u admin 允许我们指定用户。
				-P [location of password list] 允许我们指定密码列表的位置。
				-e ns 允许我们指定额外的密码检查。 ns 变量允许我们使用用户名作为密码，并且使用空密码。
				-n 80 允许我们指定端口号码。
				-F 允许我们在成功找到用户名密码组合之后停止爆破。
				注：此模块是破解HTTP服务器身份验证。

	 | ``medusa -M web-form -q``
	 
	 ::
	 
			注：此模块是破解HTTP协议表单数据。

- `htpwdScan <https://github.com/lijiejie/htpwdScan>`_
	 | ``python htpwdScan.py -f dvwa.txt -d password=/usr/share/wordlists/metasploit/unix_users.txt  -err=\"password incorrect\"``
	 | ``python htpwdScan.py -d passwd=password.txt -u=\"http://xxx.com/index.php?m=login&username=test&passwd=test\" -get -err=\"success\":false\"``
- `patator <https://github.com/lanjelot/patator>`_
- ncrack
	
	::
	
			注：HTTP破解支持的是HTTP服务器身份验证。

路径及文件扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `dirmap <https://github.com/H4ckForJob/dirmap.git>`_
	``git clone https://github.com/H4ckForJob/dirmap.git``
	``python3 -m pip install -r requirement.txt``
- dirb
	使用字典穷举特定扩展名文件:
	``dirb http://172.16.100.102 /usr/share/wordlists/dirb/common.txt -X .pcap`` 
- wfuzz
	使用字典穷举特定扩展名文件：
	``wfuzz -w /usr/share/wordlists/wfuzz/general/megabeast.txt --hc 404 http://172.16.100.102/FUZZ.sh``
- `dirsearch <https://github.com/maurosoria/dirsearch>`_
- nikto
	+ 常规扫描：nikto -host/-h http://www.example.com
	+ 指定端口(https)：nikto -h http://www.example.com -p 443 -ssl
	+ 指定目录：nikto -host/-h http://www.example.com -c /dvma
	+ 绕过IDS检测：nikto -host/-h http://www.example.com -evasion
	+ Nikto配合Nmap扫描：nmap -p80 x.x.x.x -oG - \|nikto -host - 
	+ 使用代理：nikto -h URL -useproxy http://127.0.0.1:1080
- `GOBUSTER <https://github.com/OJ/gobuster>`_
- `bfac <https://github.com/mazen160/bfac>`_
- `ds_store_exp <https://github.com/lijiejie/ds_store_exp>`_
- `cansina <https://github.com/deibit/cansina>`_
- `weakfilescan <https://github.com/ring04h/weakfilescan>`_
- `DirBrute <https://github.com/Xyntax/DirBrute>`_
- auxiliary/scanner/http/dir_scanner
- auxiliary/scanner/http/dir_listing
- auxiliary/scanner/http/brute_dirs
- DirBuster
- 御剑

路径爬虫
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `crawlergo <https://github.com/0Kee-Team/crawlergo>`_ A powerful dynamic crawler for web vulnerability scanners

指纹识别
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Wappalyzer <https://github.com/AliasIO/Wappalyzer>`_
- `Wordpress Finger Print <https://github.com/iniqua/plecost>`_
- `CMS指纹识别 <https://github.com/n4xh4ck5/CMSsc4n>`_
- `JA3 <https://github.com/salesforce/ja3>`_ is a standard for creating SSL client fingerprints in an easy to produce and shareable way
- `Joomla Vulnerability Scanner <https://github.com/rezasp/joomscan>`_
- `Drupal enumeration & exploitation tool <https://github.com/immunIT/drupwn>`_
- wpscan：wordpress CMS识别
	``插件漏洞:wpscan --url https://www.xxxxx.wiki/ --enumerate vp`` 
	``主题漏洞:wpscan --url https://www.xxxxxx.wiki --enumerate vt`` 
	``枚举用户:wpscan --url https://www.xxxxxxx.wiki/ --enumerate u`` 
	``穷举密码:wpscan --url https://www.xxxxxxx.wiki/ --enumerate u --wordlist /root/wordlist.txt`` 
- `云悉指纹 <https://www.yunsee.cn/>`_
- `whatweb <https://github.com/urbanadventurer/whatweb>`_
- `Webfinger <https://github.com/se55i0n/Webfinger>`_
- `CMSeek <https://github.com/Tuhinshubhra/CMSeeK>`_
- `TPscan <https://github.com/Lucifer1993/TPscan>`_ 一键ThinkPHP漏洞检测
- `dedecmscan <https://github.com/lengjibo/dedecmscan>`_ 织梦全版本漏洞扫描

Waf指纹
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `identywaf <https://github.com/enablesecurity/identywaf>`_
- `wafw00f <https://github.com/enablesecurity/wafw00f>`_
- `WhatWaf <https://github.com/Ekultek/WhatWaf>`_

端口扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `nmap <https://github.com/nmap/nmap>`_
	``范围扫描：nmap 192.168.0.100-110`` 
	``网段扫描：nmap 192.168.0.1/24`` 
	``文件列表：nmap -iL /root/target.txt`` 
	``指定端口：nmap 192.168.0.101 -p 80,8080,3306,3389`` 
	``路由追踪：nmap --traceroute 192.168.0.101`` 
	``服务版本:nmap -sV 192.168.0.101`` 
	``操作系统版本:nmap -O 192.168.0.101`` 
	``探测防火墙:nmap -sF -T4 192.168.0.101`` 
	``弱口令扫描:nmap --script=auth 192.168.0.101`` 
	``暴力破解(数据库,SMB,SNMP):nmap --script=brute 192.168.0.101`` 
	``检查常见漏洞:nmap --script=vuln 192.168.0.101`` 
	``默认脚本扫描:nmap --script=default 192.168.0.101 或者 nmap -sC 192.168.0.101`` 
	``局域网服务探测：nmap -n -p445 --script=broadcast 192.168.137.4`` 
	``smb破解:nmap --script=smb-brute.nse 192.168.137.4`` 
	``smb字典破解:nmap --script=smb-brute.nse --script-args=userdb=/var/passwd,passdb=/var/passwd 192.168.137.4`` 
	``smb漏洞：nmap --script=smb-check-vulns.nse --script-args=unsafe=1 192.168.137.4`` 
	``查看共享目录:nmap -p 445 --script smb-ls --script-args 'share=e$,path=\,smbuser=test,smbpass=test' 192.168.137.4`` 
- `zmap <https://github.com/zmap/zmap>`_
- `masscan <https://github.com/robertdavidgraham/masscan>`_
- `ShodanHat <https://github.com/HatBashBR/ShodanHat>`_
- DNS ``dnsenum nslookup dig fierce``
- SNMP ``snmpwalk``

DNS数据查询
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `VirusTotal <https://www.virustotal.com/>`_
- `PassiveTotal <https://passivetotal.org>`_
- `DNSDB <https://www.dnsdb.info/>`_
- `sitedossier <http://www.sitedossier.com/>`_

DNS关联
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Cloudflare Enumeration Tool <https://github.com/mandatoryprogrammer/cloudflare_enum>`_
- `amass <https://github.com/caffix/amass>`_
- `Certificate Search <https://crt.sh/>`_

搜索引擎查询
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Censys <https://censys.io>`_
- `Shodan <https://www.shodan.io/>`_
- `Zoomeye <https://www.zoomeye.org/>`_
- `fofa <https://fofa.so/>`_
- `scans <https://scans.io/>`_
- `Just Metadata <https://github.com/FortyNorthSecurity/Just-Metadata>`_
- `publicwww - Find Web Pages via Snippet <https://publicwww.com/>`_

字典
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Blasting dictionary <https://github.com/rootphantomer/Blasting_dictionary>`_
- `pydictor <https://github.com/LandGrey/pydictor>`_
- `Probable Wordlists <https://github.com/berzerk0/Probable-Wordlists>`_ Wordlists sorted by probability originally created for password generation and testing
- `Common User Passwords Profiler <https://github.com/Mebus/cupp>`_
- `chrome password grabber <https://github.com/x899/chrome_password_grabber>`_
- kali自带字典：/usr/share/wordlists/
- cewl字典生成工具
	+ 根据url爬取并生成字典：cewl http://www.ignitetechnologies.in/ -w dict.txt
	+ 生成长度最小限制的字典：cewl http://www.ignitetechnologies.in/ -m 9
	+ 爬取email地址：cewl http://www.ignitetechnologies.in/ -n -e
	+ 生成包含数字和字符的字典：cewl http://testphp.vulnweb.com/ --with-numbers
	+ 设置代理：cewl --proxy_host 192.168.1.103 --proxy_port 3128 -w dict.txt http://192.168.1.103/wordpress/

Samba
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- enum4linux
- smbclient
	``查看共享文件夹：smbclient -L //192.168.1.110 -U Jerry`` 
	``进入共享文件夹：smbclient //192.168.1.110/share -U Jerry`` 
	``上传文件：smbclient //192.168.1.110/share -c 'cd /home/dulingwen/Downloads; put shaolin.jpg'`` 
	``smb直接上传：put flower.jpg`` 
	``smb下载文件：get flower.jpg`` 
	
web破解
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Brute_force <..//_static//Brute_force.py>`_