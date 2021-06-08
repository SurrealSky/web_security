信息收集
----------------------------------------

漏洞查询
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- searchsploit
	+ ``更新：searchsploit -u`` 
	+ ``下载：searchsploit -m php/webapps/7185.php`` 

存活主机扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- fping
	+ ``fping -a -g 14.215.177.1 14.215.177.100``
	+ ``fping -a -g 14.215.177.0/24``
- masscan
	+ ``masscan --ping 28.41.0.0/16 --rate 1000000``
	+ ``心脏出血漏洞：masscan -p443 28.41.0.0/16 --banners --heartbleed``
	+ ``masscan 192.168.1.1/24 --ports 445`` 
	+ ``nmap -sP 28.41.0.0/16``
- nmap
	+ ``nmap -sP 192.168.0.1/24`` 
- arp-scan
	+ ``arp-scan -l`` 

IP信息
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- dig
	+ ``查询A记录：dig baidu.com A +noall +answer``
	+ ``查询MX记录：dig baidu.com MX +noall +answer``
	+ ``查询权威DNS：dig baidu.com NS +noall +answer``
	+ ``查询所有记录：dig baidu.com ANY +noall +answer``
	+ ``快速回答：+short``
	+ ``IP反查：dig -x 192.168.17.28 +short``
	+ ``指定域名服务器：dig baidu.com ANY @8.8.8.8``
	+ ``解析过程：dig www.ustc.edu.cn +trace``
- nslookup
	+ ``查询A记录：nslookup -q=A baidu.com``
	+ ``指定域名服务器：nslookup baidu.com -type=any 8.8.8.8``
- IP无法访问页面
	+ 服务器开启虚拟主机
		``如：www.ustc.edu.cn->218.22.21.21,页面显示400 Unknown Virtual Host``
	+ 反向代理服务器
		``如：nginx``

CDN判别
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 在线多地超级ping
	+ 多地ping得到不同的IP地址，基本判断为开启了CDN。
- dig/nslookup
	+ 多个IP则可能开启了CDN。
- DNS历史记录查询
	+ ``https://www.dnsdb.io/zh-cn/`` 
	+ ``https://viewdns.info/`` 
- 查找动态内容
	+ 有的cdn只缓存静态内容
	+ 注册登陆之类的服务器IP
- 二级域名
	+ 搜索二级域名IP
- `securitytrails <https://securitytrails.com>`_

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
	+ ``git clone https://github.com/H4ckForJob/dirmap.git``
	+ ``python3 -m pip install -r requirement.txt``
	+ ``扫描单个目标：python3 dirmap.py -i https://site.com -lcf`` 
	+ ``扫描多个目标：python3 dirmap.py -iF urls.txt -lcf`` 

	::
	
			#递归扫描处理配置
			[RecursiveScan]
			#是否开启递归扫描:关闭:0;开启:1
			conf.recursive_scan = 0
			#遇到这些状态码，开启递归扫描。默认配置[301,403]
			conf.recursive_status_code = [301,403]
			#设置排除扫描的目录。默认配置空。其他配置：e.g:['/test1','/test2']
			#conf.exclude_subdirs = ['/test1','/test2']
			conf.exclude_subdirs = ""
			 
			#扫描模式处理配置(4个模式，1次只能选择1个)
			[ScanModeHandler]
			#字典模式:关闭:0;单字典:1;多字典:2
			conf.dict_mode = 1
			#单字典模式的路径
			conf.dict_mode_load_single_dict = "dict_mode_dict.txt"
			#多字典模式的路径，默认配置dictmult
			conf.dict_mode_load_mult_dict = "dictmult"
			#爆破模式:关闭:0;开启:1
			conf.blast_mode = 0
			#生成字典最小长度。默认配置3
			conf.blast_mode_min = 3
			#生成字典最大长度。默认配置3
			conf.blast_mode_max = 3
			#默认字符集:a-z。暂未使用。
			conf.blast_mode_az = "abcdefghijklmnopqrstuvwxyz"
			#默认字符集:0-9。暂未使用。
			conf.blast_mode_num = "0123456789"
			#自定义字符集。默认配置"abc"。使用abc构造字典
			conf.blast_mode_custom_charset = "abc"
			#自定义继续字符集。默认配置空。
			conf.blast_mode_resume_charset = ""
			#爬虫模式:关闭:0;开启:1
			conf.crawl_mode = 0
			#解析robots.txt文件。暂未实现。
			conf.crawl_mode_parse_robots = 0
			#解析html页面的xpath表达式
			conf.crawl_mode_parse_html = "//*/@href | //*/@src | //form/@action"
			#是否进行动态爬虫字典生成:关闭:0;开启:1
			conf.crawl_mode_dynamic_fuzz = 0
			#Fuzz模式:关闭:0;单字典:1;多字典:2
			conf.fuzz_mode = 0
			#单字典模式的路径。
			conf.fuzz_mode_load_single_dict = "fuzz_mode_dir.txt"
			#多字典模式的路径。默认配置:fuzzmult
			conf.fuzz_mode_load_mult_dict = "fuzzmult"
			#设置fuzz标签。默认配置{dir}。使用{dir}标签当成字典插入点，将http://target.com/{dir}.php替换成http://target.com/字典中的每一行.php。其他配置：e.g:{dir};{ext}
			#conf.fuzz_mode_label = "{ext}"
			conf.fuzz_mode_label = "{dir}"
			 
			#处理payload配置。暂未实现。
			[PayloadHandler]
			 
			#处理请求配置
			[RequestHandler]
			#自定义请求头。默认配置空。其他配置：e.g:test1=test1,test2=test2
			#conf.request_headers = "test1=test1,test2=test2"
			conf.request_headers = ""
			#自定义请求User-Agent。默认配置chrome的ua。
			conf.request_header_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
			#自定义请求cookie。默认配置空，不设置cookie。其他配置e.g:cookie1=cookie1; cookie2=cookie2;
			#conf.request_header_cookie = "cookie1=cookie1; cookie2=cookie2"
			conf.request_header_cookie = ""
			#自定义401认证。暂未实现。因为自定义请求头功能可满足该需求(懒XD)
			conf.request_header_401_auth = ""
			#自定义请求方法。默认配置get方法。其他配置：e.g:get;head
			#conf.request_method = "head"
			conf.request_method = "get"
			#自定义每个请求超时时间。默认配置3秒。
			conf.request_timeout = 3
			#随机延迟(0-x)秒发送请求。参数必须是整数。默认配置0秒，无延迟。
			conf.request_delay = 0
			#自定义单个目标，请求协程线程数。默认配置30线程
			conf.request_limit = 30
			#自定义最大重试次数。暂未实现。
			conf.request_max_retries = 1
			#设置持久连接。是否使用session()。暂未实现。
			conf.request_persistent_connect = 0
			#302重定向。默认False，不重定向。其他配置：e.g:True;False
			conf.redirection_302 = False
			#payload后添加后缀。默认空，扫描时，不添加后缀。其他配置：e.g:txt;php;asp;jsp
			#conf.file_extension = "txt"
			conf.file_extension = ""
			 
			#处理响应配置
			[ResponseHandler]
			#设置要记录的响应状态。默认配置[200]，记录200状态码。其他配置：e.g:[200,403,301]
			#conf.response_status_code = [200,403,301]
			conf.response_status_code = [200]
			#是否记录content-type响应头。默认配置1记录
			#conf.response_header_content_type = 0
			conf.response_header_content_type = 1
			#是否记录页面大小。默认配置1记录
			#conf.response_size = 0
			conf.response_size = 1
			#是否自动检测404页面。默认配置True，开启自动检测404.其他配置参考e.g:True;False
			#conf.auto_check_404_page = False
			conf.auto_check_404_page = True
			#自定义匹配503页面正则。暂未实现。感觉用不着，可能要废弃。
			#conf.custom_503_page = "page 503"
			conf.custom_503_page = ""
			#自定义正则表达式，匹配页面内容
			#conf.custom_response_page = "([0-9]){3}([a-z]){3}test"
			conf.custom_response_page = ""
			#跳过显示页面大小为x的页面，若不设置，请配置成"None"，默认配置“None”。其他大小配置参考e.g:None;0b;1k;1m
			#conf.skip_size = "0b"
			conf.skip_size = "None"
			 
			#代理选项
			[ProxyHandler]
			#代理配置。默认设置“None”，不开启代理。其他配置e.g:{"http":"http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}
			#conf.proxy_server = {"http":"http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}
			conf.proxy_server = None
			 
			#Debug选项
			[DebugMode]
			#打印payloads并退出
			conf.debug = 0
			 
			#update选项
			[CheckUpdate]
			#github获取更新。暂未实现。
			conf.update = 0

- dirb
	+ ``穷举特定扩展名文件：dirb http://172.16.100.102 /usr/share/wordlists/dirb/common.txt -X .pcap`` 
	+ ``使用代理：dirb http://192.168.1.116  -p 46.17.45.194:5210`` 
	+ ``添加UA和cookie：dirb http://192.168.1.116 -a "***" -c "***"`` 
	+ ``扫描目录：dirb http://192.168.91.133 common.txt -N 404`` 
- wfuzz
	+ ``字典路径：/usr/share/wfuzz/wordlist`` 
	+ ``爆破文件：wfuzz -w /usr/share/wordlists/wfuzz/general/megabeast.txt --hc 404 http://172.16.100.102/FUZZ.sh`` 
	+ ``爆破目录：wfuzz -w wordlist http://192.168.91.137/FUZZ`` 
	+ ``枚举参数值：wfuzz -z range,000-999 http://127.0.0.1/getuser.php?uid=FUZZ`` 
	+ ``爆破HTTP表单：wfuzz -w userList -w pwdList -d "username=FUZZ&password=FUZ2Z" http://127.0.0.1/login.php`` 
	+ ``携带cookie：wfuzz -z range,000-999 -b session=session -b cookie=cookie http://127.0.0.1/getuser.php?uid=FUZZ`` 
	+ ``指定HTTP头：wfuzz -z range,0000-9999 -H "X-Forwarded-For: FUZZ" http://127.0.0.1/get.php?userid=666`` 
	+ ``HTTP请求方法：wfuzz -z list,"GET-POST-HEAD-PUT" -X FUZZ http://127.0.0.1/`` 
		::
		
			-z list可以自定义一个字典列表（在命令中体现），以-分割；
			-X参数是指定HTTP请求方法类型，因为这里要测试HTTP请求方法，后面的值为FUZZ占位符。
	+ ``使用代理：wfuzz -w wordlist -p 127.0.0.1:1087:SOCKS5 URL/FUZZ`` 
	+ ``--hc/hl/hw/hh N[,N]+：隐藏指定的代码/行/字/字符的responsnes。`` 
		::
		
			wfuzz -w megabeast.txt --hc=404 http://192.168.91.133/FUZZ
	+ ``--hs regex：在响应中隐藏具有指定正则表达式的响应。`` 
	+ ``zip并列迭代：wfuzz -z range,0-9 -w dict.txt -m zip http://127.0.0.1/ip.php?FUZZ=FUZ2Z`` 
		::
		
			设置了两个字典。两个占位符，一个是range模块生成的0、1、2、3、4、5、6、7、8、
			9,10个数字，一个是外部字典dict.txt的9行字典，使用zip迭代器组合这两个字典发送。
			zip迭代器的功能：字典数相同、一一对应进行组合，如果字典数不一致则多余的抛弃
			掉不请求，如上命令结果就是数字9被抛弃了因为没有字典和它组合。
	+ ``chain组合迭代：wfuzz -z range,0-9 -w dict.txt -m chain http://127.0.0.1/ip.php?FUZZ`` 
		::
		
			设置了两个字典，一个占位符FUZZ，使用chain迭代器组合这两个字典发送。
			这个迭代器是将所有字典全部整合（不做组合）放在一起然后传入占位符FUZZ中。
			顺序19种。
	+ ``product交叉迭代：wfuzz -z range,0-2 -w dict.txt -m product http://127.0.0.1/ip.php?FUZZ=FUZ2Z`` 
		::
		
			设置了两个字典，两个占位符，一个是range模块生成的0、1、2这3个数字，一个是外部字典
			dict.txt的3行字典，使用product迭代器组合这两个字典发送，9种组合。
	+ ``使用Encoders：wfuzz -z file --zP fn=wordlist,encoder=md5 URL/FUZZ`` 
		::
		
			简写命令：wfuzz -z file,wordlist,md5 URL/FUZZ
	+ ``组合Encoder：wfuzz -z file,dict.txt,md5-base64 http://127.0.0.1/ip.php\?FUZZ`` 
		::
		
			多个转换，使用一个-号分隔的列表.
			相当于组合，分别进行MD5模糊，和base64模糊测试。
	+ ``多次Encoder：wfuzz -z file,dict.txt,base64@md5 http://127.0.0.1/ip.php\?FUZZ`` 
		::
		
			多次转换，使用一个@号分隔的列表.
			按照从右往左顺序对字典数据进行多次转换。
	+ 注：FUZZ位置即为需要模糊测试。
- `dirsearch <https://github.com/maurosoria/dirsearch>`_
	+ -u 指定网址
	+ -e 指定网站语言
	+ -w 指定字典
	+ -r 递归目录（跑出目录后，继续跑目录下面的目录）
	+ -random-agents 使用随机UA
	+ ``python3 dirsearch.py -u http://172.16.100.104 -e php`` 
- nikto
	+ ``常规扫描：nikto -host/-h http://www.example.com`` 
	+ ``指定端口(https)：nikto -h http://www.example.com -p 443 -ssl`` 
	+ ``指定目录：nikto -host/-h http://www.example.com -c /dvma`` 
	+ ``绕过IDS检测：nikto -host/-h http://www.example.com -evasion`` 
	+ ``Nikto配合Nmap扫描：nmap -p80 x.x.x.x -oG - \|nikto -host -`` 
	+ ``使用代理：nikto -h URL -useproxy http://127.0.0.1:1080`` 
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
- `TPscan.jar <https://github.com/tangxiaofeng7/TPScan>`_ ThinkPHP漏洞扫描
- `dedecmscan <https://github.com/lengjibo/dedecmscan>`_ 织梦全版本漏洞扫描

Waf指纹
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `identywaf <https://github.com/enablesecurity/identywaf>`_
- `wafw00f <https://github.com/enablesecurity/wafw00f>`_
- `WhatWaf <https://github.com/Ekultek/WhatWaf>`_
- nmap脚本
	+ ``--script=http-waf-detect``
	+ ``--script=http-waf-fingerprint``
- sqlmap
	+ ``sqlmap -u “www.xxx.com/xxx?id=1” --identify-waf``

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