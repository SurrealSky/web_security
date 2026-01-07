资产收集
========================================

主域名/小程序/公众号/APP
----------------------------------------

ENScan
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 项目地址：``https://github.com/wgpsec/ENScan_GO``
+ 默认公司：``./enscan -n 小米``
+ 批量查询：``./enscan -f f.txt``
+ 对外投资占股100%的公司：``./enscan -n 小米 -invest 100``

企查查
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

子域爆破
-----------------------------------------
- `ESD <https://github.com/FeeiCN/ESD>`_
	| ``pip install esd``
	| ``esd -d baidu.com``
- - `wydomain <https://github.com/ring04h/wydomain>`_
- `chaos <https://github.com/projectdiscovery/chaos-client>`_
- `subDomainsBrute <https://github.com/lijiejie/subDomainsBrute>`_
	| ``python3 subDomainsBrute.py baidu.com``
- `broDomain <https://github.com/code-scan/BroDomain>`_
	+ 查询域名注册邮箱,查询备案号
	+ 通过备案号查询域名,反查注册邮箱,注册人
	+ 通过注册人查询到的域名在查询邮箱
	+ 通过上一步邮箱去查询域名
	+ 查询以上获取出的域名的子域名
- `aiodnsbrute <https://github.com/blark/aiodnsbrute>`_
	| ``pip install aiodnsbrute``
	| ``aiodnsbrute -w wordlist.txt -vv -t 1024 domain.com``
- bbot
	+ 项目地址：``https://github.com/blacklanternsecurity/bbot``
	+ 安装：``cd bbot , pip install -e .``
	+ 子域寻找：``bbot -t evilcorp.com -p subdomain-enum`` ，``bbot -t evilcorp.com -p subdomain-enum -rf passive``
	+ 网页爬虫：``bbot -t evilcorp.com -p spider``
	+ 邮箱收集：``bbot -t evilcorp.com -p email-enum``
	+ 网页扫描：``bbot -t www.evilcorp.com -p web-basic`` , ``bbot -t www.evilcorp.com -p web-thorough`` 
	+ 综合扫描：``bbot -t evilcorp.com -p kitchen-sink --allow-deadly`` , ``bbot -t evilcorp.com -p subdomain-enum cloud-enum code-enum email-enum spider web-basic paramminer dirbust-light web-screenshots --allow-deadly``
- subfinder
	+ 安装： ``go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest``
	+ ``subfinder -d yuanqisousou.com -o subdomains.txt``
- Assetfinder
	+ 安装：``go install -v github.com/tomnomnom/assetfinder@latest``
	+ ``assetfinder --subs-only baidu.com``
- Sublist3r
	+ 安装：``git clone https://github.com/aboul3la/Sublist3r.git``
	+ ``python sublist3r.py -v -d example.com``
	+ ``python sublist3r.py -v -d example.com -p 80,443``
	+ 爆破： ``python sublist3r.py -b -d example.com``
	+ ``sublist3r -d example.com -e baidu,yahoo,google,bing,ask,netcraft,virustotal,threatcrowd,crtsh,passivedns -v -o sublist3r.txt``
- amass(需要配置api-key)
	+  配置方法： ``https://medium.com/offensive-black-hat-hacking-security/amass-new-config-file-update-e95d09b6eb70``
	+ 下载安装：``https://github.com/owasp-amass/amass/releases``
	+ ``amass enum -passive -d example.com | cut -d']' -f 2 | awk '{print $1}' | sort -u > amass.txt``
- virustotal
	+ ``curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com&apikey=[api-key]" | jq -r '.subdomains[]' > vt.txt``
- urlscan.io
	+ ``curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=10000" | jq -r '.results[]?.page?.domain' | sort -u > urlscan.txt``
- alienvault OTX
	+ ``curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list?limit=500&page=1" | jq -r '.subdomains[]' | sed 's/\.example\.com$//g' > otx.txt``
- crtsh
	+ ``curl -s https://crt.sh\?q\=\example.com\&output\=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' >crtsh.txt``
- Wayback Machine
	+ ``curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u > wayback.txt``
- FFUF Subdomain Bruteforce
	+ 安装：``go install -v github.com/ffuf/ffuf@latest``
	+ ``ffuf -u "https://FUZZ.example.com" -w wordlist.txt -mc 200,301,302``
- 相关域名生成
	+ alterx
		- 可根据一个域名列表生成一个子域名列表，即字典
		- 安装：``go install -v github.com/alterx/alterx/cmd/alterx@latest``
		- ``subfinder -d example.com | alterx | dnsx``
		- ``echo example.com | alterx -enrich | dnsx``
		- ``echo example.com | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | dnsx``
- 子域名处理
	+ 合并去重： ``cat *.txt | sort -u > final.txt``

综合资产收集
----------------------------------------
+ magicRecon
	- 项目地址：``https://github.com/robotshell/magicRecon``
	- all: ``./magicrecon.sh -d domain.com -a``
	- 被动扫描： ``./magicrecon.sh -l domainlist.txt -p``
	- 主动扫描： ``./magicrecon.sh -d domain.com -x``
	- 递归： ``./magicrecon.sh -d domain.com -r``
	- 递归漏扫： ``./magicrecon.sh -d domain.com -r -v``
	- 泛域名: ``./magicrecon.sh -w domain.com``
	- 泛域名递归漏扫: ``./magicrecon.sh -w domain.com -m``
+ OneForAll(需要配置api-key)
	- 项目地址：``https://github.com/shmilylty/OneForAll``
	- ``python3 oneforall.py --target baidu.com run``
	- ``python3 oneforall.py --targets ./domains.txt run``

IP收集
----------------------------------------
+ ASN Discovery
	- 安装： ``go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest``
	- ``asnmap -d example.com | dnsx -silent -resp-only``
+ amass
	- Amass Intel by Organization: ``amass intel -org "organization_name"``
	- Amass Intel by CIDR:  ``amass intel -active -cidr 159.69.129.82/32``
	- Amass Intel by ASN: ``amass intel -active -asn [asnno]``
+ VirusTotal IP Lookup: ``curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com&apikey=[api-key]" | jq -r '.. | .ip_address? // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'``
+ AlienVault OTX: ``curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/example.com/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'``
+ URLScan.io: ``curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=10000" | jq -r '.results[]?.page?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'``
+ Shodan SSL Search: ``shodan search Ssl.cert.subject.CN:"example.com" 200 --fields ip_str | httpx -sc -title -server -td``

CDN判别
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 在线多地超级ping
	+ 多地ping得到不同的IP地址，基本判断为开启了CDN。
	+ ``https://ping.chinaz.com/``
- dig/nslookup
	+ 多个IP则可能开启了CDN。
- DNS历史记录查询
	+ ``https://www.dnsdb.io/zh-cn/`` 
	+ ``https://viewdns.info/`` 
- cdncheck
	+ 安装：``go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest``
	+ 示例
		::
		
			echo hackerone.com| cdncheck -resp
			subfinder -d hackerone.com| cdncheck -resp