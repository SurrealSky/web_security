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
- OneForAll
	+ 项目地址：``https://github.com/shmilylty/OneForAll``
	+ ``python3 oneforall.py --target baidu.com run``
	+ ``python3 oneforall.py --targets ./domains.txt run``
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
- alterx
	+ 子域名枚举工具
	+ 可根据一个域名列表生成一个子域名列表，即字典
	+ 安装：``go install -v github.com/alterx/alterx/cmd/alterx@latest``
- `wydomain <https://github.com/ring04h/wydomain>`_
- `chaos <https://github.com/projectdiscovery/chaos-client>`_

CDN判别
----------------------------------------
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