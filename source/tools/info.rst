信息收集
----------------------------------------

漏洞查询
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- searchsploit

存活主机扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- fping
	 | ``fping -a -g 14.215.177.1 14.215.177.100``
	 | ``fping -a -g 14.215.177.0/24``

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
- `hydra <https://github.com/vanhauser-thc/thc-hydra>`_
- `medusa <https://github.com/jmk-foofus/medusa>`_
- `htpwdScan <https://github.com/lijiejie/htpwdScan>`_
- `patator <https://github.com/lanjelot/patator>`_

路径及文件扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `weakfilescan <https://github.com/ring04h/weakfilescan>`_
- `DirBrute <https://github.com/Xyntax/DirBrute>`_
- `dirmap <https://github.com/H4ckForJob/dirmap.git>`_
	``git clone https://github.com/H4ckForJob/dirmap.git``
	``python3 -m pip install -r requirement.txt``
- `cansina <https://github.com/deibit/cansina>`_
- DirBuster
- dirb
	使用字典穷举特定扩展名文件:
	``dirb http://172.16.100.102 /usr/share/wordlists/dirb/common.txt -X .pcap`` 
- wfuzz
	使用字典穷举特定扩展名文件：
	``wfuzz -w /usr/share/wordlists/wfuzz/general/megabeast.txt --hc 404 http://172.16.100.102/FUZZ.sh``
- `dirsearch <https://github.com/maurosoria/dirsearch>`_
- `bfac <https://github.com/mazen160/bfac>`_
- `ds_store_exp <https://github.com/lijiejie/ds_store_exp>`_
- nikto
- auxiliary/scanner/http/dir_scanner
- auxiliary/scanner/http/dir_listing
- auxiliary/scanner/http/brute_dirs
- `GOBUSTER <https://github.com/OJ/gobuster>`_
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

Samba
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- enum4linux
- smbclient
	``查看共享文件夹：smbclient -L //192.168.1.110 -U Jerry`` 
	``进入共享文件夹：smbclient //192.168.1.110/share -U Jerry`` 
	``上传文件：smbclient //192.168.1.110/share -c 'cd /home/dulingwen/Downloads; put shaolin.jpg'`` 
	``smb直接上传：put flower.jpg`` 
	``smb下载文件：get flower.jpg`` 