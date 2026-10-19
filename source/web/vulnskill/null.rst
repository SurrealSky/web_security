没思路了怎么办
========================================

google 搜索大法
---------------------------------------
+ 查找公开可用的 API 密钥文件: ``site:github.com intitle:"index.of" intext:"api.txt"``
+ 查找潜在有问题的 API 目录: ``site:github.com inurl:"/api/v1" intext:"index of /"``
+ 针对php站点,查找所有存在 XenAPI SQL 注入漏洞的站点: ``site:github.com ext:php inurl:"api.php?action="``
+ 列出了可能暴露的 API 密钥: ``site:github.com intitle:"index of" api_key OR "api key" OR apiKey -pool``
+ 敏感文件: ``site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)``
+ dork查询： `dork_queries.txt <../../_static/dork_queries.txt>`_
+ 相关工具
	- 项目地址： ``https://github.com/ritchiemwewa/oxdork``
	- 安装： ``pip install oxdork``
	- 简单查询： ``oxdork "site:example.com filetype:pdf"``
	- 指定结果数量： ``oxdork -c 50 "site:example.com filetype:pdf"``
	- 保存结果到文件: ``oxdork -o results.txt "site:example.com filetype:pdf"``
	- 批量查询: ``oxdork queries.txt``

github搜索大法
---------------------------------------
+ ``"nasa.gov" password``
+ ``"nasa.gov" "password":``
+ ``"tesla.com" AND ("api_key" OR "secret" OR "password" OR "access_token" OR "client_secret" OR "private_key" OR "AWS_SECRET_ACCESS_KEY" OR "DB_PASSWORD" OR "slack_token" OR "github_token" OR "BEGIN RSA PRIVATE KEY")``
+ ``"tesla.com" AND ("api_key" OR "secret" OR "password" OR "access_token" OR "client_secret" OR "private_key" OR "AWS_SECRET_ACCESS_KEY" OR "DB_PASSWORD" OR "slack_token" OR "github_token" OR "BEGIN RSA PRIVATE KEY") language:JSON``
+ ``"nasa" path:/wp-config.php``
+ ``"nasa" path:/.env``
+ 相关工具： ``https://github.com/hisxo/gitGraber``
+ ``python3 gitGraber.py -k wordlists/keywords.txt -q "nasa.gov" -s``

互联网档案库
---------------------------------------
+ Wayback Machine
	- 互联网档案馆：一些网站的历史文件比如pdf之类的访问404，可以通过 ``web.archive.org`` 下载历史文件。
	- 提取子域名： ``curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u > wayback.txt``
	- 提取敏感扩展名文件： ``https://web.archive.org/cdx/search/cdx?url=*.uc.cn/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)``
	- 提取API接口： ``http://web.archive.org/cdx/search/cdx?url=uc.cn/api&matchType=prefix&output=text&fl=original&collapse=urlkey`` 
	- 提取动态网页： ``https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(php|asp|aspx|jsp|cgi|do|action)``
	- 包含特定关键词： ``https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*keyword.*``
	- 特定返回包包体类型： ``https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=mimetype:application/json``	
	- 限定时间范围： ``&from=20260101&to=20261231``
	- 404打法
		+ 寻找历史页面： ``curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.target.com/*" --data-urlencode "collapse=urlkey" --data-urlencode "output=text" --data-urlencode "fl=original" > out.txt``
		+ 提取敏感页面： ``cat out.txt | grep -a -E '^[[:print:]]+$' | urldedupe | grep -E '\.xml|\.json|\.sql|\.txt|\.zip|\.tar|\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.ini|\.bat|\.sh|\.tar|\.deb|\.rpm|\.iso|\.img|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc'`` 
		+ 直接在https://web.archive.org/搜索404页面url，选择时间范围，查看是否有历史页面。
		+ 其它404页面搜索方法
			- ``https://otx.alienvault.com/api/v1/indicators/hostname/target.com/url_list?limit=500&page=1``
			- ``https://www.virustotal.com/vtapi/v2/domain/report?apikey=<api_key>&domain=<DOMAIN>``
+ postman接口泄露（接口调用）
	- ``https://www.postman.com/search?q=xxx.com&scope=public&type=request``

参数fuzz大法
---------------------------------------
+ 优先场景
	- 403禁止页面以及重定向到另外一个页面的场景
	- 登录页面，类似login.php?这种页面
	- 空白页面
+ 根据目标收集对应的路径和参数制作自己的字典
    - ``cat taobao_urls.txt | unfurl paths >> api.txt``
    - ``cat taobao_urls.txt | unfurl keys  >> param.txt``

host碰撞
---------------------------------------
+ 搜集IP：这里是外网IP
    - 方法1： ARL->资产搜索->IP->公网->导出
	- 方法2
		+ 收集asn： ``https://bgp.he.net/search?search%5Bsearch%5D=alibaba&commit=Search``
		+ 收集IP范围： ``cat asn.txt| asnmap | tee ipscope.txt``
		+ 收集IP： ``cat ipscope.txt | mapcidr | tee ips.txt``
	- 作用1：检测有效域名: ``for i in $(cat ips.txt); do ffuf -w subs.txt -u https://$i -H "HOST: FUZZ" -of csv -o $i.csv; done``
	- 作用2：host碰撞
+ 搜集内网域名：子域名暴力破解
    - ARL->资产搜索->IP->内网->导出
+ 相关工具： ``https://github.com/fofapro/Hosts_scan``


