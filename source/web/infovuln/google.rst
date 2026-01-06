搜索引擎查询
========================================
- `scans <https://scans.io/>`_
	+ 互联网快照存档，保存了历史扫描数据
- `Shodan <https://www.shodan.io/>`_
- `Zoomeye <https://www.zoomeye.org/>`_
- `crt.sh <https://crt.sh/>`_
	+ 通过证书信息查询域名: ``example.com``
	+ 通过证书信息查询子域名: ``%.example.com``
	+ 通过证书序列号查询: ``serial:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx``
	+ 通过证书指纹查询: ``sha1:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx``
	+ 通过证书颁发机构查询: ``issuer:Let's Encrypt``
- `fofa <https://fofa.so/>`_
	+ title="后台管理" 搜索页面标题中含有“后台管理”关键词的网站和IP
	+ header="thinkphp" 搜索HTTP响应头中含有“thinkphp”关键词的网站和IP
	+ body="管理后台" 搜索html正文中含有“管理后台”关键词的网站和IP
	+ body="Welcome to Burp Suite" 搜索公网上的BurpSuite代理
	+ domain="itellyou.cn" 搜索根域名中带有“itellyou.cn”的网站
	+ host="login" 搜索域名中带有"login"关键词的网站
	+ port="3388" && country=CN 搜索开放3388端口并且位于中国的IP
	+ ip="120.27.6.1/24" 搜索指定IP或IP段
	+ cert="phpinfo.me" 搜索证书(如https证书、imaps证书等)中含有"phpinfo.me"关键词的网站和IP
	+ ports="3306,443,22" 搜索同时开启3306端口、443端口和22端口的IP
	+ ports=="3306,443,22" 搜索只开启3306端口、443端口和22端口的IP
	+ && – 表示逻辑与
	+ || – 表示逻辑或
- `Just Metadata <https://github.com/FortyNorthSecurity/Just-Metadata>`_
	+ IP地址情报搜集和分析工具
	+ 收集数据：``python Just-Metadata.py --input ip_list.txt --full``
	+ 分析数据：``python Just-Metadata.py --analyze``
- `publicwww - Find Web Pages via Snippet <https://publicwww.com/>`_
	+ 一个强大的源码搜索引擎，可以搜索网页源码中的关键词、脚本、CSS样式等内容。
	+ 查找使用特定代码、框架、组件的网站
	+ 追踪恶意软件、后门、特定漏洞
	+ 发现配置错误和敏感信息泄露
	+ 进行竞争对手分析和技术栈识别
- google hack
	+ 站点搜索
		+ ``site:example.com`` 只搜索example.com域名下的内容
		+ ``site:*.example.com``
		+ ``-site:www.example.com site:*.example.com``
	+ 文件类型
		+ ``filetype:ext`` 只搜索指定扩展名的文件，如 filetype:pdf
	+ 关键词搜索
		+ ``inurl:keyword`` 搜索URL中包含keyword关键词的页面
	+ 目录列表
		+ ``intitle:"index of"`` 搜索标题中包含“index of”关键词的页面，通常是目录泄露页面
		+ ``"parent directory"``
	+ 登录页面
		+ ``inurl:login`` 搜索URL中包含login关键词的页面
		+ ``intitle:login`` 搜索标题中包含login关键词的页面
		+ ``inurl:admin`` 搜索URL中包含admin关键词的页面
	+ 查找敏感配置文件
		+ ``site:example.com filetype:env``
		+ ``site:example.com "API_KEY"``
		+ ``site:example.com "password" filetype:txt``
		+ ``site:example.com "config" filetype:php``
		+ ``site:example.com filetype:sql``
		+ ``"db_password" site:example.com``
		+ ``inurl:"phpmyadmin" intitle:"phpMyAdmin"``
		+ ``site:example.com filetype:bak``
		+ ``site:example.com "backup" filetype:zip``
		+ ``site:example.com "backup" filetype:sql``