信息收集 - Windows
========================================

基本命令
----------------------------------------
- 查询所有计算机名称 ``dsquery computer``
- 查看配置 ``systeminfo``
- 查看版本 ``ver``
- 进程信息 ``tasklist /svc``
- 查看所有环境变量 ``set``
- 查看计划任务 ``schtasks /QUERY /fo LIST /v``
- 查看安装驱动 ``DRIVERQUERY``
- 查看操作系统架构 ``wmic os get osarchitecture``
- 查看逻辑盘 ``wmic logicaldisk get caption``
- 查看安装的软件 ``wmic product get name,version``

域信息
----------------------------------------
- 获取当前组的计算机名 ``net view``
- 查看所有域 ``net view /domain``
- 查看域中的用户名 ``dsquery user``
- 查询域组名称 ``net group /domain``
- 查询域管理员 ``net group "Domain Admins" /domain``
- 查看域控制器 ``net group "Domain controllers"``

用户信息
----------------------------------------
- 查看用户 ``net user`` / ``whoami`` / ``whoami /all``
- 查看用户信息: ``net user <administrator>``
- 用户特权信息 ``whoami /priv``
- 查看当前权限 ``net localgroup administrators``
- 查看在线用户 ``qwinsta`` / ``query user`` / ``quser``
- 查看当前计算机名，全名，用户名，系统版本，工作 站域，登陆域 ``net config Workstation``

网络信息
----------------------------------------
- 域控信息
	+ ``nltest /dclist:xx``
	+ ``Get-NetDomain``
	+ ``Get-NetDomainController``
- 网卡信息 ``ipconfig``
- ARP表 ``arp -a``
- 路由表 ``route print``
- 监听的端口 ``netstat -ano``
- 查看netbios：``nbtscan 192.168.1.17``
- 防火墙状态及规则
	+ ``netsh firewall show config``
	+ ``netsh firewall show state``
- hosts文件

密码信息
----------------------------------------
+ 当前系统凭据
	- ``cmdkey /l``

其他
----------------------------------------
+ wmic
	- 提供了从命令行接口和批命令脚本执行系统管理的支持
	- 查看补丁安装情况: ``wmic qfe get Caption,Description,HotFixID,InstalledOn``
	- 获取帮助
		+ ``wmic /?``
		+ 查看nic命令帮助：``wmic nic /?``
		+ 信息筛选：``wmic nic where NetConnectionStatus=2 get Name,MACAddress,NetConnectionStatus``
	- 进程管理
		+ 列出进程的核心信息：``wmic process list brief``
		+ 新建进程：``wmic process call create notepad``
		+ 结束进程
			- ``wmic process \[handle/PID\] delete``
			- ``wmic process \[handle/PID\] call terminate``
			- ``wmic process where "name='svchost.exe' and ExecutablePath<>'C:\\\\WINDOWS\\\\system32\\\\svchost.exe'" call Terminate``
			- ``wmic process where "name='svchost.exe' and ExecutablePath='C:\\\\WINDOWS\\\\svchost.exe'" call Terminate``
	- BIOS管理
		+ 查看bios版本型号：``wmic bios get name,SMBIOSBIOSVersion,manufacturer``
	- 计算机系统管理
		+ 查看硬件，操作系统信息：``wmic computersystem get Name,workgroup,NumberOfProcessors,manufacturer,Model``
		+ 查看系统启动选项boot.ini的内容：``wmic computersystem get SystemStartupOptions``
		+ 更改计算机名abc为123：``wmic computersystem where “name=‘abc’” call rename 123``
		+ 改工作组google为MyGroup：``wmic computersystem where “name=‘google’” call joindomainorworkgroup “”,"",“MyGroup”,1``
	- CPU 管理
		+ 查看cpu型号：``wmic cpu get name``
	- 文件管理
		+ 查找c盘下windows目录(不包括子目录)下的system.ini文件：``wmic datafile where "drive='c:' and path='\\windows\\' and FileName='system' and Extension='ini'" get Name``
		+ 删除e盘下文件大小大于10M的.cmd文件：``wmic datafile where "drive='e:' and Extension='cmd' and FileSize>'10000000'" call delete``
		+ 复制e盘下test目录(不包括子目录)下的cc.cmd文件到e:\,并改名为aa.bat：``wmic datafile where "drive='e:' and path='\\test\\' and FileName='cc' and Extension='cmd'" call copy "e:\aa.bat"``
		+ 改名c:\hello.txt为c:\test.txt：``wmic datafile "c:\\hello.txt" call rename c:\test.txt``
	- 监视器管理
		+ 获取屏幕像素：``wmic DESKTOPMONITOR where Status='ok' get ScreenHeight,ScreenWidth``
		+ 获取磁盘型号大小：``wmic DISKDRIVE get Caption,size,InterfaceType``
	- 系统环境设置管理
		+ 获取temp环境变量：``wmic ENVIRONMENT where "name='temp'" get UserName,VariableValue``
		+ 更改path环境变量值,新增e:\tools：``wmic ENVIRONMENT where "name='Path' and username='<SYSTEM>'" set VariableValue="%path%;e:\tools"``
		+ 新增系统环境变量home,值为%HOMEDRIVE%%HOMEPATH%：``wmic ENVIRONMENT create name="home",username="administrator",VariableValue="%HOMEDRIVE%%HOMEPATH%"``
		+ 删除home环境变量：``wmic ENVIRONMENT where "name='home'" delete``
	- 文件目录系统项目管理
		+ 查找c盘下名为windows的目录（不包含子目录）：``wmic FSDIR where "drive='c:' and path='\\windows\\'" list``
		+ 删除e:\test目录下除过目录abc的所有目录：``wmic FSDIR where "drive='e:' and path='\\test\\' and filename<>'abc'" call delete``
		+ 删除c:\good文件夹：``wmic fsdir "c:\\good" call delete``
		+ 重命名c:\good文件夹为abb：``wmic fsdir "c:\\good" rename "c:\\abb"``
	- 本地储存设备管理
		+ 获取硬盘系统格式、总大小、可用空间等：``wmic LOGICALDISK get name,Description,filesystem,size,freespace``
	- 网络界面控制器 (NIC) 管理
		+ 获取已连接网卡的名字、速率：``wmic NIC where NetEnabled=true get Name, Speed``
		+ 获取已IP地址网卡的index、caption：``wmic nicconfig where IPEnabled="true" get Index, Caption``
		+ 设置index =1的网卡，静态IP地址：``wmic nicconfig where Index=1 call EnableStatic ("1.2.3.4"),("255.255.255.0")``
		+ 设置index =1的网卡，采用DHCP方式获取IP地址：``wmic nicconfig where Index=1 call EnableDHCP``
	- 操作系统管理
		+ 设置系统时间：``wmic os where(primary=1) call setdatetime 20070731144642.555555+480``
		+ 更改当前页面文件(pagefile.sys)初始大小和最大值：``wmic PAGEFILESET set InitialSize="512",MaximumSize="512"``
		+ 页面文件设置到d:\下,执行下面两条命令：``wmic pagefileset create name='d:\pagefile.sys',initialsize=512,maximumsize=1024``,``wmic pagefileset where "name='c:\\pagefile.sys'" delete``
	- 安装包任务管理
		+ 卸载.msi安装包：``wmic PRODUCT where "name='Microsoft .NET Framework 1.1' and Version='1.1.4322'" call Uninstall``
		+ 修复.msi安装包：``wmic PRODUCT where "name='Microsoft .NET Framework 1.1' and Version='1.1.4322'" call Reinstall``
	- 服务程序管理
		+ 运行spooler服务：``wmic SERVICE where name="Spooler" call startservice``
		+ 停止spooler服务：``wmic SERVICE where name="Spooler" call stopservice``
		+ 暂停spooler服务：``wmic SERVICE where name="Spooler" call PauseService``
		+ 更改spooler服务启动类型[auto|Disabled|Manual] 释[自动|禁用|手动]：``wmic SERVICE where name="Spooler" set StartMode="auto"``
		+ 删除服务：``wmic SERVICE where name="test123" call delete``
	- 共享资源管理
		+ 删除共享：``wmic SHARE where name="e$" call delete``
		+ 添加共享：``WMIC SHARE CALL Create "","test","3","TestShareName","","c:\test",0``
	- 声音设备管理
		+ ``wmic SOUNDDEV list``
	- 用户登录到计算机系统时自动运行命令的管理
		+ 查看msconfig中的启动选项：``wmic STARTUP list``
		+ 基本服务的系统驱动程序管理：``wmic SYSDRIVER list``
	- 用户帐户管理
		+ 更改用户administrator全名为admin：``wmic USERACCOUNT where name="Administrator" set FullName="admin"``
		+ 更改用户名admin为admin00：``wmic useraccount where "name='admin'" call Rename admin00``
+ 日志与事件信息
	- ``wevtutil``
+ 注册表信息
	- ``reg``
