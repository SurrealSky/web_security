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
+ 日志与事件信息
	- ``wevtutil``
+ 注册表信息
	- ``reg``
