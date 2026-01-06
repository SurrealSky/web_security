主机信息
========================================

IP信息
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- dig
	+ ``查询A记录：dig baidu.com A +noall +answer``
	+ ``查询MX记录：dig baidu.com MX +noall +answer``
	+ ``查询权威DNS：dig baidu.com NS +noall +answer``
	+ ``查询所有记录：dig baidu.com ANY +noall +answer``
	+ ``快速回答：+short``
	+ ``IP反查：dig -x 192.168.17.28 +short``
	+ ``指定域名服务器：dig baidu.com ANY @8.8.8.8``
	+ ``解析过程：dig www.ustc.edu.cn +trace``
	+ ``查询所有子域名：dig @192.168.56.102 greenoptic.vm axfr``
- nslookup
	+ ``查询A记录：nslookup -q=A baidu.com``
	+ ``指定域名服务器：nslookup baidu.com -type=any 8.8.8.8``
- dnsx
	+ 项目地址：``https://github.com/projectdiscovery/dnsx``
	+ 直接apt安装
	+ 示例
		::
		
			subfinder -silent -d hackerone.com | dnsx -silent
			echo hackerone.com| dnsx -a -re

- IP无法访问页面
	+ 服务器开启虚拟主机
		``如：www.ustc.edu.cn->218.22.21.21,页面显示400 Unknown Virtual Host``
	+ 反向代理服务器
		``如：nginx``

存活主机扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- fping
	+ ``fping -a -g 14.215.177.1 14.215.177.100``
	+ ``fping -a -g 14.215.177.0/24``
- masscan
	+ ``masscan --ping 28.41.0.0/16 --rate 1000000``
	+ ``心脏出血漏洞：masscan -p443 28.41.0.0/16 --banners --heartbleed``
	+ ``masscan 192.168.1.1/24 --ports 445`` 
- nmap
	+ ``nmap -sP 192.168.0.1/24`` 
- arp-scan
	+ ``arp-scan -l`` 
- netdiscover

端口扫描
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `nmap <https://github.com/nmap/nmap>`_
	+ 扫描方式
		- ``TCP:-sT``
		- ``SYN:-sS``
		- ``ACK:-sA``
		- ``UDP:-sU``
		- ``RPC:-sR``
		- ``ICMP:-sP``
		- 禁用端口扫描:-sn
	+ 技巧
		- ``--host-timeout 主机超时时间 通常设置18000``
		- ``--scan-delay 报文时间间隔 通常设置1000``
		- ``-S 源地址 定义扫描源地址，防止被发现``
	+ 输出
		- ``-oN <file>``
		- ``-oX <xml file>``
	+ 范围扫描
		- ``nmap 192.168.0.100-110``
		- ``nmap 192.168.0.1/24`` 
		- ``nmap -iL /root/target.txt`` 
	+ 指定端口
		- ``nmap 192.168.0.101 -p 80,8080,3306,3389`` 
		- ``所有端口：nmap -p- 192.168.100.104``
		- ``nmap --top-ports 1000 192.168.100.105``
	+ 路由追踪
		- ``nmap --traceroute 192.168.0.101`` 
	+ 服务版本
		- ``nmap -sV 192.168.0.101`` 
	+ 操作系统版本
		- ``nmap -O 192.168.0.101`` 
	+ 探测防火墙
		- ``nmap -sF -T4 192.168.0.101``
	+ 插件扫描
		- 插件列表:``ls /usr/share/nmap/scripts/ |sed 's/.nse//'>scripts.list``
		- 插件用法：``nmap --script-help ssh_brute``
		- 弱口令扫描:``--script=auth``
		- 暴力破解:``--script=brute``
		- 常见漏洞:``--script=vuln``
		- 默认脚本:``--script=default或者-sC``
		- 局域网服务探测:``--script=broadcast``
		- smb字典破解:``--script=smb-brute.nse --script-args=userdb=/var/passwd,passdb=/var/passwd``
		- smb漏洞：``--script=smb-check-vulns.nse --script-args=unsafe=1 192.168.137.4`` 
		- 查看共享目录:``nmap -p 445 --script smb-ls --script-args 'share=e$,path=\,smbuser=test,smbpass=test' 192.168.137.4``
		- ssh破解：``nmap -p22 --script ssh-brute --script-args userdb=cysec_user.txt,passdb=username.txt 172.16.226.5 -nP -vvv``
		- 目录扫描:``nmap -sV --script=http-enum -p 80,60000 192.168.100.105``
		- 永恒之蓝: ``nmap --script=smb-vuln-ms17-010 192.168.117.130``
	+ 注意
		::
		
			1.默认情况下，nmap只扫描默认端口。
			2.NMAP执行结果中，端口状态后经常标记tcpwrapped。tcpwrapped表示服务器运行TCP_Wrappers服务。
			TCP_Wrappers是一种应用级防火墙。它可以根据预设，对SSH、Telnet、FTP服务的请求进行拦截，判断
			是否符合预设要求。如果符合，就会转发给对应的服务进程；否则，会中断连接请求。
		
- `zmap <https://github.com/zmap/zmap>`_
- `masscan <https://github.com/robertdavidgraham/masscan>`_
	+ 全端口扫描：``masscan 192.168.1.1 -p 1-65535 --banner``
	+ 输出扫描结果：``masscan -p80,8000-8100 10.0.0.0/8 --echo > scan.conf``
	+ 输出文件：``-oL/-oJ/-oD/-oG/-oB/-oX/-oU <file>: Output scan in List/JSON/nDjson/Grepable/Binary/XML/Unicornscan format``

RPC信息搜集
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- rpcclient
	+ ``rpcclient -U "" 10.10.10.161``

Samba服务
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- smbmap
	+ 枚举整个域中的samba共享磁盘
	+ ``smbmap -H 192.168.1.40``
	+ 枚举特定用户共享：``smbmap -H 192.168.1.17 -u raj -p 123456``
- nmblookup
	+ 网络中查询NetBIOS名称，网络中查询NetBIOS名称
	+ ``nmblookup -A 192.168.1.17``
- nbtscan
	+ 扫描IP网络以获取NetBIOS名称信息
	+ ``nbtscan 192.168.1.17``
- enum4linux
- smbclient
	+ 无密码：``smbclient -L //192.168.99.4 -N``
	+ 查看共享文件夹：``smbclient -L //192.168.1.110 -U Jerry`` 
	+ 进入共享文件夹：``smbclient //192.168.1.110/share -U Jerry`` 
	+ 上传文件：``smbclient //192.168.1.110/share -c 'cd /home/dulingwen/Downloads; put shaolin.jpg'`` 
	+ smb直接上传：``put flower.jpg`` 
	+ smb下载文件：``get flower.jpg`` 
- nmap
	+ ``nmap --script smb-enum-shares -p139,445 192.168.1.17``
	+ ``nmap --script smb-os-discovery 192.168.1.17``
	+ 检测smb类型的所有漏洞：``nmap --script smb-vuln* 192.168.1.16``
- msf
	+ ``auxiliary/scanner/smb/smb_lookupsid``
		::
		
			set rhosts 192.168.1.17
			set smbuser raj
			set smbpass 

系统信息
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `linux系统信息获取LinEnum <https://github.com/rebootuser/LinEnum>`_
- `系统信息获取PEASS-ng <https://github.com/carlospolop/PEASS-ng>`_

系统监控
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `pspy64 <https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64>`_
	|pspy|

	注：其中uid为0标识具有root权限运行的进程。

.. |pspy| image:: ../../images/pspy.jpg