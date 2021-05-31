信息收集 - Linux
========================================

获取内核，操作系统和设备信息
----------------------------------------
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
		用一个“x”来代替，将/etc /shadow作为真正的口令文件，用于保存包括个人口令在内的数据。
		如果passwd字段中的第一个字符是“*”的话，表示系统不允许持有该账号的用户登录。 
		(3)用户标识号(UID)：UID是一个数值，是Linux系统中惟一的用户标识，用于区别不同的用户。 
		(4)组标识号(GID)：这是当前用户的缺省工作组标识。
		(5)用户名(user_name)：包含有关用户的一些信息。
		(6)用户主目录(home_directory)：该字段定义了个人用户的主目录。
		(7)命令解释程序(Shell)：通常是一个Shell程序的全路径名，如/bin/bash。 

- 列出系统所有组 ``cat /etc/group``
- 列出所有用户hash（root）``cat /etc/shadow``
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
