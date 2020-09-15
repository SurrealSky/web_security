持久化 - Linux
========================================

什么是权限
----------------------------------------
在Linux 系统中， ``ls -al`` 即可查看列出文件所属的权限。这里我用kali 系统来演示。

::

	……
	drwxr-xr-x  2 kali kali    4096 Jan 27 12:52 Downloads
	-rw-r--r--  1 root root     903 Jun 14 11:33 exp.html
	-rw-r--r--  1 root root  153600 May  5 09:42 flag
	lrwxrwxrwx  1 kali kali      28 May 14 08:28 flagg -> /proc/self/cwd/flag/flag.jpg
	-rw-r--r--  1 kali kali     188 May 14 08:29 flagg.zip
	-rw-r--r--  1 root root 1807342 Apr 20 06:52 get-pip.py
	drwx------  3 kali kali    4096 Jun 18 21:35 .gnupg
	-rw-r--r--  1 root root      56 Jun 16 23:29 hash.txt
	-rw-r--r--  1 root root   12396 Jun 11 00:13 hydra.restore
	-rw-------  1 kali kali    5202 Jun 18 21:35 .ICEauthority
	-rw-r--r--  1 root root    2046 Jun 10 22:58 jim_pass.txt
	……

::

	例如：
	-rw-r--r--  1 root root      56 Jun 16 23:29 hash.txt

- 第一位
	| ``-`` :代表普通文件
	| ``d`` :代表目录
	| ``l`` :代表软链接
	| ``b`` :代表块文件
	| ``c`` :代表字符设备
- 第二及后面几位,分别三个为一组
	| ``rw-r--r--`` 代表文件所属的权限,r:文件可读。w:文件可修改。-:表示暂时没有其他权限。x:表示可执行
	| ``rw-`` 表示文件所拥有者的权限
	| ``r--`` 表示文件所在组的用户的权限
	| ``r--`` 表示其他组的用户的权限。
- 第二组数据 ``1`` 
	| 如果文件类型为目录，表示目录下的字目录个数
	| 如果文件类型是普通文件，这个数据就表示这个文件的硬链接个数
- 第三组数据 ``root`` ,表示该文件所有者为root用户
- 第四组数据 ``root`` ,表示该文件所在组为root组
- 第五组数据 ``56`` ,表示文件的大小为多少字节。如果为一个目录，则为 ``4096`` 。
- 第六组数据表示最后一次修改时间
- 第七组数据表示文件名称


权限提升
----------------------------------------
- linux exploit suggester（kernel<3.4.4）
- 明文root密码/密码复用
- 脏牛漏洞本地提权
- 内核漏洞利用
    - searchspolit linux
    - searchspolit centos 7 kernel 3.10
- 攻击有root权限的服务
- 通过有SUID属性的可执行文件
    - 查找可能提权的可执行文件
	- ``find / -perm -4000 -ls``
	- ``find / -perm -u=s -type f 2>/dev/null``
	- ``find / -user root -perm -4000 -print 2>/dev/null``
	- ``find / -user root -perm -4000 -exec ls -ldb {} \;``
    - 常用的提权文件：Nmap，Vim，find，Bash，More，Less，Nano，cp
- 利用可用的root权限
    - ``sudo -l``
- crontab计划任务
- docker提权
    - docker images命令查看已经存在的镜像
    - 没有的话就pull一个
	- docker pull alpine
    - 已经存在的images
	- docker run -it --rm xxx /bin/bash    #常规使用
	- docker run -it --rm xxx /bin/sh    #常规使用
	- docker run -it --rm -v /etc:/etc xxx /bin/bash    #异常使用
	- docker run -it --rm -v /etc:/etc xxx /bin/sh    #异常使用
    - 挂载目录到docker镜像内
	- docker run -v /:/mnt  -it alpine
	- docker run -v /etc/:/mnt -it alpinecd /mntcat shadow
    
- 其它
    - ``https://github.com/SecWiki/linux-kernel-exploits``

持久化
----------------------------------------
- 反弹shell
- suid shell
- icmp后门
- sshd wrapper
- sshd软链接后门
- port knocking
- pam后门
- webshell
- rootkit
- strace 后门
    - ``alias ssh='strace -o /tmp/.ssh.log -e read,write,connect -s 2048 ssh'``
