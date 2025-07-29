权限提升（LPE）漏洞
=========================================
+ 服务可执行文件可读写
    - 服务对应的可执行文件exe，其它低权限用户可读写。
+ DLL劫持
    - 服务进程DLL文件劫持
+ 文件移动操作劫持
    - 原理
        + Windows平台下高权限进程的Symlink攻击（高权限进程在操作文件时，未作严格的权限校验，导致攻击利用符号链接到一些受保护的目录文件，比如C盘的系统DLL文件，后面系统或应用去自动加载时，实现代码执行并提权）。
        + 应用程序在写入文件时，使用了SYSTEM用户权限，这种不安全的权限设置导致任意系统文件均可被重写。
        + 日志中的文件内容用户可控，攻击者向日志文件注入控制命令，然后将其存储为batch为文件来执行实现提权。
        + 基于windows符号链接来实现系统任意文件的读写。
    - 利用方式
        + 使用Promon监控进程文件写入行为。
            ::
            
                过滤Process Name为目标进程名，Opreation为WriteFile。
                检查程序是否使用administrator或SYSTEM权限进行操作文件。
        + 检查权限
            ::
            
                检查普通用户(Everyone)拥有对这些文件的完全控制权限。
        + 创建普通权限用户
            ::
            
                创建一个普通用户登录，查看是否对目标文件具有完全控制权限。
        + 创建软链接或符号链接
            ::
            
                创建软链接方法（任意文件读，写，删除等漏洞）：
                CreateMountPoint.exe D:\test C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
                此时，当进程操作test目录下文件，即是对系统启动目录下的文件操作。
                注：可以控制文件内容中包含如 & mkdir c:\windows\test &，就可进行命令执行。
                
                创建符号链接方法（任意文件读写漏洞）
                CreateSymlink.exe test\2.txt c:\2.bat
                注：test目录必须为空。
    - 若程序对CreateFile函数调用，检测GetLastError为REPARSE（重解析）导致漏洞无法利用