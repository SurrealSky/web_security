权限提升（LPE）漏洞
=========================================

方式
-----------------------------------------
+ 传统权限提升
	- 攻击者最初只需要一个普通的用户权限（甚至有时只需要一个低权限的网络访问）。
	- 直接从低权限级别（如普通用户 user）提升到最高权限级别（如 SYSTEM 或 NT AUTHORITY\SYSTEM）。它跨越了最大的权限鸿沟。
+ UAC绕过
	- 攻击者必须已经获取了一个管理员组成员的用户会话（即使当前是以标准用户令牌运行）。如果一个用户完全不属于 Administrators 组，UAC绕过技术对此用户无效。
	- 从受限制的管理员账户（管理员权限被UAC“过滤”或“分割”的状态）提升到完整的管理员权限。它跨越的是UAC这个“安全护栏”，而不是用户组的根本边界。

攻击面
-----------------------------------------
+ 安装包提权
    - windows下安装器
        + 基于 ``msi`` 原理安装包：遵循微软Windows Installer标准的结构化数据库格式，包含 ``.msi`` ，部分套娃式的 ``.exe`` 文件。
        + 基于 ``.exe`` : 自解压包，定制安装包 等。
        + ``AppX`` (Windows 8时代)：主要用于 ``UWP应用`` ，支持沙盒运行和干净卸载，但限制较多，未大规模普及。
        + ``MSIX`` (Windows 10 1809 版本后): 微软力推的新一代安装格式，旨在融合MSI的灵活性和AppX的现代特性（如容器化、增量更新、干净卸载）。可以看作是MSI的未来替代者。
    - 权限提升
        + msi原理安装包存在 ``按用户(或 仅为我安装)`` 和 ``按计算机（为使用这台电脑的任何人安装(所有用户)）`` 两种安装模式，其权限逻辑由 ``ALLUSERS`` 属性严格控制，攻击者可以利用 ``按计算机`` 模式的安装包来实现权限提升。
        + 按用户： ``ALLUSERS="" 或 ALLUSERS="2"`` ，安装包以当前用户权限运行，安装过程中不会请求提升权限，不需要UAC提权，安装路径写入 ``%LocalAppData%\Programs`` 或 ``%AppData%`` 等用户目录，注册表仅写入 ``HKCU`` ，安装程序以 ``Medium IL`` 运行，因此无法直接实现权限提升。
        + 按计算机： ``ALLUSERS="1"`` ，安装包以管理员权限运行，强制触发UAC，安装路径写入 ``%ProgramFiles%`` 或 ``%Windows%\System32`` 等系统目录，注册表仅写入 ``HKLM`` ,安装服务以 ``SYSTEM`` 或 ``High IL`` 运行，此时可能会出现 ``ProgramData`` 目录普通用户可写，因此可能实现权限提升。
        + msi安装程序在 ``修复`` 或 ``修改`` 时，未正确验证调用者权限，可能以SYSTEM权限执行操作。
+ ``%ProgramData%`` 权限未修改
    + 软件安装后，%ProgramData%里面 ``安装包`` 或 ``软件初次运行`` 创建的目录没有被覆盖，并修改权限，可以通过预埋目录和文件进行提权。
+ 可写服务二进制路径（Weak Service Permissions）
    - 服务对应的可执行文件exe，其它低权限用户可读写。
+ 服务路径漏洞（Unquoted Service Path）
    - CreateProcess执行该 ``路径未加引号`` ，同时lpApplicationName为NULL，系统会按以下方式依次解析该路径：
        + 解析: ``c:\program files\sub dir\1.exe``
        + c:\\program.exe：系统首先会尝试将路径从字符串的开始部分截断，解析为 c:\\program.exe。
        + c:\\program files\\sub.exe：如果第一个解析失败，系统会尝试将路径解析为 c:\\program files\\sub.exe。
        + 最后系统尝试解析整个路径，认为 1.exe 是可执行文件名，并尝试执行它。
    - 命令： ``wmic service get name,Displayname,pathname | findstr /i Program``
+ 不安全的服务操作（Insecure SERVICE_CHANGE_CONFIG）
	- 某些服务可能被配置为允许低权限用户对其进行控制，例如启动、停止、修改配置。
	- 利用方法：使用 ``sc sdshow <servicename>`` 命令可以查看服务的权限字符串。如果其中包含 (WD)（Everyone）的 RCWP（特别是 WP - Write Permission）权限，则存在风险。攻击者可以使用 sc config 等命令修改服务配置，指向恶意负载。
+ 自动安装的、以高权限运行且无需验证的辅助进程
    - 原理：一些第三方软件会安装一个一直运行的高权限服务，该服务开放了一个接口（如 **命名管道、RPC接口、本地Socket** ），等待来自用户态程序的指令。
    - 漏洞产生方式：这个高权限服务在接受指令时，没有进行充分的验证（例如，没有验证调用者程序的数字签名、路径或完整性），或者其指令接口本身存在代码执行漏洞（如缓冲区溢出）。
    - 利用方法：攻击者以一个普通用户的身份，编写一个程序向这个高权限服务的接口发送精心构造的恶意指令。服务接收到指令后，会无条件地以高权限执行攻击者想要的操作（例如，启动一个cmd.exe），从而绕过UAC。著名的 "UACME" 项目中很多绕过方法都属于此类，它们利用了大量合法软件（如Intel、NVIDIA、Citrix等）的此类服务。
    - 命名管道
        + 相关工具：pipelist,PipeViewer,ProcessExplore

    - RPC接口
        + 相关工具: RpcView64（https://github.com/silverf0x/RpcView）
    - 经典漏洞
        + 创建恶意管道服务器：在你的程序中，使用 CreateNamedPipe API创建一个命名管道，例如 \\.\pipe\test_pipe，并让它进入监听状态，等待连接。
        + 触发高权限连接：这是链条的核心。通过RPC等方式，诱使目标高权限服务（如SYSTEM权限）去主动连接到你创建的恶意管道。例如，如果发现目标服务的某个RPC函数参数是文件路径，你可以将它设置为 \\.\pipe\test_pipe。
        + 模拟客户端权限：当高权限服务成功连接后，你的管道服务器端立即调用 ImpersonateNamedPipeClient API。这个调用会使得你当前的线程模拟连接上来的客户端的权限，即SYSTEM权限。
        + 获取SYSTEM令牌：通过 OpenThreadToken 获取当前线程模拟得到的SYSTEM令牌，然后使用 DuplicateTokenEx 将其转换为一个可用的主令牌 (Primary Token)。
        + 创建高权限进程：最后，调用 CreateProcessWithTokenW 或 CreateProcessAsUser，并传入上一步获取的SYSTEM令牌，即可创建一个SYSTEM权限的进程（如 cmd.exe）。

+ DLL劫持
    - 服务进程DLL文件劫持
    - 安装包或者应用程序文件关联DLL劫持，当需要UAC授权的时候，DLL劫持就会产生提权效果。
+ Elevated COM对象提权
    - 两个条件同时满足
        + 条件A：某些COM对象被注册为"elevated"，即它们在调用时会以管理员权限运行，并且可以自动批准（AutoApprove）调用请求（无UAC弹框）。
        + 条件B：对象的LaunchPermission或AccessPermission允许低权限用户（如Everyone、BUILTIN\Users）激活和调用它。
    - 攻击流程
        + 使用OLEView等工具查看系统中注册的COM对象，寻找那些标记为"elevated"的对象。
        + 编写一个利用程序，调用这些COM对象的接口，执行恶意代码。
    - 查找有Elevation或AutoApproval标志的COM对象
        ::

            #查找所有的Elevation，Auto-Approved标志的COM对象
            $CLSIDs = Get-ChildItem HKLM:\Software\Classes\CLSID -Name
            foreach ($clsid in $CLSIDs) {
                $path = "HKLM:\Software\Classes\CLSID\$clsid"
                $elevation = Get-ItemProperty -Path "$path" -Name "Elevation" -ErrorAction SilentlyContinue
                $autoApprove = Get-ItemProperty -Path "$path" -Name "AutoApprove" -ErrorAction SilentlyContinue
                if ($elevation -or $autoApprove) {
                    Write-Host "Found potential elevated COM: $clsid"
                }
            }

            # 检查是否包含危险组
            # 危险的：Everyone, Authenticated Users, BUILTIN\Users, INTERACTIVE
            # 安全的：BUILTIN\Administrators, NT AUTHORITY\SYSTEM
            accesschk.exe -k -q "HKLM\Software\Classes\AppID\{APPID}"

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
+ 注册表提权
    - 全局注册表项
        + HKEY_LOCAL_MACHINE
        + HKEY_USERS\\.DEFAULT​​
        + 重要的全局注册表项
            - ``HKLM\SYSTEM\CurrentControlSet\Services``
            - ``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run​​``
            - ``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce​​``
            - ``HKLM\SOFTWARE\[Application Name]​​``
            - 文件关联，com对象配置：``HKLM\SOFTWARE\Classes``
        + 注意
            - 如果服务进程读取了非全局的注册表项，比如加载了非全局注册表指定的exe/dlll，将存在漏洞。
    - 权限检查
        + 检查所有授予"Everyone"用户写权限的HKLM子键：``accesschk.exe -kquwsv "Everyone" hklm\``
        + 检查Services下的所有弱权限:``accesschk.exe -kquwsv "Users" hklm\system\currentcontrolset\services\``
+ runas
    - 使用user组下普通用户test运行cmd.exe： ``runas /user:test cmd.exe``