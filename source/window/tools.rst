相关工具
========================================

反汇编/调试软件
----------------------------------------

IDA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 更该变量类型
	::
	
		IDA F5反编译的C代码
		printf((const char *)&unk_80BF804, v2[v1 - 1]);
		在unk_80BF804处按Y键更改变量类型，输入char，确定后即可看到打印的字符串：
		printf("%d\n", v2[v1 - 1]);
+ 常用插件
	- IDA FLIRT Signature Database
		+ 用于识别静态编译的可执行文件中的库函数
		+ ``https://github.com/push0ebp/sig-database``
	- Find Crypt
		+ 寻找常用加密算法中的常数（需要安装 yara-python）
		+ ``https://github.com/polymorf/findcrypt-yara``
	- IDA signsrch
		+ 寻找二进制文件所使用的加密、压缩算法
		+ ``https://sourceforge.net/projects/idasignsrch``
	- Ponce
		+ 污点分析和符号化执行工具
		+ ``https://github.com/illera88/Ponce``
	- snowman decompiler
		+ C/C++反汇编插件（F3 进行反汇编）
		+ ``http://derevenets.com/``
	- keystone
		+ 二进制文件修改工具，可以直接修改汇编
		+ ``https://github.com/keystone-engine/keypatch``
	- CodeXplorer
		+ 自动类型重建以及对象浏览（C++）（jump to disasm)
		+ ``https://github.com/REhints/HexRaysCodeXplorer``
	- IDA Ref
		+ 汇编指令注释（支持arm，x86，mips）
		+ ``https://github.com/nologic/idaref``
	- auto re
		+ 函数自动重命名
		+ ``https://github.com/a1ext/auto_re``
	- nao
		+ dead code 清除
		+ ``https://github.com/tkmru/nao``
	- HexRaysPyTools
		+ 类/结构体创建和虚函数表检测
		+ ``https://github.com/igogo-x86/HexRaysPyTools``
	- IDA sploiter
		+ 漏洞利用开发工具，寻找gadget
		+ ``http://thesprawl.org/projects/ida-sploiter/``
	- DIE
		+ 动态调试增强工具，保存函数调用上下文信息
		+ ``https://github.com/ynvb/DIE``
	- sk3wldbg
		+ IDA 动态调试器，支持多平台
		+ ``https://github.com/cseagle/sk3wldbg``
	- ret-sync
		+ 让调试器（WinDbg / GDB / LLDB / OllyDbg / OllyDbg2 / x64dbg）与IDA同步的一个插件
		+ ``https://github.com/bootleg/ret-sync``
	- idaemu
		+ 模拟代码执行（支持X86、ARM平台）
		+ ``https://github.com/36hours/idaemu``
	- x86emu 
		+ CPU模拟器吧，可以模拟执行一些代码这些。
		+ ``https://github.com/cseagle/x86emu``
	- Lighthouse 
		+ 代码覆盖测试工具Code Coverage Explorer for IDA Pro
		+ ``https://github.com/gaasedelen/lighthouse``
	- Diaphora
		+ 程序差异比较
		+ ``https://github.com/joxeankoret/diaphora``
	- FRIEND
		+ 哪里不会点哪里，提升汇编格式的可读性、提供指令、寄存器的文档等
		+ ``https://github.com/alexhude/FRIEND``
	- SimplifyGraph
		+ 简化复杂的函数流程图
	- bincat
		+ 静态二进制代码分析工具包
		+ ``https://github.com/airbus-seclab/bincat``
	- golang_loader_assist -- Golang编译的二进制文件分析助手
	- BinDiff
+ IDAPython
	- 使用方法
		点击file，Script command...菜单,选择python脚本运行。
	- API接口文档：https://www.hex-rays.com/products/ida/support/idapython_docs/
	- 7.4接口变更文档：https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
	- 示例
		::
		
			for functionAddr in Functions():
				if "strcpy" in get_func_name(functionAddr):
					print(hex(functionAddr))

windbg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 介绍
	- 标准命令：提供基本调试功能，不区分大小写。如：bp g dt dv k等。
	- 元命令：内建在调试引擎中，以.开头。如.sympath .reload等。
	- 扩展命令：用于扩展某一方面的调试功能，实现在动态加载的扩展模块中，以!开头。如!analyze等。
	- 帮助
		+ ? 显示常规命令
		+ .help 显示.系列命令
		+ .hh 打开windbg帮助文件
+ 基本设置
	- 清屏命令：``.cls``
	- 设置数据进制：``n [8/10/16]``
	- 设置处理器模式：``.effmach  x86``
	- 将windbg设置成默认调试器：``windbg -I``
	- 结束长时间未完成的命令：``ctrl + break``
+ 设置符号库
	- 设置环境变量
		+ 存在问题是会导致vs调试缓慢
	- 注册表方式
	- 菜单方式
		+ ``SRV*c:\localsymbols*https://msdl.microsoft.com/download/symbols``
	- 命令方式
		+ ``.sympath SRV*c:\localsymbols*https://msdl.microsoft.com/download/symbols``
		+ ``.reload``
	- 符号加载
		+ 加载指定模块的符号：``ld [ModuleName]``
		+ 加载所有模块的符号：``ld *``
		+ 获取符号加载状态：``!sym``
		+ 增加符号搜索路径：``.sympath+ c:\symbols``
		+ 设置符号库路径：``.symfix``
		+ 为所有已加载模块载入符号信息：``.reload``
		+ 重新加载不匹配符号的模块：``.reload /i [module name]``
		+ 指定模块加载符号信息：``.reload /f @[module path]``
		+ 指定模块加载符号信息：``.reload /f [module name]``
		+ 在内核态时强制重新加载当前所处用户态符号：``.reload /f /user``
	- 查看符号信息
		+ 列出所有模块对应的符号信息：``x *!``
		+ 列出指定模块中所有符号：``x ConsoleTest!*``
		+ 带数据类型、符号类型和大小信息：``x /t /v ConsoleTest!*``
		+ 查看pdb是否能匹配：``!itoldyouso mono D:\mySymbols\mono.pdb``
		+ 查看地址附近符号：``ln``
	- 源文件
		+ 查看当前源文件查找路径：``.srcpath``
		+ 设置源文件查找路径设：``.srcpath f:\src``
		+ 添加源文件查找路径：``.srcpath+ f:\src``
	- 查找路径
		+ 查看可执行文件查找路径：``.exepath``
		+ 设置可执行文件查找路径：``.exepath f:\bin``
		+ 添加可执行文件查找路径：``.exepath+ f:\bin``
+ 模块加载命令
	- 显示模块加载信息：``lm[ v | l | k | u | f ] [m Pattern]``
		+ 显示所有加载和未加载的模块信息：``lm``
		+ 显示已加载模块的详细信息：``lmv``
		+ 同时显示加载的符号信息：``lml``
		+ 显示内核模块信息：``lmk``
		+ 显示用户模块信息：``lmu``
		+ 显示镜像路径：``lmf``
		+ 匹配模块名称：``lmm``
		+ DML方式显示：``lmD``
		+ 显示kernel32模块详细信息：``lmv m kernel32``
		+ 显示kernel32.dll模块的信息：``!lmi kernel32``
	- !dlls
		+ 列出所有加载的模块和加载数量：``!dlls``
		+ 根据初始化顺序：``!dlls -i``
		+ 根据加载顺序（默认项）：``!dlls -l``
		+ 根据内存顺序：``!dlls -m``
		+ 显示更多详细信息：``!dlls -v``
		+ 仅显示ModuleAddr地址的模块信息：``!dlls -c ModuleAddr``
		+ 显示kernel32.dll的信息：``!dlls -v -c kernel32``
+ 异常分析命令
	- 显示当前异常的详细信息：``!analyze -v``
	- 诊断阻塞信息：``!analyze -hang``
	- 查看异常分析信息：``!analyze -f``
+ 解析错误信息
	- 解析错误信息：``!error ErrValue``
	- 将错误值作为 NTSTATUS 代码：``!error ErrValue 1``
+ 断点
	- 列出所有断点：``bl``
	- 清除所有断点：``bc *``
	- 清除1号断点：``bc 1``
	- 启用所有断点：``be *``
	- 启用1号断点：``be 1``
	- 禁用所有断点：``bd *``
	- 禁用1号断点：``bd 1``
	- 设置断点：``bp 7c801b00``
	- 设置断点：``bp MyDll+0x1032``
	- 设置断点：``bp `ConsoleTest.cpp:36```
	- 设置断点：``bp main``
	- 进程入口设置断点：``bp @$exentry``
	- 设置断点：``bp TestCommon! CTest::add``
	- 条件断点：``bp `ConsoleTest.cpp:40` ".if (poi(pVar)>5) {}; {g}"``
		+ ``".if (Condition) {Optional Commands}; {g}"``
		+ pVar指针指向的值>5，执行空语句（;）断住,否则继续执行
	- 条件断点：``bp `ConsoleTest.cpp:40` "j (poi(pVar)>5) ' '; 'g'"``
		+ ``"j (Condition) 'Optional Commands'; 'g'"``
		+ 条件断点 pVar指针指向的值>5，执行空语句（;）断住,否则继续执行
	- 匹配add_开头的函数，并在这些函数起始处都打上断点：``bm add_*``
	- 内存断点：``ba [r|w|e] [Size] Addr``
		+ ``[r=read/write, w=write, e=execute], Size=[1|2|4 bytes]``
+ 调试执行控制
	- 执行：``g``
	- 强制调试器处理异常：``gH``,``gN``
	- 执行到函数完成：``gu``
	- 暂停正在运行的程序：``Ctrl+Break``
	- 单步执行：``p [step]``
	- 执行到下一个函数调用处暂停：``pc``
	- 执行到指定地址处暂停：``pa 7c801b0b``
	- 单步步入：``t``
	- 执行到下一个函数调用处暂停：``tc``
	- 执行到分支指令停下：``tb``
	- 执行到特定地址处暂停：``ta 7c801b0b``
	- Trace and Watch Data：``WT``
	- 重新启动程序调试：``.restart``
+ 查看句柄
	- 查看所有句柄的ID：``!handle``
	- 查看所有句柄的类型和名称：``!handle 0 5``
	- 查看ID为000007f8的句柄的类型：``!handle 000007f8 1``
	- 查看ID为000007f8的句柄的名称：``!handle 000007f8 4``
+ 查看变量 
	- 查看局部变量：``dt [var]``
	- 显示dll中的类型信息：``dt ntdll!*``
	- 显示所有模块中含有IMAGE_DOS字符的类型信息：``dt *!*IMAGE_DOS*``
	- 显示myApp进程里全局变量g_app的内存布局：``dt myApp!g_app``
	- 将0x0041f8d4地址处内容按照模块WindbgTest的CTest的内存布局来解析：``dt WindbgTest!CTest 0x0041f8d4``
	- 查看this指针的类型和成员变量：``dt this``
	- 查看变量的值：``?? this->m_nPen``
	- 查看变量的地址：``? [var]``
	- 显示当前函数所有变量和参数：``dv [var]``
	- 显示数据的各种进制形式：``.formats 0x30001``
+ 查看汇编
	- 反汇编当前eip寄存器地址的后8条指令：``u .``
	- 反汇编寄存器地址的后8条指令：``u $eip``
	- 反汇编当前eip寄存器地址的前8条指令：``ub .``
	- 反汇编寄存器地址的前8条指令：``ub $eip``
	- 反汇编main+0x29地址的后30条指令：``u main+0x29 L30``
	- 反汇编main函数：``uf [/c] main``
+ 查看寄存器
	- 显示所有寄存器信息：``r``
	- 显示eax，edx寄存器信息：``r eax,edx``
	- 对寄存器eax赋值为5，edx赋值为6：``r eax=5,edx=6``
	- ``rM num`` 则是根据num的值转储指定的寄存器值，num是8位掩码值
		::
		
			rM 1
			rM 2
			eax=00000001 ebx=ffdff980 ecx=8054bd4c edx=000002f8 esi=00000000 edi=1aa78a2c
			eip=80528bdc esp=8054abd0 ebp=8054abe0 iopl=0         nv up ei pl nz na po nc
			可以看到1转储的寄存器和r指令差不多，只是减少了段寄存器和efl标志寄存器，而rM 2也是一样的结果 
			
			rM 4：转储浮点寄存器
			rM 8：转储段寄存器和efl标志寄存器 
			rM 10：转储8个64位寄存器 
			rM 20：转储调试寄存器，dr0-3是四个硬件断点寄存器，dr6和dr7是断点状态和断点控制寄存器，而cr4则是Pentium处理器新增的控制寄存器 
			rM 40：浮点计算的寄存器 
			rM 80：目前intel处理器使用到的三个控制寄存器，cr1处于保留状态
			rM 100：转储gdtr，gdtl，idtr，idtl，tr，ldtr寄存器的值。
			rM 16：即相当于输出rM 10+rM 2+rM 4的值。 

+ 查看内存
	- 查看进程的所有内存页属性：``!address [-summary][-f:stack][addr]``
	- 从7c801e02内存处开始以dword为单位显示内存,默认显示128字节长度的内容：``dd /c 5 7c801e02``
	- 从7c801e02内存处开始以dword为单位显示内存,显示8个dword：``dd /c 5 7c801e02 L8``
	- 从7c80ff03内存处开始显示Ascii字符串：``da /c 100 7c80ff03``
	- 从7c8022f5内存处开始显示Unicode字符串：``du /c 100 7c8022f5``
	- 从虚拟地址访问内存：``d[a|u|b|w|W|d|c|q|f|D] [/c 列数] [地址]``
		+ a = ascii chars
		+ u = Unicode chars
		+ b = byte + ascii   -- 和UE一样，左边为byte为单位的二进制内容，右边块为ascii形式的字符串内容
		+ w = word (2b)
		+ W = word (2b) + ascii
		+ d = dword (4b)
		+ c = dword (4b) + ascii
		+ q = qword (8b)
		+ f = floating point (single precision - 4b)
		+ D = floating point (double precision - 8b)
		+ g = 显示指定选择器的段描述符
			::
			
				dg FirstSelector [LastSelector]
				KGDT_NULL 		0x00
				KGDT_R0_CODE	0x08
				KGDT_R0_DATA	0x10
				KGDT_R3_CODE	0x18
				KGDT_R3_DATA	0x20
				KGDT_TSS		0x28
				KGDT_R0_PCR		0x30
				KGDT_R3_TEB		0x38
				KGDT_VDM_TILE	0x40
				KGDT_LDT		0x48
				KGDT_DF_TSS		0x50
				KGDT_NMI_TSS	0x58
	- 从物理地址访问内存：``!d[a|u|b|w|W|d|c|q|f|D] [/c 列数] [地址]``
	- ``dds`` ：显示给定范围内的内存内容。假定该内存是符号表中的一系列地址。相应的符号也会显示出来。
+ 写内存
	- 从虚拟地址写内存：``e[b|d|D|f|p|q|w] address [Values]``
	- 从物理地址写内存：``!e[b|d|D|f|p|q|w] address [Values]``
	- 批量内存写 ``f Address L count Values``
+ 查看堆
	- 显示进程堆的个数：``!heap -s``
	- 打印堆的内存结构：``dt _HEAP 00140000``
	- 打印堆的内存详细信息：``!heap -a 00140000``
+ 虚拟内存：``!vadump``
+ 进程命令信息
	- 显示当前进程：``| [进程号]``
	- 切换进程：``| [进程号] s``
	- 显示调试器当前运行进程信息：``!process``
	- 显示当前所调试的进程的EPROCESS：``.process``
	- 切换到目标应用程序的地址空间：``.process /p [EPROCESS]``
	- 目标进程的EPROCESS侵入式调试：``.process /i /p [EPROCESS]``
	- 显示进程列表：``!process 0 0``
		::
		
			PROCESS 881a2a20  SessionId: 1  Cid: 07e8    Peb: 7ffd6000  ParentCid: 0224
			DirBase: 7f145480  ObjectTable: 97ce2510  HandleCount:   0.
			Image: cmd.exe
			注：PROCESS域指定了当前进程的EPROCESS结构的线性地址。
			Cid域指定了当前进程的PID。
			DirBase域指定了存储在CR3寄存器中的物理地址（DirBase约等于页目录物理基地址）

	- 显示进程信息：``!process PID``
	- DML方式显示当前进程的信息：``!dml_proc``
	- 显示当前所有进程：``.tlist``
+ 线程信息命令
	- 查看线程信息
		+ 显示线程信息：``~``
		+ 所有线程：``~* [Command]``
		+ 当前线程：``~. [Command]``
		+ 引发当前事件或异常的线程：``~# [Command]``
		+ 显示指定序号的线程：``~Number [Command]``
		+ 显示指定线程ID的线程：``~~[TID] [Command]``
		+ 切换到线程 N：``~Ns``
		+ 显示所有线程的调用栈：``~* k``
		+ 显示2号线程的调用栈：``~2 k``
		+ 显示线程环境信息：``!teb``
		+ 显示当前线程所有的slot信息：``!tls -1``
		+ 显示每个线程消耗的时间：``!runaway [n]``
			- 0 用户态时间
			- 1 内核态时间
			- 2 自线程创建起的时间间隔
	- 线程上执行命令
		+ 在所有线程上执行命令：``~* e CommandString``
		+ 在当前线程上执行命令：``~. e CommandString``
		+ 在引发异常的线程上执行命令：``~# e CommandString``
		+ 在指定序号的线程上执行命令：``~Number e CommandString``
	- 冻结线程：``~Thread f``
		+ 冻结2号线程：``~2 f``
		+ 冻结引发异常的线程：``~# f``
		+ 解除对3号线程的冻结：``~3 u``
	- 挂起线程
		+ 挂起线程，增加线程挂起数量：``~Thread n``
		+ 恢复线程，减少线程挂起数量：``~Thread m``
	- 显示线程错误信息
		+ 打印当前线程最近的错误信息LastError：``!gle``
		+ 打印所有线程的最近的错误信息：``!gle -all``
		+ 显示所有线程的最后一个错误信息：```~*e !gle``
+ 堆栈信息命令
	- 显示调用栈信息：``k[n][f][L] [#Frames]``
		+ 调用栈包含帧号：``kn``
		+ 临近帧的距离：``kf``
		+ 忽略源代码：``kL``
		+ 最开始的 3 参数：``kb ...``
		+ 所有的参数：``k[p/P] ...``
		+ FPO信息：``kv ...``
		+ 显示最开始的 5 个帧：``kb 5``
	- 显示当前栈帧
		+ 显示当前帧：``.frame``
		+ 指定帧号：``.frame #``
		+ 显示寄存器信息：``.frame /r [#]``

dnSpy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 下载地址：``https://github.com/dnSpy/dnSpy``
+ 支持动态调试.net程序。


其它
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
MDebug102，OllyICE，PointH，x32dbg/x64dbg，c32asm，W32dsm，masm32，.NET（injectreflector，ildasm，PEBrowseDbg，Reflector,ILSpy）

插桩工具
----------------------------------------

TinyInst
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DynamoRIO
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 概述
	DynamoRIO是一款流行的动态二进制插桩工具，工作于操作系统与应用程序之间，通过将二进制程序的代码拷贝到代码缓存的方式模拟目标程序的执行。在动态模拟执行的过程中，可以根据分析需求，对二进制程序的运行状态进行监控与修改。
- 基本组成
	+ DynamoRIO：负责解释并执行目标程序；提供丰富的跨平台API接口
	+ Client ：通过API自定义分析操作来扩展DynamoRIO
	+ DynamoRIO Extensions：主要指drmgr，drsyms，drwrap等官方提供的扩展接口
- 事件
	+ 应用程序事件：应用程序在动态执行时的事件，包括进程创建，模块加载，系统调用等
	+ DynamoRIO事件：包括基本快、轨迹流的创建等
	+ 事件回调函数的注册：dr_register_xx_event,dr_ungister_xx_event等
- 官网：``https://github.com/DynamoRIO/dynamorio/releases``
- 文档：``https://dynamorio.org/index.html``
- 编译
	::
	
		本机为x84，编译x86程序：
		vs启动命令提示符：x86 Native Tools Command Prompt for VS 2019
		到DynamoRIO目录，执行mkdir build32 && cd build32
		cmake -G"Visual Studio 16 2019" -A Win32 ..
		cmake --build . --config RelWithDebInfo
		
		本机为x84，编译x64程序：
		vs启动命令提示符：x86_x64 Cross Tools Command Prompt for VS 2019
		到DynamoRIO目录，执行mkdir build64 && cd build64
		cmake -G"Visual Studio 16 2019" -A x64 ..
		cmake --build . --config RelWithDebInfo
		
		本机为x64，编译x86程序：
		vs启动命令提示符：x64_x86 Cross Tools Command Prompt for VS 2019
		到DynamoRIO目录，执行mkdir buildx86 && cd buildx86
		cmake -G"Visual Studio 16 2019" -A Win32 ..
		cmake --build . --config RelWithDebInfo
		
		本机为x64，编译x64程序：
		vs启动命令提示符：x64 Native Tools Command Prompt for VS 2019
		到DynamoRIO目录，执行mkdir buildx64 && cd buildx64
		cmake -G"Visual Studio 16 2019" -A x64 ..
		cmake --build . --config RelWithDebInfo
		
		
- 参数说明
	::
	
		drrun -t <client> -- <guest>
		
		说明：Client可以观察guest在运行过程中的每一条指令，对任意指令做出任意修改，
			  可以在任意位置插入任意指令。
		
		USAGE: drrun [options] <app and args to run>
		   or: drrun [options] -- <app and args to run>
		   or: drrun [options] [DR options] -- <app and args to run>
		   or: drrun [options] [DR options] -c <client> [client options] -- <app and args to run>
		   or: drrun [options] [DR options] -t <tool> [tool options] -- <app and args to run>
		   or: drrun [options] [DR options] -c32 <32-bit-client> [client options] -- -c64 <64-bit-client> [client options] -- <app and args to run>
		
		官网：https://dynamorio.org/index.html
- 客户端开发
	+ 创建项目
		Visual Studio创建空项目，生成dll
	+ 添加Dynamorio自定义宏
		- 属性管理器，添加新项目属性表，选择任一编译配置项，双击PropertySheet
		- 点击用户宏，添加宏，名称Dynamorio_ROOT，值为Dynamorio项目解压目录。
	+ 添加附加包含目录
		- C/C++，常规，附加包含目录，添加：$(Dynamorio_ROOT)\include;$(Dynamorio_ROOT)\ext\include
	+ 编写客户端代码
	+ 修改编译选项
		- VC++目录，库目录添加：$(Dynamorio_ROOT)
		- 代码中添加包含的lib库
		- 添加C/C++，预处理器定义，添加：WINDOWS，X86_32或X86_64
		- 代码生成，使用静态运行库，/MT
	+ 运行：``drrun -c demo.dll -- cmd /C dir``
- 存在问题
	+ 当导入表OriginalFirstThunk为0时，通过dr_symbol_import_iterator_hasnext无法获取导入表数据。


Intel PT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 简介
	- Pin可以被看做一个即时JIT编译器（Just in Time）。它可以程序运行时拦截常规可执行文件的指令，并在指令执行前生成新的代码，然后去执行生成的新的代码，并在新的代码执行完成后，将控制权交给被拦截的指令。
	- Pin支持多平台（Windows、Linux、OSX、Android）和多架构（x86，x86-64、Itanium、Xscale)。
	- 官方介绍: https://software.intel.com/sites/landingpage/pintool/docs/98484/Pin/html/index.html
	- API文档：https://software.intel.com/sites/landingpage/pintool/docs/98484/Pin/html/group__API__REF.html
	- 下载地址：https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html
	- tools编译
		::
		
			1.Pin官网下载windows平台对应的安装包。
			2.解压pin，将pin目录添加到path环境变量。
			3.安装Cygwin，记得选择安装make、gcc、g++工具
			4.将Cygwin目录下面的bin目录添加到环境变量Path中
			5.这里是win10 64电脑，通过VS的命令行(x64_x86交叉编译，x64 native)进入pin/source/tools目录下
			6.使用make命令，分别编译32，64位程序。
+ 使用示例
	- 基本命令：``pin [OPTION] [-t <tool> [<toolargs>]] -- <command line>``
	- 简单指令计数（指令级插装）: ``pin -t obj-ia32\inscount0.dll -- cmd /C dir``
	- 指令地址追踪（指令级插装）: ``pin -t obj-ia32\itrace.dll -- cmd /C dir``
	- 内存引用追踪（指令级插装）: ``pin -t obj-ia32\pinatrace.dll -- cmd /C dir``
	- 检测镜像的加载和卸载（镜像级插装）: ``pin -t obj-ia32\imageload.dll -- cmd /C dir``
	- 更有效的指令计数（Trace级插装）: ``pin -t obj-ia32\inscount1.dll -- cmd /C dir``
	- 过程指令计数（函数级插装）: ``pin -t obj-ia32\proccount.dll -- cmd /C dir``
	- 指令顺序: ``pin -t obj-ia32\invocation.dll -- cmd /C dir``
	- 对线程级应用插装: ``pin -t obj-ia32\malloc_mt.dll -- cmd /C dir``
	- 打印所有访问内存指令的PC（程序计数器）值和这个指令的有效访问地址: ``pin -t obj-ia32\buffer-lin_tls.dll -- cmd /C dir``
	- 统计镜像文件的指令数：``pin -t obj-ia32\staticcount.dll -- cmd /C dir``
+ 二次开发
	- 打开目录source\tools\MyPintool
	- 打开工程文件，使用vs生成解决方案

Syzygy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

frida
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 简介
	- 官网：https://frida.re/docs/installation/
	- frida框架分为两部分，一部分是运行在系统上的交互工具frida CLI; 另一部分是运行在目标机器上的代码注入工具 frida-server。
+ server端
	- github下载：https://github.com/frida/frida/releases
+ client端
	- 安装方式
		+ pip install frida
		+ pip install frida-tools
	- frida-server
		+ 下载不同平台的server，可通过不同方式进行远程连接。
		+ socket示例：``frida-server -l 127.0.0.1:1234``
	- frida全局参数
		+ -U：通过USB连接远程设备
		+ -R：连接远程机器
		+ -H：连接远程机器HOST
		+ -l：加载注入脚本
		+ 附加进程：frida -p 1234
		+ 启动进程：frida c:\\windows\\notepad.exe
			::
				
				Available commands:
				%resume(0) - resume execution of the spawned process
				%load(1) - Load an additional script and reload the current REPL state
				%reload(0) - reload (i.e. rerun) the script that was given as an argument to the REPL
				%unload(0) - no description
				%autoperform(1) - receive on/off as first and only argument, when switched onwill wrap any REPL code with Java.performNow()
				%autoreload(1) - disable or enable auto reloading of script files
				%exec(1) - execute the given file path in the context of the currently loaded scripts
				%time(1+) - measure the execution time of the given expression and print it to the screen
				%help(0) - print a list of available REPL commands
				
	- frida-ps
	- frida-trace
		+ -f target:即spawn模式
		+ -F：附加顶层当前运行的程序
		+ -n name：附加进程名
		+ -p pid：附加进程id
		+ -I MODULE：包含模块
		+ -X MODULE：排除模块
		+ -i FUNCTION, include [MODULE!]FUNCTION：包含函数，函数名可以使用通配符
		+ -x FUNCTION, exclude [MODULE!]FUNCTION：排除函数，函数名可以使用通配符
		+ -a MODULE!OFFSET, add MODULE!OFFSET：包含非导出函数，使用偏移地址
		+ -T INCLUDE_IMPORTS, include program's imports
		+ -t MODULE, include MODULE imports
		+ -m OBJC_METHOD, include OBJC_METHOD
		+ -M OBJC_METHOD, exclude OBJC_METHOD
		+ -j JAVA_METHOD, include JAVA_METHOD
		+ -J JAVA_METHOD, exclude JAVA_METHOD
		+ -s DEBUG_SYMBOL, include DEBUG_SYMBOL
		+ -q, do not format output messages
		+ -d, --decorate,add module name to generated onEnter log statement
		+ -S PATH, path to JavaScript file used to initialize the session
		+ -P PARAMETERS_JSON, parameters as JSON, exposed as a global named 'parameters'
		+ -o OUTPUT, dump messages to file
	- frida-discover
		+ rida-discover -n name：发现进程内部函数
		+ frida-discover -p pid：发现进程内部函数
	- frida-ls-devices
		+ 列举连接到电脑上的设备
	- frida-kill
		+ 杀死进程
+ 示例

脱壳
----------------------------------------
- DLL_Loader
	DLL装载器，脱DLL壳辅助工具
- ImpREC
	PE导入函数修复工具
- LPE-DLX
	PE文件信息查看修改工具
- ELFReader
	ELF文件格式解析工具
- PEID
	PE文件解析工具（带扫壳功能，加密算法分析等插件）
- Detect it Easy
	侦壳工具
- KillFlower
	花指令清除工具
- Aspr-loader
	asp脱壳辅助工具

代码计算
----------------------------------------
- 32bit Calculator
	32bit整数各种数学运算操作
- FloatConvert
	浮点数的存储变换
- jumpgen
	jmp指令机器码计算
- oPcodeR
	指令机器码生成

反编译
----------------------------------------
- java
	Decafe Pro
- Dephi
	+ DeDeDark
- PowerBuilder
	+ PBKiller
	+ DePB
- VB
	+ VB.Decompiler.Pro
	+ exdec818
- 易语言
	+ EcE

外挂
----------------------------------------
- AheadLib
	AheadLib 是用来生成一个特洛伊DLL的工具，用于分析DLL中的函数参数调用（比如记录Socket send了什么等等）、更改函数功能（随心所欲了：）、更改界面功能（比如在Hook里面生成一个按钮，截获事件等等）。
- PEDIYTools
	PE文件增加区段，导入函数，INT3以及shellcode。
- zeroadd
	PE文件增加区段。

监视工具
----------------------------------------
- gmer
- HideToolz
	隐藏进程工具
- IceSword
- regshot
	注册表快照对比工具
- spy
	窗口句柄获取工具
- SoftSnoop 
	程序API监视器
- wpe
	网络封包编辑器
- hwnd
	窗口句柄获取工具

编辑工具
----------------------------------------
- winhex