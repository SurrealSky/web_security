windbg调试器
========================================

基本用法
----------------------------------------
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
		+ 查找符号的二进制地址：``x ntdll!GlobalCounter``
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
+ 查看系统信息
	- ``vertarget``
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
	- !peb
		+ 列出进程已经加载的dll
	- !vad
		+ 进程中用户空间已分配地址信息
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
	- 格式化显示变量的资料和结构：``dt [var]``
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
	- 虚拟内存(用户态)：``!vadump``
	- 内存统计(物理内存方面)：``!memusage``
	- 内存统计(虚拟内存方面)：``!vm``
	- 查看文件缓存: ``!filecache``
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
	- 从7c801e02内存处开始以dword为单位显示内存,默认显示128字节长度的内容：``dd /c 5 7c801e02``
	- 从7c801e02内存处开始以dword为单位显示内存,显示8个dword：``dd /c 5 7c801e02 L8``
	- 从7c80ff03内存处开始显示Ascii字符串：``da /c 100 7c80ff03``
	- 从7c8022f5内存处开始显示Unicode字符串：``du /c 100 7c8022f5``
	- ``dds`` ：显示给定范围内的内存内容。假定该内存是符号表中的一系列地址。相应的符号也会显示出来。
+ 写内存
	- 从虚拟地址写内存：``e[b|d|D|f|p|q|w] address [Values]``
	- 从物理地址写内存：``!e[b|d|D|f|p|q|w] address [Values]``
	- 批量内存写 ``f Address L count Values``
+ 查看堆
	- 显示进程堆的个数：``!heap -s``
	- 打印堆的内存结构：``dt _HEAP 00140000``
	- 打印堆的内存详细信息：``!heap -a 00140000``
+ 进程命令信息
	- 显示进程列表
		+ ``.tlist`` :显示当前系统中的所有进程（注意双机调试显示的也是宿主机进程列表）
		+ ``!dml_proc`` ：DML方式显示当前进程的信息
		+ ``!process 0 0`` ：显示进程列表
			::
		
				PROCESS 881a2a20  SessionId: 1  Cid: 07e8    Peb: 7ffd6000  ParentCid: 0224
				DirBase: 7f145480  ObjectTable: 97ce2510  HandleCount:   0.
				Image: cmd.exe
				注：PROCESS域指定了当前进程的EPROCESS结构的线性地址。
				Cid域指定了当前进程的PID。
				DirBase域指定了存储在CR3寄存器中的物理地址（DirBase约等于页目录物理基地址）
	- 显示被调试进程
		+ ``| [进程号]``
			::
		
				大多数情况下调试器中只有一个被调试进程，但可以通过.attach或者.create命令同时挂载或创建多个调试对象。
				当同时对多个进程调试时，进程号是从0开始的整数。
		+ ``!process`` ：显示调试器当前运行进程信息
		+ ``.process`` ：显示当前所调试的进程的EPROCESS
	- 显示进程信息：``!process PID``
	- 切换进程：``| [进程号] s``
	- 切换到目标应用程序的地址空间：``.process /p [EPROCESS]``
	- 目标进程的EPROCESS侵入式调试：``.process /i /p [EPROCESS]``
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


内核调试
----------------------------------------
+ 选择虚拟机环境
	- 选择Windows 10 X64 环境
+ 虚拟机添加串行端口
+ 设置命名管道的名字
	- ``\\.\pipe\windbg``
	- 该端是服务器，另一端是应用程序
+ 启动虚拟机
+ 设置debug模式
	::
	
		bcdedit /dbgsettings serial baudrate:115200 debugport:1  
		bcdedit /copy {current} /d DebugEntry 	//执行完本条命令会出现一个新的{ID}，要替换以下命令中的{ID}
		bcdedit /displayorder {current} {ID} 
		bcdedit /debug {ID} ON 
+ 开启测试模式
	::
	
		bcdedit /set testsigning on
		‌Windows测试模式‌是一种特殊的系统运行模式，允许用户运行未经数字签名验证的驱动程序和应用程序。
+ 设置启动方式
	- 快捷方式
		::
		
			复制windbg快捷方式，目标中添加 -b -k com:pipe,port=\\.\pipe\windbg,resets=0,reconnect -y
	- 界面
		::
		
			打开WinDbg.exe后Ctrl+K。
			在COM选项卡填相关信息

调试技巧
----------------------------------------
- 加载符号表
	::
	
		.sympath SRV*c:\localsymbols*https://msdl.microsoft.com/download/symbols
		.reload
		加载所有模块符号表：ld *
		获取符号加载状态：!sym
