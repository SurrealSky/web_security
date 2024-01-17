插桩工具
========================================

TinyInst
----------------------------------------

DynamoRIO
----------------------------------------
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
----------------------------------------
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
----------------------------------------

frida
----------------------------------------
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