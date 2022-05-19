相关工具
========================================

IDA
----------------------------------------

基础
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ y
	::
	
		IDA F5反编译的C代码
		printf((const char *)&unk_80BF804, v2[v1 - 1]);
		在unk_80BF804处按Y键更改变量类型，输入char，确定后即可看到打印的字符串：
		printf("%d\n", v2[v1 - 1]);
		

反汇编/调试软件
----------------------------------------
- MDebug102
- OllyICE
- PointH
- x32dbg/x64dbg
- c32asm
- IDA
- W32dsm
- masm32
- .NET
	| injectreflector
	| ildasm
	| PEBrowseDbg
	| Reflector

插桩工具
----------------------------------------

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
	- frida
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
		+ -F：附加顶层程序
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
	DeDeDark
- PowerBuilder
	| PBKiller
	| DePB
- VB
	| VB.Decompiler.Pro
	| exdec818
- 易语言
	| EcE

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