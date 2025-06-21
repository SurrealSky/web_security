反汇编/调试软件
========================================

IDA
----------------------------------------
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

其它
----------------------------------------
MDebug102，OllyICE，PointH，x32dbg/x64dbg，c32asm，W32dsm，masm32，.NET（injectreflector，ildasm，PEBrowseDbg，Reflector,ILSpy）
