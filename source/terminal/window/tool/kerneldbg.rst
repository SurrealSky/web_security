windbg内核调试
========================================

环境准备
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
