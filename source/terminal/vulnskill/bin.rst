程序分析方法
=========================================

危险函数检测
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	- 常见危险函数
		::
		
			strcpy
	- 动态插桩检测
		- 使用frida hook危险函数，观察输入数据是否可控。
	- IDA插件静态检测
		- https://github.com/Accenture/VulFi

代码覆盖率
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ drrun
	- DynamoRIO工具组件见 :ref:`terminal/vulnskill/tools/binfuzz:二进制程序黑盒FUZZ`
	- 示例
		::
		
			生成覆盖率文件：
			drrun.exe -t drcov -dump_text -- test_gdiplus.exe 1.bmp
			在当前目录中生成.log文件，打开文件，修改头部DRCOV VERSION为2
			IDA使用Lighthouse插件，打开test_gdiplus.exe程序，
			点击File，Load file，Code coverage file，打开log文件
+ frida
	- 项目地址：``https://github.com/gaasedelen/lighthouse/tree/develop/coverage/frida``
	- 示例：``python frida-drcov.py <process name | pid>``
	- 指定输出文件：``python frida-drcov.py -o more-coverage.log foo``
	- 白名单模块：``python frida-drcov.py -w libfoo -w libbaz foo``
	- 指定线程：``python frida-drcov.py -t 543 -t 678 foo``
+ pin
	- 项目地址：``https://github.com/gaasedelen/lighthouse/tree/develop/coverage/pin``
	- 编译好的：``https://github.com/gaasedelen/lighthouse/releases`` ，注意官网编译的版本需要和pin版本对应。
	- 示例：``pin -t C:\CodeCoverage.dll -- C:\HashCalc.exe``

函数级跟踪
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ frida
	- ``frida-trace -p [pid] -a MODULE!OFFSET``
	- ``frida-trace -p [pid] -i FUNCTION`` ,函数名可以使用通配符。
+ drrun
	- 跟踪系统函数（NT*）
		+ ``drrun.exe -t drstrace  -- C:\HashCalc.exe``
		+ 初次运行，自动下载pdb符号库
	- 跟踪win32函数调用
		+ drmemory包含的工具
		+ 解压DynamoRIO后，使用时，需要将 ``dynamorio\lib32\release\dynamorio.dll`` 放在drmemory目录下。
		+ 参看单独的工具：``https://github.com/mxmssh/drltrace/releases``
		+ 命令：``drltrace.exe -only_from_app -print_ret_addr -- cmd /C dir``
		+ 运行后，在当前目录下生成drltrace.*文件。
+ pin
	+ ``pin -t obj-ia32\proccount.dll -- cmd /C dir``