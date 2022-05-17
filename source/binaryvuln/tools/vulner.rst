漏洞挖掘
----------------------------------------

基础工具
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 补丁比对
	+ binDiff
- SEH结构地址定位
	+ pattern_create
	+ pattern_offset
- RTF解析工具
	+ OffVis

COM FUZZ
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- COMRaider 

协议漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `SPIKE <https://resources.infosecinstitute.com/topic/intro-to-fuzzing/>`_
	C语言实现开源，支持windows和linux系统。
- beSTORM
- `Fuzzowski <https://github.com/nccgroup/fuzzowski>`_
- `backfuzz <https://github.com/localh0t/backfuzz>`_
- GANFuzz
- `boofuzz <https://boofuzz.readthedocs.io/en/stable/>`_
	+ 教程：https://paper.seebug.org/1626/
- Kitty
	+ 教程：https://paper.seebug.org/772/
- BFuzz

文件型漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `FileFuzz <https://bbs.pediy.com/thread-125263.htm>`_
- `EasyFuzzer <https://bbs.pediy.com/thread-193340.htm>`_
- Taof
- GPF
- ProxyFuzz
- Peach Fuzzer(linux/windows)
	+ Peach支持对 **文件格式、ActiveX、网络协议** 进行Fuzz测试，Peach Fuzz的关键是编写Peach Pit配置文件。
	+ 官网：https://sourceforge.net/projects/peachfuzz/
	+ pit文件结构
		- DataModel
		- StateModel
		- Agents
		- Test Block
		- Run Block
- Sulley
- Mu‐4000
- Codenomicon
- Fuzzgrind
- MiniFuzz
- `pngcheck <http://www.libpng.org/pub/png/apps/pngcheck.html>`_
- `pdfcheck <https://www.datalogics.com/products/pdf-tools/pdf-checker/>`_

二进制程序以及源码级挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- afl-fuzz
	+ 官网：https://lcamtuf.coredump.cx/afl/
	+ 安装
		::
		
			$ wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
			$ tar zxvf afl-latest.tgz
			$ cd afl-2.52b
			$ make
			$ sudo make install
			
	+ 有源码FUZZ
		::
		
			afl-gcc -g -o afl_test afl_test.c
			afl-g++ -g -o afl_test afl_test.cpp
			afl-fuzz -i fuzz_in -o fuzz_out ./afl_test
			需要根据提示设置一波core_pattern
			sudo su
			echo core >/proc/sys/kernel/core_pattern
			
	+ 无源码FUZZ
		::
		
			afl使用了qemu模式进行测试，只要在之前的命令的基础上加上-Q的参数即可。
			先进行安装,在afl的根目录打开终端执行以下命令
			cd qemu_mode
			./build_qemu_support.sh
			cd ..
			make install

			gcc -g -o afl_test2 afl_test.c
			afl-fuzz -i fuzz_in -o fuzz_out -Q ./afl_test2
			
- Winafl
	+ DynamoRIO
		- 官网：https://github.com/DynamoRIO/dynamorio/releases
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
			
				USAGE: drrun [options] <app and args to run>
				   or: drrun [options] -- <app and args to run>
				   or: drrun [options] [DR options] -- <app and args to run>
				   or: drrun [options] [DR options] -c <client> [client options] -- <app and args to run>
				   or: drrun [options] [DR options] -t <tool> [tool options] -- <app and args to run>
				   or: drrun [options] [DR options] -c32 <32-bit-client> [client options] -- -c64 <64-bit-client> [client options] -- <app and args to run>
				
				官网：https://dynamorio.org/index.html
				
	+ winafl
		- 官网：https://github.com/googleprojectzero/winafl
		- 插桩方式
			+ IntelPT
			+ DynamoRIO
			+ Syzygy
		- 编译
			::
				
				本机为x84，编译x86程序：
				vs启动命令提示符：x86 Native Tools Command Prompt for VS 2019
				到winafl目录，执行mkdir build32 && cd build32
				cmake -G"Visual Studio 16 2019" -A Win32 .. -DDynamoRIO_DIR=C:\MyProgram\winafl\dynamorio-cronbuild-9.0.19117\build32\cmake
				cmake --build . --config Release
				
				本机为x84，编译x64程序：
				vs启动命令提示符：x86_x64 Cross Tools Command Prompt for VS 2019
				到winafl目录，执行mkdir build64 && cd build64
				cmake -G"Visual Studio 16 2019" -A x64 .. -DDynamoRIO_DIR=C:\MyProgram\winafl\dynamorio-cronbuild-9.0.19117\build64\cmake
				cmake --build . --config Release
				
				本机为x64，编译x86程序：
				vs启动命令提示符：x64_x86 Cross Tools Command Prompt for VS 2019
				到winafl目录，执行mkdir buildx86 && cd buildx86
				cmake -G"Visual Studio 16 2019" -A Win32 .. -DDynamoRIO_DIR=C:\MyProgram\winafl\dynamorio-cronbuild-9.0.19117\buildx86\cmake
				cmake --build . --config Release
				
				本机为x64，编译x64程序：
				vs启动命令提示符：x64 Native Tools Command Prompt for VS 2019
				到winafl目录，执行mkdir buildx64 && cd buildx64
				cmake -G"Visual Studio 16 2019" -A x64 .. -DDynamoRIO_DIR=C:\MyProgram\winafl\dynamorio-cronbuild-9.0.19117\buildx64\cmake
				cmake --build . --config Release
				
		- 使用前提
			+ 可以用于测试dll和GUI程序的，但必须保证被测试目标函数能在 **不需用户交互** 的情况下被执行到且能返回，同时该目标函数还能打开输入文件并关闭输入文件。
		- 使用方式
			::
			
				将dynamorio-cronbuild-9.0.19117\buildx86目录下文件移动到bin32下
				将winafl-master\buildx86\bin\Release目录下文件移动到bin32\bin32目录下
		- afl-fuzz参数说明
			::
			
				afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line
				[afl options]参数如下：
				-i dir     – 测试用例存放目录
				-o dir    – fuzzing过程和结果存放目录
				-D dir   – 二进制动态Instrumentation工具执行文件路径
				-t msec  – 超时设置
				-x dir    – 字典文件
				[instrumentation options]参数由winafl.dll处理。
		- winafl.dll参数说明
			::
			
				即[instrumentation options]参数。
				-debug # debug模式, 它会生成一个log文件
				-target_module # 目标程序(只能有一个), 也是target_offset所在的模块
				-target_offset # 目标程序偏移，相对于target_module的偏移，在method无法导出的时候使用
				-fuzz_iterations # 在重新启动目标进程之前，目标函数要运行的最大迭代次数
				-nargs # 目标程序执行所需要的参数个数(包括目标程序本身)
				-target_module # 目标函数,需要export或者调试符号(pdb)
				-coverage_module # 计算覆盖率的模块,也就是目标程序会调用的模块(dll); (可以有多个)
				
	+ 语料库
		- afl源码下的testcases
		- 其它
			+ `afl generated image test sets <http://lcamtuf.coredump.cx/afl/demo/>`_
			+ `fuzzer-test-suite <https://github.com/google/fuzzer-test-suite>`_
			+ `libav samples <https://samples.libav.org/>`_
			+ `ffmpeg samples <http://samples.ffmpeg.org/>`_
			+ `fuzzdata <https://github.com/MozillaSecurity/fuzzdata>`_
			+ `moonshine <https://gitlab.anu.edu.au/lunar/moonshine>`_
		- 语料库修剪
			+ afl-cmin
			+ afl-tmin
	+ 示例
		- 覆盖率文件
			+ ``drrun.exe -t drcov -dump_text -- test_gdiplus.exe 1.bmp``
			+ ``drcov2lcov -input drcov.notepad.exe.01556.0000.proc.log -output cov.info``
			+ ``perl genhtml cov.info -o html``	
		- 测试运行
			+ ``drrun.exe  -c winafl.dll -debug -target_module test_gdiplus.exe -target_offset 0x1680 -fuzz_iterations 50 -nargs 2 -- test_gdiplus.exe in/1.bmp``
			+ 生成得log文件中显示 ``Everything appears to be running normally`` 证明运行正常。
		- FUZZ测试
			+ ``afl-fuzz.exe -i in -o out -D . -t 20000 -- -coverage_module gdiplus.dll -target_module test_gdiplus.exe -target_offset 0x1680 -fuzz_iterations 50 -nargs 2 -- test_gdiplus.exe @@``
			+ afl-fuzz会创建子进程,参数如下
				- ``.\drrun.exe -pidfile childpid_82ef960aa080045c.txt -no_follow_children -c winafl.dll -coverage_module gdiplus.dll -target_module test_gdiplus.exe -target_offset 0x1680 -fuzz_iterations 50 -nargs 2 -fuzzer_id 82ef960aa080045c -- test_gdiplus.exe out\.cur_input``
			+ 注意call_convention参数，标记了函数的调用约定（如 -call_convention thiscall）
			+ winafl默认的调用约定是stdcall，错误的调用约定可能导致程序在后续的迭代fuzz过程中崩溃
		- 界面说明
			+ stage progress -> now trying && stage execs，now trying 表示目前执行的任务，而 stage execs 表示任务执行的进度，用百分率表示。
			
- `libFuzzer(linux) <https://github.com/Dor1s/libfuzzer-workshop>`_
- syzkaller
	
工控漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `modbus fuzzer <https://github.com/youngcraft/boofuzz-modbus>`_
- `BACnet fuzzer <https://github.com/VDA-Labs/BACnet-fuzzer>`_
- `iec60870_fuzzing_scripts <https://github.com/robidev/iec60870_fuzzing_scripts>`_
- `RTSPhuzz <https://github.com/IncludeSecurity/RTSPhuzz>`_

静态代码审计
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- Coverity
	
内核漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `IOCTL Fuzzer（Windows） <https://code.google.com/archive/p/ioctlfuzzer/>`_
- syzkaller

综合框架
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- AlphaFuzzer
	AlphaFuzzer是一款多功能的漏洞挖掘框架，截止到1.3版本，AlphaFuzzer只包含了文件格式的漏洞挖掘框架。从1.4版本开始，AlphaFuzzer增加了网络协议漏洞挖掘框架。
- Radamsa
- Honggfuzz