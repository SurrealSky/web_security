二进制程序黑盒FUZZ
----------------------------------------
- afl-fuzz
	+ 黑盒FUZZ
		::
		
			afl使用了qemu模式进行测试，只要在之前的命令的基础上加上-Q的参数即可。
			先进行安装,在afl的根目录打开终端执行以下命令
			cd qemu_mode
			./build_qemu_support.sh
			cd ..
			make install

			gcc -g -o afl_test2 afl_test.c
			afl-fuzz -i fuzz_in -o fuzz_out -Q ./afl_test2
	+ AFL网络程序
		- 利用preeny库辅助
		- 利用AFL的persistent模式
		- afl-net

- Winafl
	+ winafl
		- 官网：https://github.com/googleprojectzero/winafl
		- 插桩方式
			+ IntelPT
			+ DynamoRIO(以此为例)
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
				- 尝试找到与语料库全集具有相同覆盖范围的最小子集。举个例子：假设有多个文件，都覆盖了相同的代码，那么就丢掉多余的文件。
				- ``afl-cmin -i input_dir -o output_dir -- /path/to/tested/program [params]``
			+ afl-tmin
				- 减小单个输入文件的大小
				- ``afl-tmin -i input_file -o output_file -- /path/to/tested/program [params] @@``
	+ 示例
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

- honggfuzz
	+ 项目地址：https://github.com/google/honggfuzz
- syzkaller
- wtf
	+ 基于快照的fuzz工具
	+ 项目地址：``https://github.com/0vercl0k/wtf``
