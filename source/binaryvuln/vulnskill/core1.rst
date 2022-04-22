核心技术-模糊测试
========================================

概述
----------------------------------------
模糊测试（fuzzing）是一种通过向程序提供非预期的输入并监控输出中的异常来发现软件中的故障的方法。

分类
----------------------------------------
+ 基于变异的模糊测试器
	- 通过对已有的数据样本进行变异来创建测试用例
+ 基于生成的模糊测试器
	- 为被测试系统使用的协议或文件格式建模，基于模型生成输入并据此创建测试用例。
	
缺点
----------------------------------------
+ 具有较强的盲目性
	- 即使熟悉协议格式，依然没有解决测试用例路径重复的问题，导致效率较低
+ 测试用例冗余度大
	- 由于很多测试用例通过随机策略产生，导致会产生重复或相似的测试用例
+ 对关联字段的针对性不强
	- 大多数时候只是对多个元素进行数据的随机生成或变异，缺乏对协议关联字段的针对性
	
AFL fuzzer
----------------------------------------

AFL概述
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
AFL全称是American Fuzzy Lop，由Google安全工程师Michał Zalewski开发的一款开源fuzzing测试工具，原理是在相关代码处插桩，因此AFL主要用于对 **开源软件** 进行测试。当然配合QEMU等工具，也可对 **闭源二进制代码** 进行fuzzing，但执行效率会受到影响。

AFL安装
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 官网：https://lcamtuf.coredump.cx/afl/
+ linux
	::
	
		$ wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
		$ tar zxvf afl-latest.tgz
		$ cd afl-2.52b
		$ make
		$ sudo make install
		
		有源码：
		afl-gcc -g -o afl_test afl_test.c
		afl-g++ -g -o afl_test afl_test.cpp
		afl-fuzz -i fuzz_in -o fuzz_out ./afl_test
		需要根据提示设置一波core_pattern
		sudo su
		echo core >/proc/sys/kernel/core_pattern
		
		无源码：
		afl使用了qemu模式进行测试，只要在之前的命令的基础上加上-Q的参数即可。
		先进行安装,在afl的根目录打开终端执行以下命令
		cd qemu_mode
		./build_qemu_support.sh
		cd ..
		make install

		gcc -g -o afl_test2 afl_test.c
		afl-fuzz -i fuzz_in -o fuzz_out -Q ./afl_test2
+ windows
	- 官网：https://github.com/googleprojectzero/winafl
	- 基于二进制插桩工具DynamoRIO
	
AFL示例
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

二次开发
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

libFuzzer
----------------------------------------

libFuzzer概述
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
libFuzzer需要和要被测试的库链接在一起，通过一个模糊测试入口点（目标函数），把测试用例喂给要被测试的 **库函数（开源或闭源）** 。fuzzer会跟踪哪些代码区域已经测试过，然后在输入数据的语料库上进行变异，来使代码覆盖率最大化。代码覆盖率的信息由 LLVM 的SanitizerCoverage 插桩提供。

libfuzzer安装
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 官网：https://llvm.org/docs/LibFuzzer.html

libFuzzer示例
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``clang++ -g -std=c++11 -fsanitize=address,fuzzer first_fuzzer.cc ./libFuzzer/libFuzzer.a -o first_fuzzer``