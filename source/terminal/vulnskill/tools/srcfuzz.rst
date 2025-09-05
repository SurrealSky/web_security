源码级程序白盒FUZZ
----------------------------------------
- libFuzzer
	+ 项目地址：https://github.com/Dor1s/libfuzzer-workshop
	+ 官网：https://llvm.org/docs/LibFuzzer.html
	+ 说明
		- LibFuzzer与AFL类似，但它是在单个进程中执行了所有模糊测试。
		- 进程内的模糊测试可能更具针对性，由于没有进程反复启动的开销，因此与AFL相比可能更快。
		- LibFuzzer和要被测试的库链接在一起，通过一个特殊的模糊测试进入点（目标函数），用测试用例feed（喂）要被测试的库。
		- 其中代码覆盖的信息由LLVM的SanitizerCoverage插桩提供。
		- 无法开箱即用的执行黑盒测试（通常需要具有源代码时使用）
		- 主要用于模糊共享库，而不是独立的二进制文件
	+ 优点
		- 搜索空间过于广泛
		- 无法fuzz特定的函数
		- 难以fuzz网络协议
		- 常规fuzz速度太慢
	+ 示例
		- 调用代码
			::
			
				// fuzz_target.cc
				extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
				  DoSomethingInterestingWithMyAPI(Data, Size);
				  return 0;  // Non-zero return values are reserved for future use.
		- 编译生成
			
			::
			
				clang++ -g -std=c++11 -fsanitize=address,fuzzer first_fuzzer.cc ./libFuzzer/libFuzzer.a -o first_fuzzer
				-g和-O1是gcc/clang的通用选项，前者保留调试信息，使错误消息更易于阅读；后者指定优化等级为1（保守地少量优化），但这两个选项不是必须的。
				-fsanitize=fuzzer启用libFuzzer,向libFuzzer提供进程中的覆盖率信息，并与libFuzzer运行时链接。
				除了fuzzer外，还可以附加其他sanitize选项，参考https://clang.llvm.org/docs/AddressSanitizer.html
				libFuzzer.a: 为libfuzzer项目中执行build.sh 编译好生成的 libFuzzer.a。
		- 开始FUZZ
			直接运行程序。
- afl-fuzz
	+ 官网：https://lcamtuf.coredump.cx/afl/
	+ 安装
		::
		
			$ wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
			$ tar zxvf afl-latest.tgz
			$ cd afl-2.52b
			$ make
			$ sudo make install
			
	+ afl-gcc模式
		::
		
			afl-gcc -g -o afl_test afl_test.c
			afl-g++ -g -o afl_test afl_test.cpp
			
			或：
			./configure CC="afl-gcc" CXX="afl-g++"
			静态构建方式如下：
			./configure --disable-shared CC="afl-gcc" CXX="afl-g++" 
	+ LLVM模式
		::
		
			cd llvm_mode
			apt-get install clang
			export LLVM_CONFIG=`which llvm-config` && make && cd ..
			./configure --disable-shared CC="afl-clang-fast" CXX="afl-clang-fast++" 
	+ 测试插桩程序
		::
		
			使用afl-showmap跟踪单个输入的执行路径，并打印程序执行的输出、捕获的元组（tuples）
			afl-showmap -m none -o /dev/null -- ./build/bin/imagew 23.bmp out.png
			使用不同的输入，正常情况下afl-showmap会捕获到不同的tuples，这就说明我们的的插桩是有效的，
			还有前面提到的afl-cmin就是通过这个工具来去掉重复的输入文件。
	+ 执行fuzz
		::
		
			在执行afl-fuzz前，如果系统配置为将核心转储文件（core）通知发送到外部程序，将导致将崩溃信息发
			送到Fuzzer之间的延迟增大，进而可能将崩溃被误报为超时，所以我们得临时修改core_pattern文件。
			sudo su
			echo core >/proc/sys/kernel/core_pattern
			afl-fuzz -i testcase_dir -o findings_dir /path/to/program [params]
	+ 使用screen
		::
		
			一次Fuzzing过程通常会持续很长时间，如果这期间运行afl-fuzz实例的终端终端被意外关闭了，
			那么Fuzzing也会被中断。而通过在screen session中启动每个实例，可以方便的连接和断开。
			screen -S fuzzer1
			afl-fuzz -i testcase_dir -o findings_dir /path/to/program [params] @@
			screen -r fuzzer1
	+ 并行FUZZ
		- 单系统并行测试
			::
			
				查看系统核数：
				cat /proc/cpuinfo| grep "cpu cores"| uniq
				afl-fuzz并行Fuzzing，一般的做法是通过-M参数指定一个主Fuzzer(Master Fuzzer)、
				通过-S参数指定多个从Fuzzer(Slave Fuzzer)。
				screen afl-fuzz -i testcases/ -o sync_dir/ -M fuzzer1 -- ./program
				screen afl-fuzz -i testcases/ -o sync_dir/ -S fuzzer2 -- ./program
				screen afl-fuzz -i testcases/ -o sync_dir/ -S fuzzer3 -- ./program
				afl-whatsup工具可以查看每个fuzzer的运行状态和总体运行概况，加上-s选项只显示概况，其中的数据都是所有fuzzer的总和。
				afl-whatsup -s syncdir
				afl-gotcpu工具可以查看每个核心使用状态。
		- 多系统并行测试(略)
	+ AFL状态窗口
		::
		
			① Process timing:Fuzzer运行时长、以及距离最近发现的路径、崩溃和挂起经过了多长时间。
			② Overall results：Fuzzer当前状态的概述。
			③ Cycle progress：我们输入队列的距离。
			④ Map coverage：目标二进制文件中的插桩代码所观察到覆盖范围的细节。
			⑤ Stage progress：Fuzzer现在正在执行的文件变异策略、执行次数和执行速度。
			⑥ Findings in depth：有关我们找到的执行路径，异常和挂起数量的信息。
			⑦ Fuzzing strategy yields：关于突变策略产生的最新行为和结果的详细信息。
			⑧ Path geometry：有关Fuzzer找到的执行路径的信息。
			⑨ CPU load：CPU利用率
