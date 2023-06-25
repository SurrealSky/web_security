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

dll劫持漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `Rattler <https://github.com/sensepost/rattler/releases/>`_
- `ChkDllHijack <https://github.com/anhkgg/anhkgg-tools>`_

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
	+ 官方：https://boofuzz.readthedocs.io
	+ 语法风格
		- Spike-style static protocol definition：https://boofuzz.readthedocs.io/en/stable/user/static-protocol-definition.html
		- non-static protocol definition：https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html
	+ 日志文件
		- 保存在boofuzz-results下的DB文件
		- 重新打开： ``boo open <run-*.db>`` 
	+ web可视化
		- http://127.0.0.1:26000/
- Kitty
	+ 教程：https://paper.seebug.org/772/
- BFuzz

文件型漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- Peach Fuzzer
	+ Peach支持对 **文件格式、ActiveX、网络协议** 进行Fuzz测试，Peach Fuzz的关键是编写Peach Pit配置文件。
	+ 官网源码：https://gitlab.com/gitlab-org/security-products/protocol-fuzzer-ce
	+ 在线帮助：https://peachtech.gitlab.io/peach-fuzzer-community/WhatIsPeach.html
	+ windows编译：https://zhuanlan.zhihu.com/p/386565953
	+ 打开安装目录PeachService.exe，可以打开web服务，浏览器查看FUZZ进度和崩溃信息
	+ pit文件结构
		- 首先必须创建Peach Pit格式文件，文件是基于XML格式，里面记录了文件格式的组织方式，我们需要如何进行Fuzz，Fuzz的目标等信息。
		- Pit文件主要包含5个元素
			+ DataModel：定义数据结构的元素。
			+ StateModel：管理 Fuzz 过程的执行流。
			+ Agents：监视 Fuzz 过程中程序的行为，可以捕获程序的 crash 信息。
			+ Test Block：将 StateModel 和 Agents 等联系到一个单一的测试用例里。
			+ Run Block：定义 Fuzz 过程中哪些 Test 会被执行。这个块也会记录 Agent 产生的信息。
	+ pit文件基本框架
		::
		
			<?xml version="1.0" encoding="utf-8"?>
			<Peach ...版本，作者介绍之类...>
				<Include ...包含的外部文件/> 			#通用配置
				<DataModel> 					#数据模型
					<Block/>
					<Blob/>
					......
				</DataModel>
				<StateModel> 					#状态模型
				</StateModel> 
				<Agent> 					#代理器
				</Agent>
				<Test>
					<StateModel/> 				#必须
					<Publisher/> 				#必须
					<agent> 				#可选
						<Monitor>
							<Param name="CommandLine" value="test01.exe fuzzed1.png"/> #注意fuzzed1.png与Publisher配置的Filename参数值一致
						</Monitor>
					</agent>
					<Include/> 				#可选
					<Exclude/> 				#可选
					<Strategy/> 				#可选
					<Logger/> 				#可选
						......
			  </Test>
				<Run>Fuzzer执行的进入点</Run>
			</Peach>
	+ 说明
		- publisher="Peach.Agent"
			::
			
				<Action type="call" method="WaitForPort" publisher="Peach.Agent" />
				Peach.Agent即没有指定publisher，默认取Test列表中第一个publisher
	+ 相关示例
		- `文件FUZZ <../../_static/peach_file.xml>`_
		- `UDP协议FUZZ <../../_static/peach_udp.zip>`_
		- `TCP协议FUZZ <../../_static/peach_tcp.zip>`_

- `FileFuzz <https://bbs.pediy.com/thread-125263.htm>`_
- `EasyFuzzer <https://bbs.pediy.com/thread-193340.htm>`_
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
			
	+ 白盒FUZZ
		- afl-gcc模式
			::
			
				afl-gcc -g -o afl_test afl_test.c
				afl-g++ -g -o afl_test afl_test.cpp
				
				或：
				./configure CC="afl-gcc" CXX="afl-g++"
				静态构建方式如下：
				./configure --disable-shared CC="afl-gcc" CXX="afl-g++" 
		- LLVM模式
			::
			
				cd llvm_mode
				apt-get install clang
				export LLVM_CONFIG=`which llvm-config` && make && cd ..
				./configure --disable-shared CC="afl-clang-fast" CXX="afl-clang-fast++" 
		- 测试插桩程序
			::
			
				使用afl-showmap跟踪单个输入的执行路径，并打印程序执行的输出、捕获的元组（tuples）
				afl-showmap -m none -o /dev/null -- ./build/bin/imagew 23.bmp out.png
				使用不同的输入，正常情况下afl-showmap会捕获到不同的tuples，这就说明我们的的插桩是有效的，
				还有前面提到的afl-cmin就是通过这个工具来去掉重复的输入文件。
		- 执行fuzz
			::
			
				在执行afl-fuzz前，如果系统配置为将核心转储文件（core）通知发送到外部程序，将导致将崩溃信息发
				送到Fuzzer之间的延迟增大，进而可能将崩溃被误报为超时，所以我们得临时修改core_pattern文件。
				sudo su
				echo core >/proc/sys/kernel/core_pattern
				afl-fuzz -i testcase_dir -o findings_dir /path/to/program [params]
		- 使用screen
			::
			
				一次Fuzzing过程通常会持续很长时间，如果这期间运行afl-fuzz实例的终端终端被意外关闭了，
				那么Fuzzing也会被中断。而通过在screen session中启动每个实例，可以方便的连接和断开。
				screen -S fuzzer1
				afl-fuzz -i testcase_dir -o findings_dir /path/to/program [params] @@
				screen -r fuzzer1
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
	+ AFL网络程序
		- 利用preeny库辅助
		- 利用AFL的persistent模式
		- afl-net
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
				- 尝试找到与语料库全集具有相同覆盖范围的最小子集。举个例子：假设有多个文件，都覆盖了相同的代码，那么就丢掉多余的文件。
				- ``afl-cmin -i input_dir -o output_dir -- /path/to/tested/program [params]``
			+ afl-tmin
				- 减小单个输入文件的大小
				- ``afl-tmin -i input_file -o output_file -- /path/to/tested/program [params] @@``
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
- libFuzzer
	+ 项目地址：https://github.com/Dor1s/libfuzzer-workshop
	+ 官网：https://llvm.org/docs/LibFuzzer.html
	+ 说明
		- LibFuzzer与AFL类似，但它是在单个进程中执行了所有模糊测试。
		- 进程内的模糊测试可能更具针对性，由于没有进程反复启动的开销，因此与AFL相比可能更快。
		- LibFuzzer和要被测试的库链接在一起，通过一个特殊的模糊测试进入点（目标函数），用测试用例feed（喂）要被测试的库。
		- 其中代码覆盖的信息由LLVM的SanitizerCoverage插桩提供。
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
- honggfuzz
	+ 项目地址：https://github.com/google/honggfuzz
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
	
驱动漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `DriverView驱动查看工具 <http://www.nirsoft.net/utils/driverview.html>`_
- `DeviceTree驱动关联设备查看工具 <http://www.osronline.com/article.cfm%5earticle=97.htm>`_
- `WinObj查看符号链接 <http://technet.microsoft.com/en-us/sysinternals/bb896657>`_
- IRP监控器
	+ IrpTracker：http://www.osronline.com/article.cfm%5earticle=199.htm
	+ IRPMon：https://github.com/MartinDrab/IRPMon
- IOCTLpus
	+ 项目：https://github.com/jthuraisamy/ioctlpus
- IOCTLbf
	+ 下载：https://code.google.com/archive/p/ioctlbf/downloads
	+ 用法
		::
		
			Scanning by Function code + Transfer type bruteforce from given valid IOCTL:
			ioctlbf.EXE -d deviceName -i 00004000

			Scanning a given IOCTL codes range:
			ioctlbf.EXE -d deviceName -r 00004000-00004fff -f

			Fuzzing only a given IOCTL (quiet mode):
			ioctlbf.EXE -d deviceName -i 00004000 -u -q
- kDriver Fuzzer
	+ 基于ioctlbf框架编写的驱动漏洞挖掘工具
	+ 项目：https://github.com/k0keoyo/kDriver-Fuzzer
	+ 参数说明
		::
		
			"-l" ：开启日志记录模式（不会影响主日志记录模块）
			"-s" ：驱动枚举模块
			"-d" ：打开设备驱动的名称
			"-i" ：待Fuzz的ioctl code，默认从0xnnnn0000-0xnnnnffff
			"-n" ：在探测阶段采用null pointer模式，该模式下极易fuzz 到空指针引用漏洞，不加则常规探测模式
			"-r" ：指定明确的ioctl code范围
			"-u" ：只fuzz -i参数给定的ioctl code
			"-f" ：在探测阶段采用0x00填充缓冲区
			"-q" ：在Fuzz阶段不显示填充input buffer的数据内容
			"-e" ：在探测和fuzz阶段打印错误信息（如getlasterror()）
			"-h" ：帮助信息
	+ 示例
		- ``kDriverFuzz.exe -d X -i 0xaabb0000 -f -l``
			对X驱动的ioctl code 0xaabb0000-0xaabbffff范围进行探测及对可用的ioctl code进行fuzz，探测时除了正常探测外增加0x00填充缓冲区探测，开启数据日志记录（如增加-u参数，则只对ioctl code 0xaabb0000探测，若是有效ioctl code则进入fuzz阶段）
		- ``kDriver Fuzz.exe -d X -r 0xaabb1122-0xaabb3344 -n -l``
			对X驱动的ioctl code 0xaabb1122-0xaabb3344范围内进行探测，探测时采用null pointer模式，并数据日志记录
- IOCTL Fuzzer（Windows）
	+ 说明
		IOCTL Fuzzer 是一个自动化的 windows 内核驱动漏洞挖掘工具，它利用自己的驱动 hook 了 NtDeviceIoControlFile， 目的是接管整个系统所有的 IOCTL 请求。当处理 IOCTL 请求时，一旦符合配置文件中定义的条件，IOCTL Fuzzer 回用随机产生的 fuzz 数据去替换 IOCTL 的原始请求数据。IOCTL Fuzzer 只替换输入数据并不会改变 IOCTL 数据包的其他数据。
	+ 下载：https://code.google.com/archive/p/ioctlfuzzer
	+ xml配置说明
		- fuzzing_type：random，dwords；
		- log_file：设置日志文件的路径和名称
		- hex_dump：是否把IOCTL buffer中的内容记录到日志文件中
		- log_requests：是否控制台方式显示信息
		- debug_log_requests：是否向内核调试器发送信息，可以用DebugView查看
		- fuze_requests：是否对IOCTL进行fuzz
		- fuze_size：对IOCTL进行fuzz时是否改变input buffer的大小
		- 设置目标
			::
			
				<allow>
					<!-- IOCTL request destination driver name. --> 
					//想要FUZZ的驱动程序名称，如果设置了allow列表中的 <drivers>，后面的<deny>中的<drivers>配置将不会生效
					<drivers>
					 <entry>mydriver.sys</entry>
					</drivers>

					<!-- IOCTL request destination device name. -->
					//想要FUZZ的设备名称
					<devices>
					</devices>

					<!-- IOCTL request Control Code. --> 
					//可以指定对某个驱动程序的部分Control Code进行FUZZ
					<ioctls>
					</ioctls>

					<!-- IOCTL request sender process file path/name. -->
					<processes>
					</processes>
				</allow>
		- deny节点
			::
			
				<deny>
					<!-- 
						"deny" list is identical in structure to "allow" list.
					--> 

					<!-- Don't fuzz default Windows drivers. --> 
					<drivers>
						//此列表中的驱动程序将不会被FUZZ，如果<allow>中<drivers>不为空，此列表不会生效
					  <entry>tcpip.sys</entry>
					  <entry>afd.sys</entry>
					  <entry>NDIS.sys</entry>
					  <entry>fltMgr.sys</entry>
					  <entry>ipsec.sys</entry>
					  <entry>mrxsmb.sys</entry>
					  <entry>KsecDD.sys</entry>
					  <entry>netbios.sys</entry>
					  <entry>nsiproxy.sys</entry>
					</drivers>
				</deny>
	+ 使用：``ioctlfuzzer.exe –config ioctlfuzzer.xml``
- syzkaller

综合框架
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- AlphaFuzzer
	AlphaFuzzer是一款多功能的漏洞挖掘框架，截止到1.3版本，AlphaFuzzer只包含了文件格式的漏洞挖掘框架。从1.4版本开始，AlphaFuzzer增加了网络协议漏洞挖掘框架。
- Radamsa
- Honggfuzz