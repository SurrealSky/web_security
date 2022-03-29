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
- BFuzz

文件型漏洞挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `FileFuzz <https://bbs.pediy.com/thread-125263.htm>`_
- `EasyFuzzer <https://bbs.pediy.com/thread-193340.htm>`_
- Taof
- GPF
- ProxyFuzz
- `Peach Fuzzer(linux/windows) <https://sourceforge.net/projects/peachfuzz/>`_
	Peach支持对 **文件格式、ActiveX、网络协议** 进行Fuzz测试，Peach Fuzz的关键是编写Peach Pit配置文件。
- Sulley
- Mu‐4000
- Codenomicon
- Fuzzgrind
- MiniFuzz
- `pngcheck <http://www.libpng.org/pub/png/apps/pngcheck.html>`_
- `pdfcheck <https://www.datalogics.com/products/pdf-tools/pdf-checker/>`_

二进制程序以及源码级挖掘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `afl-fuzz（linux） <https://lcamtuf.coredump.cx/afl/>`_
	AFL全称是American Fuzzy Lop，由Google安全工程师Michał Zalewski开发的一款开源fuzzing测试工具，原理是在相关代码处插桩，因此AFL主要用于对 **开源软件** 进行测试。当然配合QEMU等工具，也可对 **闭源二进制代码** 进行fuzzing，但执行效率会受到影响。
	::
			
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
	
- `Winafl（windows） <https://github.com/googleprojectzero/winafl>`_
	基于二进制插桩工具DynamoRIO。
- `libFuzzer(linux) <https://github.com/Dor1s/libfuzzer-workshop>`_
	libFuzzer 和要被测试的库链接在一起，通过一个模糊测试入口点（目标函数），把测试用例喂给要被测试的 **库函数（开源或闭源）** 。fuzzer会跟踪哪些代码区域已经测试过，然后在输入数据的语料库上进行变异，来使代码覆盖率最大化。代码覆盖率的信息由 LLVM 的SanitizerCoverage 插桩提供。
	``clang++ -g -std=c++11 -fsanitize=address,fuzzer first_fuzzer.cc ./libFuzzer/libFuzzer.a -o first_fuzzer``
- syzkaller
	Syzkaller是Google开发的一款内核模糊测试工具，简单点说就是自动化向内核输入各种有效的、无效的、完全随机化的参数数据，并观察内核的运行状况，是否发生了panic、内存泄漏等问题，以此发现隐藏在内核中的漏洞。近些年很多内核的CVE发现均来自于此，而且该工具的开发维护还挺活跃的。而且它不仅支持x86，还支持ARM、Power、MIPS等处理器，而且不仅支持Linux，还支持windows、FreeBSD、Fuchsia等系统，同时还能支持对远程物理机、本地虚拟机的测试，此外还能支持分布式多机器测试。

固件分析
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- binwalk
	+ 固件扫描:``binwalk firmware.bin``
	+ 提取文件:``binwalk -eM firmware1.bin firmware2.bin firmware3.bin``
	+ 文件比较:``binwalk -W --block=8 --length=64 firmware1.bin firmware2.bin``
	+ 指令系统分析:``binwalk -A firmware.bin``
	+ 熵分析:``binwalk -E firmware.bin``
	+ 插件分析:``binwalk --enable-plugin=zlib firmware.bin``
	
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