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
- `Winafl（windows） <https://github.com/googleprojectzero/winafl>`_
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