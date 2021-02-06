漏洞挖掘技术
========================================
针对二进制级别的软件，工业界目前普遍采用的是进行 Fuzz 测试(乱拳打死老师傅)。Fuzz 的测试用例往往是带有攻击性的畸形数据，用以触发各种类型的漏洞。

协议漏洞挖掘
----------------------------------------
- `SPIKE <https://resources.infosecinstitute.com/topic/intro-to-fuzzing/>`_
- `Fuzzowski <https://github.com/nccgroup/fuzzowski>`_
- `backfuzz <https://github.com/localh0t/backfuzz>`_
- GANFuzz
- `boofuzz <https://boofuzz.readthedocs.io/en/stable/>`_
- BFuzz

文件型漏洞挖掘
----------------------------------------
FileFuzz可以分为Blind Fuzz和Smart Fuzz。Blind Fuzz即通常所说的“盲测”，就是在随机位置修改数据来生成畸形文件。然而现在的文件格式越来越复杂，Blind Fuzz的代码覆盖率偏低，会产生大量的无用测试用例。针对Blind Fuzz的不足，Smart Fuzz被越来越多地提出和应用。Smart Fuzz即智能Fuzz，通过解析文件格式，然后基于样本和变异来生成畸形文件。它能够识别不同的数据类型，并且能够针目标数据的类型按照不同规则来生成畸形数据。跟Blind Fuzz相比，Smart Fuzz能大大减少无效畸形文件的数量。

Blind Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
一个形象的Blind Fuzzer例子就比如下面让一个猴子去测试应用程序。通过让它胡乱点击电脑的键盘或者移动鼠标，产生不在预期内的输入，从而发现目标程序的bug。（Android应用测试中的Monkey测试也是类似的，它通过胡乱点击Android手机上所有可见的控件，进行压力测试，当Android应用出现闪退或者不能响应的问题时，bug也就发现了）。

- Filefuzz
- `EasyFuzzer <https://bbs.pediy.com/thread-193340.htm>`_

Mutation-based Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
基于变异的Fuzzer（mutation-based fuzzer）不再是胡乱的产生输入，而是在已知合法的输入的基础上，对该输入进行随机变种或者依据某种经验性的变种，从而产生不可预期的测试输入。

- Taof
- GPF
- ProxyFuzz
- `Peach Fuzzer <https://sourceforge.net/projects/peachfuzz/>`_

Generation-based Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
基于变异的Fuzzer对于合法的输入集合有较强的依赖性。为了能够测试尽可能多的输入类型，必须要有足够丰富类型的合法输入，以及花样够多的变种方式。。如果测试人员对目标程序或者协议已经有了较为充分的了解，那么也有可能制造出更为高效的Fuzzer工具（通过对目标协议或文件格式进行建模）。即，测试的目的性更强，输入的类型有意识的多样化，将有可能更快速的挖掘到漏洞。这类方法的名称叫做基于模板的Fuzzer（Generation-based）。

- `boofuzz <https://boofuzz.readthedocs.io/en/stable/>`_
- `Peach Fuzzer <https://sourceforge.net/projects/peachfuzz/>`_
- SPIKE
- Sulley
- Mu‐4000
- Codenomicon

Evolutionary-based Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
基于程序代码的覆盖率是一个此类方法的核心，主要有路径覆盖率（可以有类似的利用BL算法的路径标记和压缩算法），分支覆盖率，代码行覆盖率。

- 相关工具
	- `afl-fuzz <https://lcamtuf.coredump.cx/afl/>`_
	- `Winafl <https://github.com/googleprojectzero/winafl>`_
	- `libFuzzer <https://github.com/Dor1s/libfuzzer-workshop>`_
		libFuzzer 和要被测试的库链接在一起，通过一个模糊测试入口点（目标函数），把测试用例喂给要被测试的库。fuzzer会跟踪哪些代码区域已经测试过，然后在输入数据的语料库上进行变异，来使代码覆盖率最大化。代码覆盖率的信息由 LLVM 的SanitizerCoverage 插桩提供。
		``clang++ -g -std=c++11 -fsanitize=address,fuzzer first_fuzzer.cc ./libFuzzer/libFuzzer.a -o first_fuzzer``

其它
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- Fuzzgrind
- `FileFuzz <https://bbs.pediy.com/thread-125263.htm>`_
- MiniFuzz
- `pngcheck <http://www.libpng.org/pub/png/apps/pngcheck.html>`_
- `pdfcheck <https://www.datalogics.com/products/pdf-tools/pdf-checker/>`_

FTP漏洞挖掘
----------------------------------------

Email漏洞挖掘
----------------------------------------

ActiveX漏洞挖掘
----------------------------------------

代码审计
----------------------------------------

工控系统协议漏洞挖掘
----------------------------------------
- `modbus fuzzer <https://github.com/youngcraft/boofuzz-modbus>`_

智能建筑协议漏洞挖掘
----------------------------------------
- `BACnet fuzzer <https://github.com/VDA-Labs/BACnet-fuzzer>`_

RTSP协议漏洞挖掘
----------------------------------------
- `RTSPhuzz <https://github.com/IncludeSecurity/RTSPhuzz>`_

iec60870电力系统漏洞挖掘
----------------------------------------
- `iec60870_fuzzing_scripts <https://github.com/robidev/iec60870_fuzzing_scripts>`_