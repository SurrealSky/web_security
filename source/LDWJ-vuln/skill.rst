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

- `boofuzz(python) <https://boofuzz.readthedocs.io/en/stable/>`_
	 **网络协议** fuzz工具。
- `Peach Fuzzer(linux/windows) <https://sourceforge.net/projects/peachfuzz/>`_
	Peach支持对 **文件格式、ActiveX、网络协议** 进行Fuzz测试，Peach Fuzz的关键是编写Peach Pit配置文件。
- SPIKE（linux）
	 **网络协议** fuzz工具。
- Sulley
- Mu‐4000
- Codenomicon

Evolutionary-based Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
基于程序代码的覆盖率是一个此类方法的核心，主要有路径覆盖率（可以有类似的利用BL算法的路径标记和压缩算法），分支覆盖率，代码行覆盖率。

- 相关工具
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

工控系统协议漏洞挖掘
----------------------------------------

相关协议
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ Modbus
	| Modbus是由Modicon（现为施耐德电气公司的一个品牌）在1979年发明的，是全球第一个真正用于工业现场的总线协议。ModBus网络是一个工业通信系统，由带智能终端的可编程序控制器和计算机通过公用线路或局部专用线路连接而成，可应用于各种数据采集和过程监控。
	| ModBus网络只有一个主机，所有通信都由它发出。网络可支持247个之多的远程从属控制器，但实际所支持的从机数要由所用通信设备决定。采用这个系统，各PC可以和中心主机交换信息而不影响各PC执行本身的控制任务。
	| 标准端口：502
+ EtherNet/IP
	| EtherNet Industry Protoco1是适合工业环境应用的协议体系。它是基于控制与信息协议CIP(Control and Informal/on Protoco1)的网络，是一种是面向对象的协议，能够保证网络上隐式的实时I/0信息和显式信息(包括用于组态参数设置、诊断等)的有效传输。EtherNet/IP采用标准的EtherNet和TCP/IP技术来传送CIP通信包，通用且开放的应用层协议CIP加上已经被广泛使用的EtherNet和TCP/IP协议，就构成EtherNet/IP协议的体系结构。
	| 标准端口：44818
+ DNP3
	| DNP(Distributed Network Protocol，分布式网络协议)是一种应用于自动化组件之间的通讯协议，常见于电力、水处理等行业。SCADA可以使用DNP协议与主站、RTU（远程终端设备）、及IED（智能电子设备）进行通讯。
	| DNP3协议是一个广泛应用于电力系统中子站与主站通讯的协议，因为DNP3协议可以封装在以太网TCP/IP上运行（默认端口为TCP的 20000端口），这样难免就会有暴露在公网的情况，而DNP3协议也比较特殊，其主要应用在电力行业，在暴露的数据中肯定不乏一些电力行业的设备以及系统。
	| 标准端口：20000
+ BACnet
	| 楼宇自动控制网络数据通讯协议（A Data Communication Protocol for Building Automation and Control Networks）是由美国暖通、空调和制冷工程师协会(ASHRAE )组织的标准项目委员会135P (Stand Project Committee即SPC 135P)历经八年半时间开发的。BACnet 协议是为计算机控制采暖、制冷、空调系统和其他建筑物设备系统定义服务和协议，从而使BACnet协议的应用以及建筑物自动控制技术的使用更为简单。
	| 标准端口：47808
+ Siemens S7
	| Siemens S7属于第7层的协议，用于西门子设备之间进行交换数据，通过TSAP（Transport Service Access Point,传输服务访问点），可加载MPI（Multi Point Interface，多点接口），DP（传输协议，实现控制CPU和分布式I/O之间快速、循环的数据交换），以太网等不同物理结构总线或网络上，PLC一般可以通过封装好的通讯功能块实现。
	| 标准端口：102
+ OMRON FINS
	| 欧姆龙是来自日本的知名电子和自控设备制造商，其中小型PLC在国内市场有较高的市场占有量，有CJ、CM等系列，PLC可以支持Fins，Host link等协议进行通信。支持以太网的欧姆龙PLC CPU、以太网通信模块根据型号的不同，一般都会支持FINS(Factory Interface Network Service)协议，一些模块也会支持EtherNet/IP协议，Omron fins协议使用TCP/UDP的9600端口进行通信，fins协议封装在TCP/UDP上进行通信，需要注意的是TCP模式下组包和UDP模式下在头部上有所差异。具体协议包的构造可以参考欧姆龙官方的协议文档。FINS协议实现了OMRON PLC与上位机以太网通信。
+ MELSEC-Q
	| 三菱Q系列PLC以太网模块系统默认开放了TCP的5007端口和UDP的5006端口用于与GX软件进行通信，通过对通讯协议的分析，可以实现对该系列PLC设备的识别和发现。
	| 标准端口：5007
+ Tridium Niagara Fox
	| Tridium是Honeywell旗下独立品牌运作的全资子公司。采用Tridium技术的世界著名品牌包括：Honeywell，Siemens，JCI，Schneider，Samsung 和IBM等。Tridium创造性的开发了软件框架“Niagara Framework”。基于Niagara框架可以集成、连接各种智能设备和系统，而无需考虑它们的制造厂家和所使用的协议，形成一个统一的平台，实现互联互通互操作，并可以通过互联网基于Web浏览器进行实时控制和管理。另外，基于Niagara框架，客户可以进行二次开发，实现其专有的应用，开发其专有的产品。
	| NiagaraAX平台到今天已经整合了不同层级的东西，之前谈论的大多数都是设备，硬件设备是为建筑或者园区提供基础设置的，另外一些包括安防系统、访客管理、能源计费系统、管理服务、设备、设施维护计划，资产管理、设施管理等系统，NiagaraAX可以把这些基础设备和系统相互衔接起来，使用专有的Tridium Niagara Fox协议通信，给客户创造价值。
	| 标准端口：1911
+ PCWorx
	| 2005年，菲尼克斯电气公司首次推出中文版大型工控软件 PCWORX，这是欧美公司推出的第一套中文版大型工控软件。该中文版工控软件的推出将极大地方便中国用户对于先进自动化技术的学习和使用，代表了欧美公司对中国市场的又一贡献。菲尼克斯电气的自动化技术 AUTOMATIONWORX 不仅由大量的硬件和支持软件所构成，可以形成各种典型的自动化系统，如单纯的总线系统，具有安全功能的总线系统，以太网与总线相结合的系统，以及正在推出的网络技术”E网到底”的自动化系统；它还涵盖了 INTERBUS、Ethernet PROFINET、工业无线通讯、光纤以及安全等技术，PCWORX3.11是菲尼克斯电气公司的专用协议。
	| 标准端口：1962
+ ProConOs
	| ProConOS是德国科维公司（KW-Software GmbH）开发的用于PLC的实时操作系统，ProConOS embedded CLR是新型的开放式标准化PLC运行时系统，符合IEC 61131标准，可执行不同的自动化任务（PLC、PAC、运动控制、CNC、机器人和传感器）。通过采用国际标准的微软中间语言（依据IEC/ISO 23271标准为MSIL/CIL）作为设备接口，可使用C＃或IEC 61131标准语言对ProConOS Embedded CLR编程，ProConOS Embedded CLR为客户提供了实时的嵌入式应用。该操作系统使用ProConOs专有的工控协议通讯，服务端口号是20547。
	| 标准端口：20547
+ IEC 60870-5-104
	| IEC 60870-5-104是国际电工委员会制定的一个规范，用于适应和引导电力系统调度自动化的发展，规范调度自动化及远动设备的技术性能。IEC 60870-5-104可用于交通行业，利用IEC104规约实现城市轨道交通中变电站与基于城域网的综合监控系统的集成通信是非常好的一个方法，它既保证了电力监控系统的开放性，又能很好的满足城市轨道交通系统对电力监控系统信息传输的实时、可靠等要求，又有利于利用标准化的优势带来开发的便捷性。
	| 标准端口：2404
+ Crimson v3.0
	| 红狮(Red Lion Controls)控制系统制造公司位于美国的宾西法尼亚州，可以制造多种工业控制产品从定时器和计数器到精密复杂的人机界面，具有最新的贴片安装和板上芯片的生产能力。红狮工程团队可以提供各种新产品设计，从应用范围很广的标准控制产品到根据客户和OEM的要求而定做的产品。美国红狮控制公司为其交货迅速、良好的客户服务和高质量的技术支持而引以为豪。
	| Crimson v3.0 是redlion公司最受欢迎的工控系统配置软件，产品协议成为自动化市场最受欢迎的协议之一，免费的Crimson3.0软件拥有强大的功能，支持拖拉式组态结构，显示，控制，数据记录仪功能，是为了充分发挥MC系列产品的功能而设计开发的。大部分简单的应用程序可以一步步建立，配置相关的通讯协议和数据标签。内置多种串口和以太网口驱动程序选择菜单，可以数秒内将数据下载到MC上，内置各种驱动程序，无需编写任何代码就可以和各种PLC，PC机和SCADA系统通讯。
	| 标准端口：789
	
工具
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- `modbus fuzzer <https://github.com/youngcraft/boofuzz-modbus>`_
- `BACnet fuzzer <https://github.com/VDA-Labs/BACnet-fuzzer>`_
- `iec60870_fuzzing_scripts <https://github.com/robidev/iec60870_fuzzing_scripts>`_
- `RTSPhuzz <https://github.com/IncludeSecurity/RTSPhuzz>`_

其它
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 协议识别：https://www.zoomeye.org/topic?id=ics_project