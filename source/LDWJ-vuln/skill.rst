漏洞挖掘技术
========================================
针对二进制级别的软件，工业界目前普遍采用的是进行 Fuzz 测试。Fuzz 的测试用例往往是带有攻击性的畸形数据，用以触发各种类型的漏洞。

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
- Filefuzz

Smart Fuzz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- Peach
- Fuzzgrind
- afl-fuzz
- Winafl
- `FileFuzz <https://bbs.pediy.com/thread-125263.htm>`_
- MiniFuzz

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