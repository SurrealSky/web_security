﻿ios漏洞挖掘
========================================

文件结构
----------------------------------------
- 锁屏密码
	+ /data/system/gesture.key ##手势密码文件
	+ /data/system/password.key ##其他密码文件

应用层安全
----------------------------------------
开源的安卓漏洞扫描平台，技术重点是静态代码审计，但是静态代码审计大家都懂的，如果没有符号执行或者污点扩散分析等理论支撑，仅仅靠缺陷模式匹配有很多漏洞都扫不出来。实际上现在市面上免费的安卓漏扫平台都是只能扫风险，扫出来的漏洞大都属于不可利用、很难利用甚至误报。真正能扫出高危漏洞的工具只在一些有多年挖洞经验的系统安全研究团队里。


加固
----------------------------------------

系统漏洞
----------------------------------------

相关工具
----------------------------------------
- Drozer
- Intent Sniffer
- Intent Fuzzer
- Android Security Evaluation Framework (ASEF)
- AFE(Android Framework for Exploitation)
- X-Ray
- Smartphone Pentest Framework (SPF)
- dSploit(nowadays, dSploit merges with zANTI2)

