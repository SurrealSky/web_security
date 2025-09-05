驱动漏洞挖掘
---------------------------------------
- 自动化分析脚本：``https://github.com/TakahiroHaruyama/VDR?tab=readme-ov-file``
	+ 本地文件：`VDR-main.zip <..//_static//VDR-main.zip>`_
- `DriverView驱动查看工具 <http://www.nirsoft.net/utils/driverview.html>`_
- `DeviceTree驱动关联设备查看工具 <http://www.osronline.com/article.cfm%5earticle=97.htm>`_
- `WinObj查看符号链接 <http://technet.microsoft.com/en-us/sysinternals/bb896657>`_
- IOCTLCODE解码
	+ IDA插件：https://github.com/FSecureLABS/win_driver_plugin
	+ OSR Online IOCTL Decoder：http://www.osronline.com/article.cfm%5Earticle=229.htm
	+ pediy_IOCTL_DECODE
- IRP监控器
	+ IrpTracker(x86)：http://www.osronline.com/article.cfm%5earticle=199.htm
	+ IRPMon(x64)：https://github.com/MartinDrab/IRPMon
- IOCTLpus
	+ 说明：测试IOCTL CODE的有效性
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
		IOCTL Fuzzer 是一个自动化的 windows 内核驱动漏洞挖掘工具，它利用自己的驱动 hook 了 NtDeviceIoControlFile， 目的是接管整个系统所有的 IOCTL 请求。当处理 IOCTL 请求时，一旦符合配置文件中定义的条件，IOCTL Fuzzer 会用随机产生的 fuzz 数据去替换 IOCTL 的原始请求数据，此方法只能被动的等待通信发生，进行数据变异。
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