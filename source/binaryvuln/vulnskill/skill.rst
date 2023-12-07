思路和技巧
========================================

攻击面（AttackSurface）研究
----------------------------------------

文件解析漏洞
----------------------------------------
+ 工程文件
	- 恶意工程文件
		工程文件中是否含有js，py脚本等
	- zip slip漏洞
		::
		
			生成工具：https://github.com/usdAG/slipit
			如：./slipit evil.zap17.zip ncrypt.dll --depth 10 --prefix "Program Files\Siemens"
			注：可同时利用dll劫持达到本地执行。
	- 序列化漏洞
		很难遇到。
+ 其它文件
	- 图片，pdf等
+ Fuzz
	- afl
	- peach

通信协议漏洞
----------------------------------------
+ 未授权漏洞
	- 文件读写
	- 命令执行
+ 拒绝服务
	- FUZZ
	- 畸形数据包

软件程序分析
----------------------------------------

DLL劫持漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 分类
	+ 针对应用程序安装目录的 DLL 劫持
		在查找 DLL 时应用程序本身所在的目录都是最先被搜索的。因此如果能够放一个恶意的 DLL 文件到程序的安装目录，就可以利用 DLL 劫持漏洞来执行代码。
	+ 针对文件关联的 DLL 劫持
		当在资源管理器中打开某种特定类型的文件时，操作系统会自动创建一个进程来处理这个文件，进程对应的程序就是该文件类型关联的默认处理程序，进程的当前目录就是被打开文件所在的目录。
	+ 针对安装程序的 DLL 劫持
		与 针对应用程序安装目录的DLL劫持 比较类似。
- 挖掘思路
	+ Process Monitor工具
		::
			
			Path ends with .dll
			Result is NAME NOT FOUND
			Process Name contains 进程名称
			打开exe或者使用某些功能时，进行如上过滤，观察输出。
	+ AheadLib
		用于生成劫持dll文件的CPP源码文件，使用VS编译生成劫持dll。
- 提权
	如果系统服务存在dll劫持，会造成提权漏洞。

升级漏洞
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 攻击面
	- 采用不安全的HTTP通信协议与服务器交互，并未对服务器返回的新版升级程序文件进行任何校验，攻击者可以利用中间人技术，通过篡改网络数据包中的更新配置内容，使受害主机下载任意恶意文件并自动触发，从而达到全面控制客户端的攻击效果。
	- 不安全的升级方案，利用白名单升级程序过AV检测。

危险函数检测
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	- 常见危险函数
		::
		
			strcpy
	- 动态插桩检测
		- 使用frida hook危险函数，观察输入数据是否可控。
	- IDA插件静态检测
		- https://github.com/Accenture/VulFi

代码覆盖率
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ drrun
	- DynamoRIO工具组件见 :ref:`binaryvuln/tools/vulner:二进制程序以及源码级挖掘`
	- 示例
		::
		
			生成覆盖率文件：
			drrun.exe -t drcov -dump_text -- test_gdiplus.exe 1.bmp
			在当前目录中生成.log文件，打开文件，修改头部DRCOV VERSION为2
			IDA使用Lighthouse插件，打开test_gdiplus.exe程序，
			点击File，Load file，Code coverage file，打开log文件
+ frida
	- 项目地址：``https://github.com/gaasedelen/lighthouse/tree/develop/coverage/frida``
	- 示例：``python frida-drcov.py <process name | pid>``
	- 指定输出文件：``python frida-drcov.py -o more-coverage.log foo``
	- 白名单模块：``python frida-drcov.py -w libfoo -w libbaz foo``
	- 指定线程：``python frida-drcov.py -t 543 -t 678 foo``
+ pin
	- 项目地址：``https://github.com/gaasedelen/lighthouse/tree/develop/coverage/pin``
	- 编译好的：``https://github.com/gaasedelen/lighthouse/releases`` ，注意官网编译的版本需要和pin版本对应。
	- 示例：``pin -t C:\CodeCoverage.dll -- C:\HashCalc.exe``

函数级跟踪
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ frida
	- ``frida-trace -p [pid] -a MODULE!OFFSET``
	- ``frida-trace -p [pid] -i FUNCTION`` ,函数名可以使用通配符。
+ drrun
	- 跟踪系统函数（NT*）
		+ ``drrun.exe -t drstrace  -- C:\HashCalc.exe``
		+ 初次运行，自动下载pdb符号库
	- 跟踪win32函数调用
		+ drmemory包含的工具
		+ 解压DynamoRIO后，使用时，需要将 ``dynamorio\lib32\release\dynamorio.dll`` 放在drmemory目录下。
		+ 参看单独的工具：``https://github.com/mxmssh/drltrace/releases``
		+ 命令：``drltrace.exe -only_from_app -print_ret_addr -- cmd /C dir``
		+ 运行后，在当前目录下生成drltrace.*文件。
+ pin
	+ ``pin -t obj-ia32\proccount.dll -- cmd /C dir``

windows驱动漏洞挖掘
----------------------------------------

基础
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 驱动对象创建驱动设备，设备名称形如（ **\\Device\\设备名** ）只能在内核访问, 所以有了设备的别名即 **符号链接** (内核中形如 **\\dosDevices\\设备名** 或 **\\??\\设备名** )。
+ 3环程序通过CreateFile函数打开符号链接(形如 **\\\\.\\DeviceName** )，获取驱动设备句柄。
+ 3环的程序向驱动发出I/O请求时，是由 **DeviceIoControl** 等函数所完成的
+ 不是所有驱动都使用符号链接和用户层进行通信，有很多驱动不是以这种方式和用户进行数据交换

DeviceIoControl函数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 原型
	::
	
		BOOL WINAPI DeviceIoControl(
		  _In_        HANDLE       hDevice,
		  _In_        DWORD        dwIoControlCode,
		  _In_opt_    LPVOID       lpInBuffer,
		  _In_        DWORD        nInBufferSize,
		  _Out_opt_   LPVOID       lpOutBuffer,
		  _In_        DWORD        nOutBufferSize,
		  _Out_opt_   LPDWORD      lpBytesReturned,
		  _Inout_opt_ LPOVERLAPPED lpOverlapped
		);
		
		参数：
		hDevice [in]
			需要执行操作的设备句柄。该设备通常是卷，目录，文件或流，使用 CreateFile 函数打开获取设备句柄。
		dwIoControlCode [in]
			操作的控制代码，该值标识要执行的特定操作以及执行该操作的设备的类型,每个控制代码决定lpInBuffer，nInBufferSize，lpOutBuffer和nOutBufferSize参数的使用细节。
		lpInBuffer [in, optional]
			（可选）指向输入缓冲区的指针。这些数据的格式取决于dwIoControlCode参数的值。
		nInBufferSize [in]
			输入缓冲区以字节为单位的大小。单位为字节。
		lpOutBuffer [out, optional]
			（可选）指向输出缓冲区的指针。这些数据的格式取决于dwIoControlCode参数的值。
		nOutBufferSize [in]
			输出缓冲区以字节为单位的大小。单位为字节。
		lpBytesReturned [out, optional]
			（可选）指向一个变量的指针，该变量接收存储在输出缓冲区中的数据的大小。如果输出缓冲区太小，无法接收任何数据，则GetLastError返回ERROR_INSUFFICIENT_BUFFER,
				错误代码122(0x7a)，此时lpBytesReturned是零。
			如果输出缓冲区太小而无法保存所有数据，但可以保存一些条目，某些驱动程序将返回尽可能多的数据,在这种情况下，调用失败，GetLastError返回ERROR_MORE_DATA,
				错误代码234，lpBytesReturned指示接收到的数据量。您的应用程序应该再次使用相同的操作调用DeviceIoControl，指定一个新的起点。
		lpOverlapped [in, out, optional]
			（可选）指向OVERLAPPED结构的指针,
			如果在未指定FILE_FLAG_OVERLAPPED的情况下打开hDevice，则忽略lpOverlapped。
			如果使用FILE_FLAG_OVERLAPPED标志打开hDevice，则该操作将作为重叠（异步）操作执行。

		返回值:
			如果操作成功完成，DeviceIoControl将返回一个非零值。

			如果操作失败或正在等待，则DeviceIoControl返回零。 要获得扩展的错误信息，请调用GetLastError。
+ dwIoControlCode
	|ioctl1|
	::
	
		由宏CTL_CODE构成，可分为四部分：
		#define CTL_CODE( DeviceType, Function, Method, Access ) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
		DeviceType(16-31) + Access(14-15) + Function(2-13) + Method(0-1)
		DeviceType表示设备类型；
		Access表示对设备的访问权限；
		Function表示设备IoControl的功能号，0~0x7ff为微软保留，0x800~0xfff由程序员自己定义；
		Method表示3环与0环通信中的内存访问方式。
		
		Method部分又有四种内存访问方式：
		METHOD_BUFFERED(0):对I/O进行缓冲 
		从ring3输入数据：在Win32 API DeviceIoControl函数的内部，用户提供的输入缓冲区的内容被复制到ring 0 IRP的pIRP->AssociatedIrp.SystemBuffer的内存地址，复制的字节是有DeviceControl指定的输入字节数。
		从ring0输出数据：系统将AssociatedIrp.SystemBuffer的数据复制到DeviceIoControl提供的输出缓冲区，复制的字节数由pIrp->IoStatus.Information指定，DeviceIoControl也可以通过参数lpBytesReturned得到复制的字节数。       
		这种方式避免了驱动程序在内核态直接操作用户态内存地址的问题，过程比较安全。
		
		METHOD_IN_DIRECT(1):对输入不进行缓冲 
		METHOD_OUT_DIRECT(2):对输出不进行缓冲 
		
		METHOD_NEITHER(3):都不缓冲 
		很少被用到，直接访问用户模式地址，要求调用DeviceIoControl的线程和派遣函数运行在同一个线程设备上下文中。
		往驱动中Input数据：通过I/O堆栈的Parameters.DeviceIoControl.Type3InputBuffer得到DeviceIoControl提供的输入缓冲区地址，Parameters.DeviceIoControl.InputBufferLength得到其长度。
		  由于不能保证传递过来的地址合法，所以需要先要结果ProbeRead函数进行判断。
		从驱动中Output数据：通过pIrp->UserBuffer得到DeviceIoControl函数提供的输出缓冲区地址，再通过Parameters.DeviceIoControl.OutputBufferLength得到输出缓冲区大小。同样的要用ProbeWrite函数先进行判断。

挖掘思路
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 信息搜集
	- 符号连接
		::
		
			寻找IoCreateSymbolicLink函数调用参数。
	- IOCTL CODE
		- 监控正常交互
		- 暴力破解
		- 逆向分析
			::
			
				分析DriverEntry入口函数中DriverObject->MajorFunction[0xE]的指针值（IRP_MJ_DEVICE_CONTROL），
				因为在该指针处定义的函数使用了DeviceIoControl及其包含的I/O控制代码（IOCTL）来处理从用户模式发出的请求。
				或
				寻找对IofCompleteRequest的调用，然后从调用向上滚动，以查找DWORD比较。
				或
				搜索Text，"jumptable"
+ 逆向代码审计
+ IoControl MITM (Man-in-the-Middle) Fuzz
	- 定义：通过对NtDeviceIoControlFile函数进行hook操作，从而接管用户层和内核层的通信，当监控到通信操作对其中的输入输出数据进行变异操作，属于被动等待式的FUZZ。
+ IoControl Driver Fuzz
	- 定义：主动对内核驱动模块进行通信，首先需要通过逆向手段获得驱动的设备名称以及派遣函数对应的IoControlCode，接着对数据进行变异以后通过主动调用DeviceIoControl函数来完成FUZZ。
	- 流程
		+ 确定驱动设备名称
		+ 确定有效的IOCTL CODE
		+ IOCTL测试
		+ ioctl FUZZ
	- 变异策略
		+ Method != METHOD_NEITHER：由于输入输出都有系统保护，因此修改地址没有意义，需要变异的数据只有：输入数据，输入长度，输出长度。
		+ Method == NMETHOD_NEITHER：驱动中可能直接访问输入输出地址，而没有探测是否可写，因此需要变异的数据有：输入地址，输入数据，输出地址，输出长度。

	.. |ioctl1| image:: ../../images/ioctl1.png