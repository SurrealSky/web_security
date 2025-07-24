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

DLL劫持漏洞
----------------------------------------
- 分类
	+ 针对应用程序安装目录的 DLL 劫持
		- 在查找 DLL 时应用程序本身所在的目录都是最先被搜索的。因此如果能够放一个恶意的 DLL 文件到程序的安装目录，就可以利用 DLL 劫持漏洞来执行代码。
	+ 针对文件关联的 DLL 劫持
		- 当在资源管理器中打开某种特定类型的文件时，操作系统会自动创建一个进程来处理这个文件，进程对应的程序就是该文件类型关联的默认处理程序，进程的当前目录就是被打开文件所在的目录。
	+ 针对安装程序的 DLL 劫持
		- 与 针对应用程序安装目录的DLL劫持 比较类似。
	+ 针对CreateProcess函数的lpCommandLine参数问题劫持
		- CreateProcess执行该路径时未加引号，同时lpApplicationName为NULL，系统会按以下方式依次解析该路径：
		- 解析:``c:\program files\sub dir\1.exe``
		- c:\\program.exe：系统首先会尝试将路径从字符串的开始部分截断，解析为 c:\\program.exe。
		- c:\\program files\\sub.exe：如果第一个解析失败，系统会尝试将路径解析为 c:\\program files\\sub.exe。
		- 最后系统尝试解析整个路径，认为 1.exe 是可执行文件名，并尝试执行它。

- 挖掘思路
	+ Process Monitor工具
		::
			
			Path ends with .dll
			Result is NAME NOT FOUND
			Process Name contains 进程名称
			打开exe或者使用某些功能时，进行如上过滤，观察输出。
	+ AheadLib
		用于生成劫持dll文件的CPP源码文件，使用VS编译生成劫持dll。

升级漏洞
----------------------------------------
+ 攻击面
	- 采用不安全的HTTP通信协议与服务器交互，并未对服务器返回的新版升级程序文件进行任何校验，攻击者可以利用中间人技术，通过篡改网络数据包中的更新配置内容，使受害主机下载任意恶意文件并自动触发，从而达到全面控制客户端的攻击效果。
	- 不安全的升级方案，利用白名单升级程序过AV检测。
+ 利用竞争条件
    - 当下载文件具有某种校验无法绕过时，利用检查时间到使用时间的（TOCTOU）漏洞，利用竞争条件在检查之后，执行之前替换二进制文件。

TOCTOU
----------------------------------------
+ TOCTOU即是time-of-check-to-time-of-use的缩写，是条件竞争漏洞的一种。
+ 多出现在类Unix系统对文件系统的操作上，但是也可能在别的环境下发生，例如对本地sockets或数据库事务的使用。
+ 利用机制
    - oplock是一种可以放置在文件上的锁，当其他进程想要访问该文件时，它可以被告知—同时延迟这些进程的访问，以便锁定进程可以在解除锁之前让文件处于适当的状态。
+ 相关工具
    - SetOpLock
    - BaitAndSwitch
+ 场景示例
    ::
    
        当X应用程序运行的过程中，在某个操作之前，比如读文件，会检查一下文件是否存在与是否具有权限，
        在检查与真正的读取之间的间隔就是一个可以被利用的竞争条件（Race Condition），在这个间隔中我
        们可以将需要越权读取的文件替换成自己的文件，使其检查过程通过，这样就可以越权读取其他用户的
        文件。

权限提升（LPE）漏洞
----------------------------------------
+ 服务可执行文件可读写
    - 服务对应的可执行文件exe，其它低权限用户可读写。
+ DLL劫持
    - 服务进程DLL文件劫持
+ 文件移动操作劫持
    - 原理
        + Windows平台下高权限进程的Symlink攻击（高权限进程在操作文件时，未作严格的权限校验，导致攻击利用符号链接到一些受保护的目录文件，比如C盘的系统DLL文件，后面系统或应用去自动加载时，实现代码执行并提权）。
        + 应用程序在写入文件时，使用了SYSTEM用户权限，这种不安全的权限设置导致任意系统文件均可被重写。
        + 日志中的文件内容用户可控，攻击者向日志文件注入控制命令，然后将其存储为batch为文件来执行实现提权。
        + 基于windows符号链接来实现系统任意文件的读写。
    - 利用方式
        + 使用Promon监控进程文件写入行为。
            ::
            
                过滤Process Name为目标进程名，Opreation为WriteFile。
                检查程序是否使用administrator或SYSTEM权限进行操作文件。
        + 检查权限
            ::
            
                检查普通用户(Everyone)拥有对这些文件的完全控制权限。
        + 创建普通权限用户
            ::
            
                创建一个普通用户登录，查看是否对目标文件具有完全控制权限。
        + 创建软链接或符号链接
            ::
            
                创建软链接方法（任意文件读，写，删除等漏洞）：
                CreateMountPoint.exe D:\test C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
                此时，当进程操作test目录下文件，即是对系统启动目录下的文件操作。
                注：可以控制文件内容中包含如 & mkdir c:\windows\test &，就可进行命令执行。
                
                创建符号链接方法（任意文件读写漏洞）
                CreateSymlink.exe test\2.txt c:\2.bat
                注：test目录必须为空。
    - 若程序对CreateFile函数调用，检测GetLastError为REPARSE（重解析）导致漏洞无法利用

程序分析方法
----------------------------------------

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
	- DynamoRIO工具组件见 :ref:`terminal/vulnskill/tools/vulner:二进制程序黑盒FUZZ`
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
+ 设备名称：驱动对象创建驱动设备，设备名称形如（ **\\Device\\设备名** ）只能在内核访问(内核中形如 **\\dosDevices\\设备名** 或 **\\??\\设备名** )。
+ 符号链接：3环程序通过CreateFile函数打开符号链接(形如 **\\\\.\\DeviceSymlink** )，获取驱动设备句柄。
+ 3环的程序向驱动发出I/O请求时，是由 **DeviceIoControl** 等函数所完成的
+ 不是所有驱动都使用符号链接和用户层进行通信，有很多驱动不是以这种方式和用户进行数据交换

查询驱动
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 命令：``driverquery /v /fo list``
+ 目录：``C:\Windows\System32\drivers``
+ Sysinternals套件中的Autoruns工具

DeviceIoControl函数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 基础
	- MajorFunctions数组存储了驱动程序设备的行为调度例程。
	- MajorFunctions数组特殊索引，它定义为IRP_MJ_DEVICE_CONTROL。
	- 它指向在驱动程序的设备上调用DeviceIoControl API后被调用的调度例程的函数指针。
		::
		
			IRP_MJ_CREATE是在调用CreateFile这个API时驱动程序将要调用的函数的指针的索引；
			IRP_MJ_READ是与ReadFile等函数相关的索引。
			IRP_MJ_DEVICE_CONTROL与DeviceIoControl相对应的索引。
	- 位于索引IRP_MJ_DEVICE_CONTROL处的调度例程，其代码大体上就是一个switch语句。
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

COM漏洞挖掘
----------------------------------------

COM基础
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ COM(微软组件对象模型)，是一种独立于平台的分布式系统，用于创建可交互的二进制软件组件。 
+ COM 是 Microsoft 的 OLE (复合文档) 和 ActiveX (支持 Internet 的组件) 技术的基础技术。
+ 注册表项： ``HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID`` 下，包含COM对象的所有公开的信息。
	::
	
			ProgID ： 代表COM名称
			UUID ： 代表COM
			CLSID ： 代表COM组件中的类
			IID ：代表COM组件中的接口
+ COM组件搜索顺序
	::
	
		HKCU\Software\Classes\CLSID
		HKCR\CLSID
		HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\shellCompatibility\Objects\

分类
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 进程内COM
	- 在DLL中实现的COM/DCOM组件，即In-Process Server，因为这些组件是加载到使用它们的客户端应用程序执行程序内存之中。
	- 当应用程序调用COM/DCOM 组件的服务时，就和一般的程序或函数调用一样，非常快速。
+ 进程外COM
	- 在EXE 中实现的COM/DCOM组件是执行在它自己的执行程序之中，即Out-Process Server。
	- 当客户端应用程序调用在独立的执行程序中的 COM/DCOM 组件时必须穿越不同的执行程序，因为 Out-Process Server 在执行时会比In-Process Server 慢许多。

COM对象的创建
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 脚本语言（VB,JS等）
	::
	
		Dim Shell
		Set Shell = CreateObject("Wscript.Shell")
		Shell.Run "cmd /c calc.exe"
		
		Dim Shell
		Set Shell = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")
		Shell.Run "cmd /c calc.exe"
+ html
	::
	
		<object classid=clsid:D45FD31B-5C6E-11D1-9EC1-00C04FD7081F width="32" height="32" name="evil"></OBJECT> 
		<script>
		document.write(evil.OpenPage("cmd.exe"));
		</script>
+ 高级语言（C++等）
	::
	
		#define _WIN32_DCOM
		using namespace std;
		#include <comdef.h>

		#pragma comment(lib, "stdole2.tlb")

		int main(int argc, char** argv)
		{
			HRESULT hres;

			// Step 1: ------------------------------------------------
			// 初始化COM组件. ------------------------------------------

			hres = CoInitializeEx(0, COINIT_MULTITHREADED);

			// Step 2: ------------------------------------------------
			// 初始化COM安全属性 ---------------------------------------

			hres = CoInitializeSecurity(
				NULL,
				-1,                          // COM negotiates service
				NULL,                        // Authentication services
				NULL,                        // Reserved
				RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
				RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
				NULL,                        // Authentication info
				EOAC_NONE,                   // Additional capabilities 
				NULL                         // Reserved
			);
			// Step 3: ---------------------------------------
			// 获取COM组件的接口和方法 -------------------------
			LPDISPATCH lpDisp;
			CLSID clsidshell;
			hres = CLSIDFromProgID(L"WScript.Shell", &clsidshell);
			if (FAILED(hres))
				return FALSE;
			hres = CoCreateInstance(clsidshell, NULL, CLSCTX_INPROC_SERVER, IID_IDispatch, (LPVOID*)&lpDisp);
			if (FAILED(hres))
				return FALSE;
			LPOLESTR pFuncName = L"Run";
			DISPID Run;
			hres = lpDisp->GetIDsOfNames(IID_NULL, &pFuncName, 1, LOCALE_SYSTEM_DEFAULT, &Run);
			if (FAILED(hres))
				return FALSE;
			// Step 4: ---------------------------------------
			// 填写COM组件参数并执行方法 -----------------------
			VARIANTARG V[1];
			V[0].vt = VT_BSTR;
			V[0].bstrVal = _bstr_t(L"cmd /c calc.exe");
			DISPPARAMS disParams = { V, NULL, 1, 0 };
			hres = lpDisp->Invoke(Run, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_METHOD, &disParams, NULL, NULL, NULL);
			if (FAILED(hres))
				return FALSE;
			// Clean up
			//--------------------------
			lpDisp->Release();
			CoUninitialize();
			return 1;
		}
+ powershell
	::
	
		通过ProgID创建WSH对象: $shell = [Activator]::CreateInstance([type]::GetTypeFromProgID("WScript.Shell"))
		通过CLSID创建: $shell = [Activator]::CreateInstance([type]::GetTypeFromCLSID("72C24DD5-D70A-438B-8A42-98424B88AFB8"))
		运行：$shell.Run("cmd /c calc.exe")

COM挖掘思路
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 遍历系统COM组件
	::
	
		编写powershell脚本，将CLSID输出到txt文本中：
		New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
		Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > clsids.txt
		利用这些clsid通过powershell创建对应的COM对象，并且使用Get-Member方法获取对应的方法和属性，并最终输出到文本中，pwoershell脚本如下：
		$Position  = 1
		$Filename = "clsid-members.txt"
		$inputFilename = "clsids.txt"
		ForEach($CLSID in Get-Content $inputFilename) {
			  Write-Output "$($Position) - $($CLSID)"
			  Write-Output "------------------------" | Out-File $Filename -Append
			  Write-Output $($CLSID) | Out-File $Filename -Append
			  $handle = [activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))
			  $handle | Get-Member | Out-File $Filename -Append
			  $Position += 1
		}
+ 自动化FUZZ
	- 使用Fuzz测试工具:比较出名的有ComRaider、Axman等。
+ 人工测试
	- 通过控件解析器如ComRaider 、OLEView等，解析出控件的方法和属性，再根据每个方法的参数和返回值等，手工构造测试用例，依次对各个属性和方法进行异常测试，根据页面的返回情况，确定是否存在安全漏洞。
+ COM劫持攻击
	- 注意
		+ 一般用于后渗透阶段，权限提升，维持等。
		+ 一般两种方法： **寻找被遗弃的COM键进行劫持** ， **覆盖COM对象** 。
	- 寻找被遗弃的COM键进行劫持
		+ 一些程序在卸载后，注册表种的COM键会保留下来，即处于注册的状态，这个COM键会指向一个不存在的DLL文件，可以修改路径实现劫持。
		+ 查找方法
			::
			
				使用promon，以calc.exe为例，使用以下过滤：
				Process Name is calc.exe
				Operation is RegOpenKey
				Result is NAME NOT FOUND
				Path contains InProcServer32
	- 覆盖COM对象
		+ 在HKCU注册表种创建正确的键值，当引用目标COM对象时，HKLM中的键值就会被覆盖（并且“添加”到HKCR中）。

	.. |ioctl1| image:: ../../images/ioctl1.png