windows驱动漏洞
========================================

分类
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 总线驱动 (Bus Driver)
	- 职责： 负责管理物理总线控制器或逻辑总线适配器。它是最底层的驱动。
	- 功能：
		+ 枚举连接到该总线上的子设备（例如，PCI 总线驱动枚举 PCI 插槽上的网卡、声卡）。
		+ 检测设备的插入和移除（即插即用事件）。
		+ 管理总线本身的电源状态。
		+ 为总线上的设备提供基本的访问能力（读写总线上的寄存器/端口）。
	- 例子： PCI.sys (PCI/PCIe 总线), USBHUB3.SYS (USB 根集线器/控制器), ACPI.sys (ACPI 总线/系统固件接口), pcmcia.sys (PCMCIA/CardBus)。
+ 功能驱动 (Function Driver)
	- 职责： 这是驱动栈的核心，负责管理特定类型设备的核心功能和操作。一个设备通常有且只有一个功能驱动。
	- 功能：
		+ 实现设备的主要功能（如网卡发送/接收数据包，声卡播放/录制音频，显卡渲染图像）。
		+ 处理应用程序或系统发送给该设备的 I/O 请求包 (IRP)。
		+ 处理设备的即插即用和电源管理请求（通常与总线驱动协作）。
		+ 为设备注册设备接口 (Device Interface)，使应用程序能够发现和访问该设备。
		+ 处理设备特定的配置和控制请求 (IOCTL)。
	- 例子： HDAudBus.sys (High Definition Audio 总线功能驱动，管理声卡), e1d65x64.sys (Intel 网卡驱动), nvlddmkm.sys (NVIDIA 显卡驱动)。
+ 过滤器驱动 (Filter Driver)
	- 职责： 附加在功能驱动（或另一个筛选器驱动）之上或之下，用于修改或增强设备或另一个驱动程序的行为。它们不是必须的，但非常灵活。
	- 位置分类:
		+ 上层筛选器驱动 (Upper Filter Driver): 位于功能驱动之上。它可以拦截发送给功能驱动的 IRP，在功能驱动处理之前或之后进行修改、记录、阻止或添加额外处理。常用于：
			- 添加额外功能（如加密、压缩）。
			- 监控和记录 I/O 活动（安全软件、性能分析）。
			- 实现虚拟化。
			- 解决特定硬件/软件兼容性问题。
		+ 下层筛选器驱动 (Lower Filter Driver): 位于功能驱动（或总线驱动）之下。它拦截功能驱动发送给下层驱动（如总线驱动）的 IRP。常用于：
			- 在数据到达硬件之前进行修改（如 BIOS 补丁、特定硬件模拟）。
			- 拦截底层硬件访问进行监控。
			- 实现某些类型的设备仿真或虚拟化。
	- 例子： 防病毒软件的实时文件系统筛选器 (监控文件读写)，键盘记录器（恶意或用于诊断），磁盘加密驱动，某些虚拟光驱软件的部分驱动。
+ 微型驱动 (Miniport Driver)
	- 职责： 这是一种特殊的设计模式，尤其常见于网络适配器、存储控制器 (SCSI, RAID) 和显示适配器。它不是一个独立层次，而是功能驱动的一种实现方式。
	- 架构：
		+ 有一个由 Microsoft 提供的、设备类通用的“端口驱动” (Port Driver)。它处理该设备类的通用操作、协议和复杂任务（如 NDIS 协议栈网络封包处理、SCSI 命令协议、显示管理器交互）。
		+ 由硬件供应商提供的、硬件特定的“微型驱动”。它只包含与特定硬件芯片组或型号交互的必要代码。
	- 优点: 简化了硬件厂商的开发工作（只需关注硬件差异），提高了通用功能的稳定性和一致性。
	- 例子:
		+ 网络 (NDIS): ndis.sys (端口驱动) + e1d65x64.sys (Intel 网卡微型驱动)
		+ 存储 (Storport): storport.sys (端口驱动) + iaStorAC.sys (Intel Rapid Storage RAID/SATA 微型驱动)
		+ 显示 (WDDM): dxgkrnl.sys (DirectX 图形内核) + nvlddmkm.sys (NVIDIA 显示微型驱动)
+ 文件系统驱动 (File System Driver)
	- 职责： 管理磁盘卷或网络共享上的文件系统结构（如 NTFS, FAT32, exFAT, ReFS）。
	- 功能：
		+ 解释磁盘上的数据结构，实现文件和目录的创建、读取、写入、删除、属性管理。
		+ 管理磁盘空间分配。
		+ 处理安全描述符（权限）。
		+ 实现文件系统特性（如压缩、加密、卷影复制）。
	- 位置： 通常位于存储设备栈（由磁盘驱动、分区驱动、卷驱动组成）的最顶端。应用程序的文件操作请求最终会到达 FSD。
	- 例子： ntfs.sys (NTFS), fastfat.sys (FAT32/exFAT), udfs.sys (UDF), nfsrdr.sys (NFS 客户端)。
+ 软件驱动 (Non-Hardware Driver / Software Driver)
	- 职责： 这类驱动不管理物理硬件，而是提供纯软件功能或虚拟设备。
	- 功能：
		+ 实现虚拟设备（如虚拟网卡 TAP-Windows Adapter V9 用于 VPN/虚拟机网络，虚拟磁盘 vdmpart.sys）。
		+ 提供内核服务（如内核事件日志 ksecdd.sys）。
		+ 作为内核扩展，用于监控或修改系统行为（如某些安全产品、调试工具）。
	- 位置： 可以存在于各种设备栈中，或者作为独立的驱动对象存在。

核心概念
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 设备对象
	- 驱动对象创建设备对象，设备名称形如（ **\\Device\\设备名** ）
	- 只能在内核访问，用户态不可见/不可用。
	- 设备对象创建： **IoCreateDevice、WdfDeviceCreate**
+ 符号链接
	- 用户态可见且可访问的路径名，它指向内核中的一个设备对象。
	- 通常位于 \\.\ 或 \\?\ 命名空间下。
	- 通过CreateFile函数打开符号链接(形如 **\\\\.\\DeviceSymlink** )，获取驱动设备句柄。
	- 3环的程序向驱动发出I/O请求时，是由 **DeviceIoControl** 等函数所完成的
	- 符号连接创建： **IoCreateSymbolicLink、WdfDeviceCreateSymbolicLink**
+ 设备接口
	- 提供一个标准化的方式，让用户态应用程序（或其他内核驱动）能够发现、识别并最终与特定的硬件设备或虚拟设备进行通信。
	- 注册函数： **IoRegisterDeviceInterface**
+ 其它
	- 不是所有驱动都使用符号链接和用户层进行通信，有很多驱动不是以这种方式和用户进行数据交换

用户态和驱动通信方式
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ I/O 控制代码 (IOCTL - I/O Control Code)
	- 核心机制： 最常用、最标准、最推荐的驱动与用户态通信方式。
	- 原理：
		+ 用户态应用使用 DeviceIoControl Win32 API 函数。
		+ 应用需要先使用 CreateFile 打开驱动暴露的设备对象（通常通过其关联的符号链接或设备接口路径，如 \\.\MyDevice）。
		+ DeviceIoControl 接收一个驱动定义的 IOCTL 代码、一个可选的输入缓冲区（应用传递给驱动的数据）、一个可选的输出缓冲区（驱动返回给应用的数据）以及它们的大小。
		+ 这个调用最终在内核中转化为一个 IRP_MJ_DEVICE_CONTROL 或 IRP_MJ_INTERNAL_DEVICE_CONTROL 的 I/O 请求包 (IRP)，并发送到目标驱动的设备栈。
		+ 驱动在其分发例程（如 EvtIoDeviceControl in WDF）中处理这个 IRP，解析 IOCTL 代码，从输入缓冲区读取数据，处理请求，并将结果写入输出缓冲区。
		+ 处理完成后，驱动设置 IRP 的状态和完成信息，最终 DeviceIoControl 在用户态返回，应用可以检查操作结果和获取输出数据。
	- 适用场景： 绝大多数需要驱动执行特定操作、查询状态或交换数据的场景。例如：配置设备、读取传感器数据、发送控制命令、获取驱动信息等。
+ 读写操作 (ReadFile / WriteFile)
	- 原理：
		+ 用户态应用使用标准的 ReadFile 和 WriteFile Win32 API。
		+ 同样需要先使用 CreateFile 打开设备对象。
		+ ReadFile 调用会生成一个 IRP_MJ_READ IRP 发送给驱动，驱动在其读分发例程（如 EvtIoRead in WDF）中将数据写入应用提供的缓冲区。
		+ WriteFile 调用会生成一个 IRP_MJ_WRITE IRP 发送给驱动，驱动在其写分发例程（如 EvtIoWrite in WDF）中读取应用提供的缓冲区数据。
	- 适用场景： 设备本质上表现为一个数据流（如串行端口 COM、管道、文件系统卷、简单的数据采集卡）。驱动需要实现 IRP_MJ_READ 和 IRP_MJ_WRITE 的处理例程。
+ 设备接口与符号链接 (Discovery and Access)
	- 原理： 这不是直接的“数据传输”机制，而是让用户态应用能够发现驱动并获取其通信句柄的关键前置步骤。它是 IOCTL 和 Read/Write 的基础。
		+ 驱动在启动其设备对象时，会调用 IoRegisterDeviceInterface (WDM) 或 WdfDeviceCreateDeviceInterface (WDF) 来注册一个或多个 GUID 标识的设备接口。
		+ 系统为每个注册的接口实例生成一个唯一的符号链接名称（通常位于 \\.\ 或 \\?\ 命名空间）。
		+ 用户态应用使用 SetupAPI 函数（如 SetupDiGetClassDevs, SetupDiEnumDeviceInterfaces, SetupDiGetDeviceInterfaceDetail）或 CM_XXX ConfigMgr 函数来枚举系统中存在的、支持特定 GUID 接口的设备实例，并获取其符号链接路径。
		+ 应用使用 CreateFile 打开这个符号链接路径，获得一个设备句柄 (HANDLE)。
		+ 获得这个句柄 HANDLE 后，应用才能在上面调用 DeviceIoControl, ReadFile, WriteFile 等函数进行实际的通信。
+ 共享内存 (Shared Memory)
	- 原理：
		+ 驱动和用户态应用映射同一块物理内存页到它们各自的地址空间。
		+ 驱动端： 通常使用 MmAllocateContiguousMemory 或 MmAllocatePagesForMdl 等函数分配物理内存，然后使用 MmMapLockedPagesSpecifyCache 将其映射到内核虚拟地址。接着需要通过某种方式（如 IOCTL）将内存的物理地址或段/偏移量信息传递给用户态应用。
		+ 用户端： 应用使用 CreateFileMapping 和 MapViewOfFile (操作特殊对象如 \Device\PhysicalMemory - 极不推荐且不安全) 或者更现代、更安全的方式：驱动通过 IOCTL 返回一个内存段句柄（section handle），应用使用 MapViewOfFile 映射这个句柄来访问共享内存区域。WDF 提供了 WdfCommonBufferCreate 等函数来简化安全的共享内存创建和用户态映射。

查询驱动
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 命令：``driverquery /v /fo list``
+ 目录：``C:\Windows\System32\drivers``
+ Sysinternals套件中的Autoruns工具
+ DriverView工具

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

	.. |ioctl1| image:: ../../../images/ioctl1.png