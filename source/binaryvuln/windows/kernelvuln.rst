系统内核安全
========================================

内核FUZZ思路
----------------------------------------

内核API函数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ring3调用，Ring0执行。如SSDT、Shadow SSDT。

Hook-API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
即安全软件hook过的内核API

网络协议
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
有些协议的处理是在System进程中，那么就可以考虑构造畸形数据包来Fuzz

IoControl
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
这个是被挖漏洞数最多的，作为Ring0与Ring3交互的重要方式，DeviceIoControl函数最后会通过内核函数NtDeviceIoControlFile来实现通信。

参考DeviceIoControl，我们可以通过构造畸形参数来Fuzz驱动程序：

::

	BOOL WINAPI DeviceIoControl(
	_In_        HANDLE       hDevice, // 设备句柄
	_In_        DWORD        dwIoControlCode, // IO控制号
	_In_opt_    LPVOID       lpInBuffer, // 输入缓冲区指针
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer, // 输出缓冲区指针
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped // 异步调用时指向的OVERLAPPED指针
	
	方法有两种：
	1.IoControl Man-in-the-Middle Fuzz:
	也就是在内核hook掉NtDeviceIoControlFile函数，检查IoControl对象，当发现是我们要Fuzz的对象时，获取其参数，然后按照Fuzz策略修改其参数，
	再将篡改后的数据传递给原始NtDeviceIoControlFile函数，观察是否出现内核崩溃或蓝屏（这个思路其实与Hook型内核Rootkit是相同的，比如Linux 
	Rootkit 实验 0001 基于修改sys_call_table的系统调用挂钩）。

	2.IoControl Driver Fuzz
	这种方法指的是对DeviceIoControl每个参数都畸形化，然后组合出不同的参数组（完全给出畸形化参数，而不是去将正常参数部分修改为畸形参数）。
	相比上面的方法，这种方法测试得更为全面。

内核漏洞利用
----------------------------------------

提权
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 替换进程token
    - https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-1
    - 查找当前进程的EPROCESS地址
    - 找到SYSTEM进程的EPROCESS地址
    - 将SYSTEM进程的token复制到当前进程
    - 执行需要SYSTEM权限的操作
    - 示例：https://github.com/MortenSchenk/Token-Stealing-Shellcode 
+ 特权进程ACL NULL
    - https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2
    - EPROCESS结构中SecurityDescriptor数据清0
    - 示例：https://github.com/MortenSchenk/ACL_Edit
+ 特权进程ACL 修改
+ 启用权限
    - https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-3
    - 修改进程EPROCESS结构TOKEN结构Privileges结构，偏移0x8设置为Enabled（-1）
    - 示例：https://github.com/MortenSchenk/Privilege_Shellcode
+ 令牌窃取
    - https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-4-there-is-no-code