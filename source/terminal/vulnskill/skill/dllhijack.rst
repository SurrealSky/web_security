DLL劫持漏洞
=====================================

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
