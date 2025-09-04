符号链接测试工具
========================================

mklink
----------------------------------------
::

	mklink /D <符号链接> <目标>
	mklink /D "C:\Users\Administrator\Desktop\link" "C:\Users\Administrator\Documents"
	mklink /H <硬链接> <目标>
	mklink /H "C:\linkdoc.txt" "C:\dstdoc.txt"
	注：其中对dstdoc.txt文件应具备写入权限（测试需要是文件拥有者）
	mklink /J <软联接/连接点> <目标>
	mklink /J "C:\linkdir" "C:\dstdir"
	注：其中linkdir在当前目录中应当不存在，且对dstdir目录应具备写入权限

symboliclink-testing-tools
----------------------------------------
+ 项目地址： ``https://github.com/googleprojectzero/symboliclink-testing-tools``
+ 工具说明
	- BaitAndSwitch 
		::
		
			创建一个符号链接，并且设置OPLOCK锁，相当于SetOpLock和CreateSymlink工具组合
			通常用于测试TOCTOU BUG，命令如下：
			BaitAndSwitch.exe dd\1.txt c:\1.txt c:\2.txt
			当第一次打开文件操作，文件为c:\1.txt
			当第二次打开文件操作，文件为c:\2.txt
	- CreateDosDeviceSymlink
		::
		
			使用csrss创建对象管理器符号链接：
			CreateDosDeviceSymlink.exe "\RPC Control\config.txt" "??\C:\dont_delete.txt"
			注：\RPC Control下的符号链接会在系统重启后丢失。
	- CreateSymlink
		::
		
			创建连接点 + 对象管理器符号链接,可以任意文件删除：
			示例：CreateSymlink "C:\\test\\1.txt" "D:\\2.txt"
			注:test目录必须为空，可以在 非管理员权限下 创建。
			相当于以下命令：
			CreateDosDeviceSymlink.exe "\RPC Control\config.txt" "??\C:\dont_delete.txt"
			CreateMountPoint.exe "C:\test" "\RPC Control"
			删除C:\test目录下config.txt文件，就是删除C:\dont_delete.txt文件。
			注：\RPC Control下的符号链接会在系统重启后丢失。

	- CreateMountPoint
		::
		
			创建软链接/连接点：
			示例：CreateMountPoint "C:\\test1" "D:\\test2"
			注：test1目录必须已经存在并且用户具有对目录的完全控制权限。
	- CreateHardlink
		::
		
			创建硬链接
	- CreateNtfsSymlink
		:: 
		
			创建符号连接：
			管理员权限下运行，创建<目录链接到目录>：
			CreateNtfsSymlink.exe -d C:\Dir C:\Other
			注：其中Dir目录要提前建立好，并且要是空目录。
			创建<文件到文件>的符号链接：
			CreateNtfsSymlink.exe -r C:\demo_file_link.txt C:\dst.txt
			
	- CreateObjectDirectory
		:: 
		
			Create a new object manager directory
	- CreateRegSymlink
		:: 
		
			创建注册表符号链接
	- DeleteMountPoint
		:: 
		
			Delete a mount point
	- DumpReparsePoint
		:: 
		
			Delete the reparse point data
	- NativeSymlink
		::
		
			Create an object manager symbolic link
	- SetOpLock
		:: 
		
			工具可以让你创建锁，并阻止对文件或目录的访问，直到你按回车键释放锁。
			它让你在读、写和放行oplock之间进行选择。

查看软连接/连接点状态
----------------------------------------
+ fsutil reparsepoint query [连接点]