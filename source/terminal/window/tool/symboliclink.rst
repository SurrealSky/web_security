符号链接测试工具
========================================

mklink
----------------------------------------
::

    mklink /D <符号链接> <目标>
    mklink /D "C:\Users\Administrator\Desktop\link" "C:\Users\Administrator\Documents"
    mklink /H <硬链接> <目标>
    mklink /H "C:\Users\Administrator\Desktop\doc.txt" "C:\Users\Administrator\Documents\doc.txt"
    mklink /J <联接> <目标>
    mklink /J "C:\Users\Administrator\Desktop\link" "C:\Users\Administrator\Documents"

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
        
            Creates a object manager symbolic link using csrss
    - CreateSymlink
        ::
        
            创建符号链接
            示例：CreateSymlink "C:\\test\\1.txt" "D:\\2.txt"
            注:test目录必须为空
    - CreateMountPoint
        ::
        
            创建软链接
            示例：CreateMountPoint "C:\\test1" "D:\\test2"
            注：test1目录必须已经存在并且用户具有对目录的完全控制权限。
    - CreateHardlink
        ::
        
            创建硬链接
    - CreateNtfsSymlink
        :: 
        
            Create an NTFS symbolic link
    - CreateObjectDirectory
        :: 
        
            Create a new object manager directory
    - CreateRegSymlink
        :: 
        
            Create a registry key symbolic link
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