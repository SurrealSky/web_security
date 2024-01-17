windows符号链接测试工具
========================================
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
    - CreateMountPoint
        :: 
        
            Create an arbitrary file mount point
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