常见思路
========================================

溢出类型
----------------------------------------

Return-2-Shellcode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 定义
	- 如果程序未开启NX,可以直接写shellcode到栈(或者堆,bss等可控区域)上,如果能泄露对应地址(通过缓冲区泄露)就可以通过偏移直接ret到shellcode上,或者寻找jmp esp(32位)这种gadget控制PC register(eip/rip)到栈上.


Return-2-libc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ 定义
	- 利用libc中的函数来获取shell,最典型的就是system("/bin/sh");.这个可以用来绕过DEP.
+ 前提
	- 泄露了libc地址(如果是动态链接,静态链接直接ROP即可).这样就能绕过ASLR获得system的地址.
		::
		
			libc = ELF("libc.so")
			off_system = libc.symbols['write'] - libc.symbols['system']
			system_addr = write_addr - off_system
			
			用工具获得动态库的导出函数偏移:
			nm -D libc.so | grep "system"
			objdump -T libc.so | grep "system"

Return-2-csu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

BROP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~