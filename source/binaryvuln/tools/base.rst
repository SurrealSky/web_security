基础
========================================

DynELF
----------------------------------------
+ 背景
	- 由于ASLR，获取函数地址有两种方法，一种方法是先泄露出 libc.so 中的某个函数，然后根据函数之间的偏移计算。前提是能找到和目标服务器上一样的libc.so。
	- 利用pwntools的DynELF模块，对内存进行搜索，直接得到我们需要的函数地址。

ROPgadget
----------------------------------------
+ 查找可存储寄存器的代码
	- ``ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'``
+ 查找字符串
	- ``ROPgadget --binary rop --string "/bin/sh"``
+ 查找有int 0x80的地址
	- ``ROPgadget --binary rop  --only 'int'``

one_gadget
----------------------------------------
+ 安装
	::
	
		
		sudo apt -y install ruby
		sudo gem install one_gadget
+ 介绍
	- one_gadget是寻找libc中存在的一些执行execve("/bin/sh", NULL, NULL)的片段，
	- 当可以泄露libc地址，并且可以知道libc版本的时候，可以使用此方法来快速控制指令寄存器开启shell。
	- 相比于system("/bin/sh")，这种方式更加方便，不用控制RDI、RSI、RDX等参数。运用于不利构造参数的情况。
+ 使用示例
	::
	
		one_gadget libc_32.so.6 
		0x3a819 execve("/bin/sh", esp+0x34, environ)
		constraints:					#以下是调用one_gadget前需要满足的条件
		  esi is the GOT address of libc
		  [esp+0x34] == NULL

		0x5f065 execl("/bin/sh", eax)
		constraints:
		  esi is the GOT address of libc
		  eax == NULL

		0x5f066 execl("/bin/sh", [esp])
		constraints:
		  esi is the GOT address of libc
		  [esp] == NULL

pwntools
----------------------------------------

官方帮助
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://pwntools-docs-zh.readthedocs.io/zh_CN/dev/

命令行
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 基本模块
	::
	
		asm                 Assemble shellcode into bytes
		checksec            Check binary security settings
		constgrep           Looking up constants from header files. Example: constgrep -c freebsd -m ^PROT_ '3 + 4'
		cyclic              Cyclic pattern creator/finder
		debug               Debug a binary in GDB
		disasm              Disassemble bytes into text format
		disablenx           Disable NX for an ELF binary
		elfdiff             Compare two ELF files
		elfpatch            Patch an ELF file
		errno               Prints out error messages
		hex                 Hex-encodes data provided on the command line or stdin
		phd                 Pretty hex dump
		pwnstrip            Strip binaries for CTF usage
		scramble            Shellcode encoder
		shellcraft          Microwave shellcode -- Easy, fast and delicious
		template            Generate an exploit template
		unhex               Decodes hex-encoded data provided on the command line or via stdin.
		update              Check for pwntools updates
		version             Pwntools version

pwnlib用法
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 导入
	::
	
		from pwn import *
		# 本地
		p = process('')
		# 远程
		p = remote('8.8.8.8', 8888)
- 汇编与反汇编
	::
	
		asm('nop', arch='arm')
		disaasm('')
- shellcode
	::
	
		shellcraft.sh()
		shellcraft.i386.linux.sh()
		shellcraft.amd64.linux.sh()
- ELF
	::
	
		elf = ELF('')
		# 或者
		p = process('')
		elf = p.elf

		# 文件装载地址
		elf.address
		# 符号表
		elf.symbols
		# GOT表
		elf.got
		# PLT表
		elf.plt
- pack与unpack
	::
	
		# 将数据解包
		u32()
		u64()
		# 将数据打包
		p32()
		p64()
- Cyclic
	::
	
		# 生成一个0x100大小的字符串
		cyclic(0x100)
		cyclic_find(0x12345678)
		cyclic_find('abcd')
- Context
	::
	
		# 环境设置
		context(os='linux', arch='amd64', log_level='debug')
		# 或者
		context.log_level = 'debug'
		context.arch = 'i386'
		...
- gdb
	::
	
		from pwnlib import *
		# 打开调试进程，并设置断点
		pwnlib.gdb.debug('./human', 'b *main')

		# 附加调试进程p
		pwnlib.gdb.attach(p)
		
- IO交互
	::
	
		send(payload)	#发送payload
		sendline(payload) #payload + 换行\n
		sendafter(string, payload) #接收到指定string后发送payload
		sendlineafter(string, payload) #接收到指定string后发送payload + 换行\n
		recvn(n) # 接收n个字符
		recvline() # 接收一行输出
		recvlines(n) # 接收n行输出
		recvuntil(string) # 接收到指定string为止

		interactive() # shell式交互
- FmtStr
	计算偏移。
- rop
	::
	
		elf = ELF('./proc')
		rop = ROP(elf)
		# 第一个参数是需要call的函数或地址，第二个为函数参数
		rop.call('read', (0, elf.bss(0x80)))
		rop.dump()