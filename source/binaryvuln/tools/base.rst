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

模块和函数
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- pwn：简单的用 from pwn import * 就能把所有子模块和一些常用的系统库导入当前命名空间中，是专门为了CTF比赛优化的。
- pwnlib：适合开发成产品，根据需要导入不同的子模块。
- 模块列表
	::
	
		pwnlib.adb: 安卓adb
		pwnlib.asm: 汇编和反汇编
		pwnlib.constans: 包含各种体系结构和操作系统中的系统调用号常量（来自头文件），constants.linux.i386.SYS_stat
		pwnlib.context: 设置运行环境
		pwnlib.dynelf: 利用信息泄漏远程解析函数
		pwnlib.encoders: 对shellcode进行编码，如encoders.encoder.null('xxx')
		pwnlib.elf: 操作ELF可执行文件和共享库
		pwnlib.fmtstr: 格式化字符串利用工具
		pwnlib.gdb: 调试，配合gdb使用
		pwnlib.libcbd: libc数据库，入libcdb.search_by_build_id('xxx')
		pwnlib.log: 日志记录管理,比如log.info('hello')
		pwnlib.memleak: 内存泄漏工具，将泄漏的内存缓存起来，可作为Payload
		pwnlib.qume: QEMU模拟相关，一般用来模拟不同架构的指令或运行程序
		pwnlib.rop: ROP利用工具，包括rop,srop等
		pwnlib.runner: 运行Shellcode，例如：run_assembly('mov eax,SYS_exit;int 0x80;')
		pwnlib.shellcraft: Shellcode生成器
		pwnlib.tubes: scokets、ssh、进程管道通信
		pwnlib.utils: 一些实用小工具，比如CRC计算,cyclic字符串生成等

- pwnlib.context
	+ 设置进程运行时的环境，比如目标是什么CPU架构，多少位数，什么平台，是否开启日志等等
		::
		
			#架构32位X86,平台Linux
			context(arch='i386',os='linux')
			#设置tmux分屏
			context.terminal['tmux','splitw','-h']
			#开启日志信息
			context.log_level = 'debug'
	+ 架构如下
		::
		
			architectures = _longest({
			'aarch64':   little_64,
			'alpha':     little_64,
			'avr':       little_8,
			'amd64':     little_64,
			'arm':       little_32,
			'cris':      little_32,
			'i386':      little_32,
			'ia64':      big_64,
			'm68k':      big_32,
			'mips':      little_32,
			'mips64':    little_64,
			'msp430':    little_16,
			'powerpc':   big_32,
			'powerpc64': big_64,
			'riscv':     little_32,
			's390':      big_32,
			'sparc':     big_32,
			'sparc64':   big_64,
			'thumb':     little_32,
			'vax':       little_32,
			'none':      {},
			})
			transform = [('ppc64', 'powerpc64'),
						 ('ppc', 'powerpc'),
						 ('x86-64', 'amd64'),
						 ('x86_64', 'amd64'),
						 ('x86', 'i386'),
						 ('i686', 'i386'),
						 ('armv7l', 'arm'),
						 ('armeabi', 'arm'),
						 ('arm64', 'aarch64')]
			位数：
			big_32    = {'endian': 'big', 'bits': 32}
			big_64    = {'endian': 'big', 'bits': 64}
			little_8  = {'endian': 'little', 'bits': 8}
			little_16 = {'endian': 'little', 'bits': 16}
			little_32 = {'endian': 'little', 'bits': 32}
			little_64 = {'endian': 'little', 'bits': 64}
			平台：
			oses = sorted(('linux','freebsd','windows','cgc','android','baremetal'))

- pwnlib.tubes
	+ pwnlib.tubes.process
	+ pwnlib.tubes.serialtube
	+ pwnlib.tubes.sock
	+ pwnlib.tubes.ssh
	+ IO交互示例
		::
	
			打开本地进程：
			p = process('./hackhack')
			打开远程socket：
			p = remote('8.8.8.8', 8888 ,typ="tcp")
			
			send(payload)	#发送payload
			sendline(payload) #payload + 换行\n
			sendafter(string, payload) #接收到指定string后发送payload
			sendlineafter(string, payload) #接收到指定string后发送payload + 换行\n
			recvn(n) # 接收n个字符
			recvline() # 接收一行输出
			recvlines(n) # 接收n行输出
			recvuntil(string) # 接收到指定string为止
			interactive() # shell式交互

- pwnlib.gdb
	::
	
		# 打开调试进程，并设置断点
		pwnlib.gdb.debug('./human', 'b *main')

		# 附加调试进程p
		pwnlib.gdb.attach(pid)

- pwnlib.asm
	::
	
		asm('nop', arch='arm')
		(disasm(unhex('E007BF'),arch='aarch64',bits=64))
		
- pwnlib.shellcraft
	::
	
		shellcraft.sh()
		shellcraft.i386.linux.sh()
		shellcraft.amd64.linux.sh()
- pwnlib.elf
	::
	
		elf = ELF('./hack')
		# 或者
		p = process('')
		elf = p.elf
		
		#文件装载地址
		elf.address
		elf.arch
		elf.bits
		elf.os
		# 符号表
		elf.symbols
		# GOT表
		for kv in elf.got.items():
			print(kv)
		# PLT表
		for kv in elf.plt.items():
			print(kv)
		#hack函数偏移:hex(elf.symbols['hack'])
- pwnlib.util
	+ packing
		::
		
			# 将数据解包
			u8()
			u32()
			u64()
			# 将数据打包
			p8()
			p32()
			p64()
	+ Cyclic
		::
		
			# 生成一个0x100大小的字符串
			cyclic(0x100)
			cyclic_find(0x12345678)
			cyclic_find('abcd')

- pwnlib.rop
	::
	
		elf = ELF('./proc')
		rop = ROP(elf)
		# 第一个参数是需要call的函数或地址，第二个为函数参数
		rop.call('read', (0, elf.bss(0x80)))
		rop.dump()

python struct模块
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 主要函数
	::
	
		string pack(fmt,v1,v2…)               按照给定的格式(fmt),把数据转换成字符串(字节流),并将该字符串返回.
		pack_into(fmt,buffer,offset,v1,v2…)   按照给定的格式(fmt),将数据转换成字符串(字节流),并将字节流写入以offset开始的buffer中.(buffer为可写的缓冲区,可用array模块)
		tuple unpack(fmt,v1,v2…..)            按照给定的格式(fmt)解析字节流,并返回解析结果
		tuple pack_from(fmt,buffer,offset)    按照给定的格式(fmt)解析以offset开始的缓冲区,并返回解析结果
		calcsize(fmt)                         计算给定的格式(fmt)占用多少字节的内存，注意对齐方式
- 对齐方式
	::
	
		Character    Byte           order      Size    Alignment
		@(默认)      本机           本机       本机    凑够4字节
		=            本机           标准       none    按原字节数
		<            小端           标准       none    按原字节数
		>            大端           标准       none    按原字节数
		!            network(大端)  标准       none    按原字节数

- 格式符
	::
	
		格式符      C语言类型              Python类型            Standard size
		x           pad byte(填充字节)     no value
		c           char                   string of length 1       1
		b           signed char            integer                  1
		B           unsigned char          integer                  1
		?           _Bool                  bool                     1
		h           short                  integer                  2
		H           unsigned short         integer                  2
		i           int	integer	4
		I(大写的i)  unsigned int           integer                  4
		l(小写的L)  long                   integer                  4
		L           unsigned long          long                     4
		q           long long              long                     8
		Q           unsigned long long     long                     8
		f           float                  float                    4
		d           double                 float                    8
		s           char[]                 string
		p           char[]                 string
		P           void *                 long
- 进制转换
	::
	
		# 获取用户输入十进制数
		dec = int(input("输入数字："))
		print("十进制数为：", dec)
		print("转换为二进制为：", bin(dec))
		print("转换为八进制为：", oct(dec))
		print("转换为十六进制为：", hex(dec))

python binascii模块
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- 主要函数
	::
	
		a2b_uu(string)            将以ascii编码的一行数据转化为二进制,并且返回二进制数据.
		b2a_uu(data)              将二进制数据转化为一行以ascii编码的字符,date的最大长度为45.
		a2b_base64(string)        将一块base64的数据转换为二进制数据,并返回该二进制数据
		b2a_base64(string)        与上面相反
		a2b_qp(string[, header])  quoted-printable data->bin,并返回
		b2a_qp(data[, quotetabs, istext, header])   与上面相反
		a2b_hqx(string)           binhex4格式化的ASCII数据转换为二进制,没有做RLE解压.
		b2a_hqx(data)             与上相反
		rledecode_hqx(data)       按照binhex4标准,对data执行RLE解压
		rlecode_hqx(data)        对data执行binhex方式的压缩,并返回结果
		crc_hqx(data, crc)       计算data的binhex4的crc值
		crc32(data[, crc])       根据crc,计算crc32(32位检验和数据,然后将结果&0xffffffff(为了在所有Python版本中生成相同的结果,具体不清楚,求指导…)
		b2a_hex(data)            返回二进制数据的16进制的表现形式
		a2b_hex(data)            与上面相反
		hexlify(data)            返回二进制数据的16进制的表现形式
		unhexlify(hexstr)        与上面相反
- 进制转换
	::
	
		chr()      把一个整形转换成ASCII码表中对应的单个字符
		ord()      把ASCII码表中的字符转换成对应的整形
		hex()      把十进制转换成16进制字符
		oct()      把十进制转换成八进制字符
		bin()      把十进制整形转换成二进制字符
