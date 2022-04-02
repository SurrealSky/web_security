逆向工具
========================================

pwndbg
----------------------------------------

安装
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- pwndbg是一个gdb的插件，尤其对堆的查看，有很多独有的指令。
- pwndb不可和其他插件一起使用。
- git clone https://github.com/pwndbg/pwndbg
- cd pwndbg
- ./setup.sh
- 配置
	::
	
		pwndbg,gef,peda三个插件无法同时运行，所以下载安装完后，如果想要切换，只能通过修改root下的.gdbinit文件。
		仅安装pwndbg时
		└─# cat .gdbinit    
		source /home/kali/下载/pwndbg/gdbinit.py
		
pwndbg-ELF文件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- elfheader：显示区段数据
- elfsymbol：从ELF文件获取非调试符号信息
- readelf：从elf文件获取头信息
- got：查看Global Offset Table
- plt：查看.plt区段中的符号
- gotplt：查看.got.plt区段中的符号
- rop：Dump ROP gadgets with Jon Salwan's ROPgadget tool. 
- ropper：ROP gadget search with ropper. 
- auxv：查看Auxiliary ELF Vector信息
- checksec：查看程序保护机制
	
pwndbg-进程状态信息
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- aslr [{off,on}]：开启关闭aslr
- procinfo：显示进程信息
- pid：显示进程pid
- gsbase：查看GS base address
- fsbase：查看FS base address
- canary：查看当前的static canary
- context：查看进程上下文环境信息
- regs：查看所有寄存器数据
- telescope：Recursively dereferences pointers starting at the specified address ($sp by default)
- stack [count] [offset]：查看堆栈数据
- retaddr：查看堆栈中的返回地址
- libs：查看程序加载的库
- entry_point：查看entry地址
- piebase [offset] [module]：Calculate VA of RVA from PIE base.
- dumpargs [-f]：显示在调用指令处停止时传递给函数的参数
- dumprop <from> <to>：显示特定内存范围内的所有ROP gadgets
- getfile
- getpid		

pwndbg-反汇编
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- u [addr] [n]：反汇编包含 **地址和汇编指令**
- nearpc [addr] [N] [emulate]：反汇编包含 **地址和汇编指令**
- pdisass [addr] [N]：反汇编包含 **地址和汇编指令**
- emulate [addr] [N]：反汇编包含 **地址和汇编指令**
- disassemble <addr>：反汇编包含 **地址和汇编指令**
	+ disassemble /m [addr]：包含 **源码**
	+ disassemble /s [addr]：包含 **源码**
	+ disassemble /r [addr]：包含 **指令数据16进制**
	
pwndbg-调试指令
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- entry_point：查看entry地址
- i r [a]：查看寄存器值
- bl：断点列表
- bd [which]：禁用断点
- be [which]：启用断点
- bp where：设置断点
- breakrva [offset] [module]：相对于程序PIE base设置offset偏移断点
- bc [which]：删除指定断点
- k：查看堆栈
- ln [addr]：查看指定地址附近的符号
- peb：查看peb
- go：执行程序
- pc：下一个call处暂停执行
- nextjmp/nextcall/nextret/nextsyscall
- nextproginstr：执行到程序领空
- stepover/stepsyscall/stepret
- entry：执行程序并暂停在oep位置，一般比main靠前
- start/main/init：执行程序并暂停在main函数处
- sstart：执行程序并暂停在__libc_start_main函数处
- xuntil target：执行程序到指定地址

pwndbg-内存指令
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- dps <addr>：优雅地显示内存信息
- vmmap：显示程序内存结构
- hexdump [address] [count]
- xinfo [address]：查看指定地址附近的信息
- d[b/w/d/q/c]：查看内存数据
- dt typename [address]：指定地址显示指定类型的数据
- e[b/w/d/q/z/za]：指定地址写入数据
- da addr [max]：Dump a string at the specified address. 
- dds addr [max]：Dump pointers and symbols at the specified address. 
- ds addr [max]：Dump a string at the specified address. 
- 内存泄露
	+ probeleak [address] [count] [max_distance]
	+ leakfind [-p [PAGE_NAME]] [-o [MAX_OFFSET]] [-d [MAX_DEPTH]] [-s [STEP]] [--negative_offset [NEGATIVE_OFFSET]] address
- search <\*argv>：搜索内存中的值

pwndbg-堆指令
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- arena [addr]：查看main arena或指定地址的arena
- arenas：列出分配的arena列表
- bin/bins [addr]：从main arena或指定地址查看tcachebins, fastbins, unsortedbin, smallbins, and largebins。
- heap [addr]：查看指定堆的chunks
- parseheap：优雅地查看分配的chunk
- fastbins [addr]：从main arena或指定地址查看fastbins。
- find_fake_fast：Finds candidate fake fast chunks that will overlap with the specified address. Used for fastbin dups and house of spirit。
- largebins [addr]：从main arena或指定地址查看largebins。
- malloc_chunk [addr] [fake]：从指定地址查看chunk。
- mp：在glibc中查看mp_structure
- smallbins [addr]：从main arena或指定地址查看smallbins。
- tcache [addr]：查看tcache信息。
- tcachebins [addr]：从当前线程或指定地址查看所有bins。
- top_chunk [addr]：从main arena或指定地址查看top chunk。
- unsortedbin [addr]：从main arena或指定地址查看unsortedbin。
- vis_heap_chunks [--naive] [count] [address]：在指定地址查看可视化的chunks

pwndbg-配置
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- config：显示当前配置
- configfile：从当前配置保存到配置文件
- theme：显示当前主题
- themefile：从当前主题配置保存到主题文件
- argc/argv/envp

Radare2
----------------------------------------

官方地址
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- https://github.com/radareorg/radare2
- 帮助文档：https://book.rada.re/index.html
- 类Unix系统上的逆向工程框架和命令行工具集

查看帮助
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ?:查看支持的命令
- p?:查看p系列命令帮助

特殊符号
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ~：指令后添加~代表过滤输出（grep）
	+ dm~heap:执行dm指令，并过滤包含heap字符串的行
- ;
	+ 命令分隔符，如px 10;pd 20
- !
	+ 运行 shell 命令
- @
	+ @ addr
	+ @r:[reg]
- @@：迭代器，在列出的偏移处重复执行命令
	+ wx ff @@ 10 20 30		在偏移 10、20、30 处写入 ff
	+ p8 4 @@ fcn.* 		打印处每个函数的头 4 个字节
- ?$?：显示表达式所使用变量的帮助信息
	+ $$ 是当前所处的虚拟地址
	+ $? 是最后一个运算的值
	+ $s 文件大小
	+ $b 块大小
	+ $l 操作码长度
	+ $j 跳转地址。当 $$ 处是一个类似 jmp 的指令时，$j 中保存着将要跳转到的地址
	+ $f 跳转失败地址。即当前跳转没有生效，$f 中保存下一条指令的地址
	+ $m 操作码内存引用。如：mov eax,[0x10] => 0x10
	
r2-ELF文件
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ia：查看二进制程序基本信息，导入库，导出库
- it：查看二进制hash值
- ie：查看程序entrypoint
- iS：显示文件区段
- iSS：显示内存段
- is：查看符号信息（Symbols）
- iz/izj：查看数据段中的字符串
- izz：Search for Strings in the whole binary
- id：pdb调试
	::
	
		[0x55ccb818f179]> id?
		| id                 Show DWARF source lines information
		| idp [file.pdb]     Load pdb file information
		| idpi [file.pdb]    Show pdb file information
		| idpi*              Show symbols from pdb as flags (prefix with dot to import)
		| idpd               Download pdb file on remote server
		注：gcc -g编译

r2-进程内存映射
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- dm[=/\*]						显示进程内存映射
- dmj							显示进程内存映射(json格式)
- dm.							显示当前地址内存映射名
- dmi.                          显示当前地址内存映射名
- dmd[a] [file]					保存当前映射到文件
- dmh[?]                        查看Malloc chunk列表
- dmi[*] [addr|libname] [symname]	进程加载的模块
- dmm[?][j*]                    列出模块 (库文件，内存中加载的二进制文件)

r2-汇编
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- pa [assembly]    				汇编
- pad [hexpairs]   				反汇编（显示汇编代码）
- paD [hexpairs]   				反汇编（显示汇编指令，汇编代码）
- pdx [hex]						类似pad				
- pade [hexpairs]  				汇编ESIL
- pae [assembly]  	 			汇编ESIL

r2-反汇编
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- p[i\/I]						**静态反汇编** (显示汇编代码）
- pdi							**静态反汇编** (显示地址，汇编指令，汇编代码）
- pi[f\/F]						**静态反汇编** 到函数结束(显示汇编代码）
- pCd [N]						**动态反汇编** (显示地址，汇编代码）
- pd:							**动态反汇编** (显示地址，汇编指令，汇编代码)
- pD [N]             			**动态反汇编** (显示地址，汇编指令，汇编代码)
- pd -N            				**动态反汇编（含代码分析）前N条** (显示地址，汇编指令，汇编代码)
- pd N             				**动态反汇编（含代码分析）** (显示地址，汇编指令，汇编代码)
- pd--[n]          				**动态反汇编（含代码分析）前后N条** (显示地址，汇编指令，汇编代码)
- pdb              				**动态反汇编（含代码分析）基本块** (显示地址，汇编指令，汇编代码)
- pdr              				**动态反汇编（含代码分析）函数块** (显示地址，汇编指令，汇编代码)
- pdR              				**动态反汇编（含代码分析）函数块** (显示地址，汇编指令，汇编代码)
- pdf              				**动态反汇编（含代码分析）函数块** (显示地址，汇编指令，汇编代码)
- pdc              				**反编译c格式代码** 类似IDA F5功能
- pde[q|qq|j] [N]  				**动态反汇编（含代码分析）当前代码以及call/跳转后代码** (显示地址，汇编指令，汇编代码)	
- pdl              				显示每条指令长度
- pds[?]           				显示(strings, calls, jumps, refs)

代码分析
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- aaa							代码分析
- af[r]	([name]) ([addr])		递归分析函数
- afl							列出二进制中存在的函数
- afi [addr|fcn.name]			显示函数信息
- afo [fcn.name]				显示函数地址
- afx							显示函数引用
- afv							显示函数局部变量，参数及其ebp偏移
- afv[b\/s]						显示函数局部变量，参数相对ebp/esp偏移
- afvd							显示函数局部变量，参数及其 **值**
- afv=							显示函数局部变量引用
- afvR [varname]				显示局部变量被读访问的相关地址
- afvW [varname]				显示局部变量被写访问的相关地址
- afvx							即afvR和afvW合并执行
- axt							查看交叉引用

r2-调试指令
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- r2 -d -A heap AAAAAAAAAAAA
	+ -A 		自动化分析或者再命令台使用aaa
	+ -d 		启动调试
- s:移动到不同位置
	+ s：打印当前地址
	+ s @main：打印main函数地址
	+ s @PC：打印当前eip寄存器内容
	+ s addr
	+ s/sr	[register]
- VV:可视化的函数调用图
- 断点
	+ db sym.main               下断点
	+ db <addr>                 下断点
	+ dbH <addr>                硬件断点
	+ drx number addr len perm  更改硬件断点
	+ drx-number                清空硬件断点
	+ db- <addr>                删除断点
	+ dbi- <idx>                使用序号删除断点
	+ db-*                      删除所有断点
	+ dbc <addr> <cmd>          Run command when breakpoint is hit
	+ dbC <addr> <cmd>          条件断点：运行直到cmd返回0
	+ dbd <addr>                禁用断点
	+ dbid <idx>                使用序号禁用断点
	+ dbe <addr>                启用断点
	+ dbie <idx>                使用序号启用断点
	+ dbn [<name>]              显示或设置断点别名
	+ dbi                       断点列表
	+ db.                       断点列表
	+ dbj                       断点列表
	+ dbix <idx> [expr]         指定序号断点设置条件表达式
	+ dbite <idx>               启用断点跟踪（调试运行不中断，仅显示命中了断点）
	+ dbitd <idx>               禁用断点跟踪
	+ dbt[?]                    查看调用堆栈
	+ dbw <addr> <r/w/rw>       添加watchpoint		
- 重启调试程序
	+ doo [args]				重启调试程序
	+ doc           			关闭调试会话
- 调试执行
	+ dc						继续运行调试程序
	+ dcc                       继续执行直到call(单步步入)
	+ dccu                      继续执行直到call(单步步入)
	+ dcr						继续执行直到ret(单步步过)
	+ dcs[?] <num>				继续执行直到系统调用syscall
	+ dcu[?] [..end|addr] ([end])  继续执行直到指定地址
- 查看寄存器
	+ drl						显示所有寄存器名
	+ dr						打印寄存器数据
	+ dr=						多列显示寄存器数据
	+ drr						打印寄存器数据，并显示引用数据
	+ drx						查看dr硬件寄存器值
	+ dr??						显示所有寄存器别名及值（包含状态寄存器flag值）
- 单步调试
	+ ds						**单步步入**
	+ ds <num>          		单步num条指令
	+ dsb               		Step back one instruction
	+ dsf               		执行到函数结尾
	+ dsi <cond>        		执行直到cond条件满足
	+ dsl               		单步一行源代码
	+ dsl <num>         		执行num行源代码
	+ dso <num>					**单步步过** num条指令
	+ dsp             			执行进入程序领空
	+ dss <num>         		执行num条指令
	+ dsu[?] <address>  		执行直到address地址

r2查看变量
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ???：可以获得以?开头的命令的细节
	+ ?  		**计算表达式** 如 ? 1234
	+ ?p vaddr 	获得虚拟地址 vaddr 的物理地址
	+ ?P paddr 	获得物理地址 paddr 的虚拟地址
	+ ?v 		以十六进制的形式显示某数学表达式的结果。如 ?v eip-0x804800。
	+ ?l str 	获得str的长度，结果被临时保存，使用 ?v 可输出结果

r2内存指令
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- pv[1/2/4/8]					打印内存1/2/4/8字节数据
- pb [N]						打印N个比特数据（二进制展示）
- pB [N]						打印N个字节数据（二进制展示）
- pxb [N]:						以hexdump形式显示二进制数据
- pc [N]						c数组显示内存数据
- pci [N]						c数组显示内存数据(显示汇编注释)
- ps							显示 **字符串**
- pvz							显示 **字符串**
- psz[j]   						显示\0结束的字符串
- 十六进制数据视图
	+ px               			16进制视图
	+ pxs						16进制视图（sparse mode）
	+ pxc               		16进制视图（带注释）
	+ pxf               		16进制视图（函数作为边界）
	+ pxl [N]              		16进制视图（N行）
	+ pxo						16进制视图（10进制数据显示）
	+ pxh               		16进制视图（16bits即2字节一组）
	+ pxw               		16进制视图（32bits即4字节一组）
	+ pxq               		16进制视图（64bit即8字节一组）
	+ pxx               		16进制视图（仅显示字符部分）
	+ px0               		16进制字符串直到00（不显示字符部分）
	+ pxb               		16进制视图（二进制比特位显示）
	+ pxd[?1248]        		16进制视图（有符号整数显示）
	+ pxr[1248][qj]     		显示数据引用
	+ px/               		类似gdb x/命令
- pf：以指定格式显示内存数据
	::
	
		Usage: pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]  
		Commands:
		| pf fmt                     Show data using the given format-string. See 'pf??' and 'pf???'.
		| pf?                        Help on commands
		| pf??                       Help on format characters
		| pf???                      Show usage examples
		| pf* fmt_name|fmt           Show data using (named) format as r2 flag create commands
		| pf.                        List all format definitions
		| pf.fmt_name                Show data using named format
		| pf.fmt_name.field_name     Show specific data field using named format
		| pf.fmt_name.field_name=33  Set new value for the specified field in named format
		| pf.fmt_name.field_name[i]  Show element i of array field_name
		| pf.fmt_name [0|cnt]fmt     Define a new named format
		| pf?fmt_name                Show the definition of a named format
		| pfc fmt_name|fmt           Show data using (named) format as C string
		| pfd.fmt_name               Show data using named format as graphviz commands
		| pfj fmt_name|fmt           Show data using (named) format in JSON
		| pfo fdf_name               Load a Format Definition File (fdf)
		| pfo                        List all format definition files (fdf)
		| pfq fmt ...                Quiet print format (do now show address)
		| pfs[.fmt_name| fmt]        Print the size of (named) format in bytes
		| pfv.fmt_name[.field]       Print value(s) only for named format. Useful for one-liners
		
		列出支持的复杂格式
		[0x56104a3021a9]> pfo
		zip
		trx
		dll
		elf32
		elf64
		mz
		elf_enums
		pe32
		
		加载格式：pfo elf64
		查看加载的数据格式：pf.
		查看复杂格式数据：
		[0x55fd4d10e1a9]> pf.elf_header @ 0x55fd4d10d000
			 ident : 
						struct<elf_ident>
				   magic : 0x55fd4d10d000 = "\x7fELF"
				   class : 0x55fd4d10d004 = class (enum elf_class) = 0x2 ; ELFCLASS64
					data : 0x55fd4d10d005 = data (enum elf_data) = 0x1 ; ELFDATA2LSB
				 version : 0x55fd4d10d006 = version (enum elf_hdr_version) = 0x1 ; EV_CURRENT
			  type : 0x55fd4d10d010 = type (enum elf_type) = 0x3 ; ET_DYN
		   machine : 0x55fd4d10d012 = machine (enum elf_machine) = 0x3e ; EM_X86_64
		   version : 0x55fd4d10d014 = version (enum elf_obj_version) = 0x1 ; EV_CURRENT
			 entry : 0x55fd4d10d018 = (qword)0x0000000000001070
			 phoff : 0x55fd4d10d020 = (qword)0x0000000000000040
			 shoff : 0x55fd4d10d028 = (qword)0x0000000000003ba8
			 flags : 0x55fd4d10d030 = 0x00000000
			ehsize : 0x55fd4d10d034 = 64
		 phentsize : 0x55fd4d10d036 = 56
			 phnum : 0x55fd4d10d038 = 13
		 shentsize : 0x55fd4d10d03a = 64
			 shnum : 0x55fd4d10d03c = 37
		  shstrndx : 0x55fd4d10d03e = 36
		
- ph：计算数据块的各种hash
			
r2-堆指令
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- dmh                                          查看堆中所有malloc_chunk列表
- dmh @[malloc_state]                          查看指定malloc_state的malloc_chunk列表
- dmha                                         查看所有malloc_state列表
- dmhb @[malloc_state]                         查看指定malloc_state的所有bin数据
- dmhb [bin_num|bin_num:malloc_state]          查看指定malloc_state的指定序号bin数据
- dmhbg [bin_num]                              Display double linked list graph of main_arena's bin [Under developemnt]
- dmhc @[chunk_addr]                           查看指定地址的malloc_chunk数据
- dmhf @[malloc_state]                         查看指定malloc_state的fastbins数据
- dmhf [fastbin_num|fastbin_num:malloc_state]  查看指定malloc_state的指定序号的fastbin数据
- dmhg                                         查看堆malloc_chunk列表图示
- dmhg [malloc_state]                          Display heap graph of a particular arena
- dmhi @[malloc_state]                         查看指定malloc_state的heap_info数据
- dmhj                                         List the chunks inside the heap segment in JSON format
- dmhm                                         查看main thread所有的malloc_state数据
- dmhm @[malloc_state]                         List all malloc_state instance of a particular arena
- dmht                                         查看thread cache的malloc_state列表
- dmh?                                         Show map heap help