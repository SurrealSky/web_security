逆向工具
========================================

pwndbg
----------------------------------------
+ 安装
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
			
+ 反汇编
	- u [addr] [n]：反汇编包含 **地址和汇编指令**
	- nearpc [addr] [N] [emulate]：反汇编包含 **地址和汇编指令**
	- pdisass [addr] [N]：反汇编包含 **地址和汇编指令**
	- emulate [addr] [N]：反汇编包含 **地址和汇编指令**
	- disassemble <addr>：反汇编包含 **地址和汇编指令**
		+ disassemble /m [addr]：包含 **源码**
		+ disassemble /s [addr]：包含 **源码**
		+ disassemble /r [addr]：包含 **指令数据16进制**
+ 调试指令
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
+ 内存指令
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
+ 堆指令
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
+ ELF文件指令
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
+ 进程状态信息
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
+ 配置
	- config：显示当前配置
	- configfile：从当前配置保存到配置文件
	- theme：显示当前主题
	- themefile：从当前主题配置保存到主题文件
+ search <\*argv>：搜索内存中的值
+ argc/argv/envp

Radare2
----------------------------------------
+ 官方地址
	- https://github.com/radareorg/radare2
	- 帮助文档：https://book.rada.re/index.html
	- 类Unix系统上的逆向工程框架和命令行工具集
+ 查看帮助
	- ?:查看支持的命令
	- p?:查看p系列命令帮助
+ ~：指令后添加~代表过滤输出
	- dm~heap:执行dm指令，并过滤包含heap字符串的行
+ @：seek
	- @ addr
	- @r:[reg]：seek到寄存器
+ 汇编
	- pa
		::
		
			Usage: pa[edD] [asm|hex]  print (dis)assembled
			| pa [assembly]    print hexpairs of the given assembly expression
			| paD [hexpairs]   print assembly expression from hexpairs and show hexpairs
			| pad [hexpairs]   print assembly expression from hexpairs (alias for pdx, pix)
			| pade [hexpairs]  print ESIL expression from hexpairs
			| pae [assembly]   print ESIL expression of the given assembly expression
+ 反汇编
	- pCd [N]：显示地址和静态汇编代码
	- p[i/I]：显示静态汇编代码
		+ pif：汇编到函数结束
		+ pIf：汇编到函数结束
	- pd:反汇编
		::
		
			[0x556fc5273222]> pd?
			Usage: p[dD][ajbrfils] [len]   # Print Disassembly
			| NOTE: len        parameter can be negative
			| NOTE:            Pressing ENTER on empty command will repeat last print command in next page
			| pD N             disassemble N bytes
			| pd -N            disassemble N instructions backward
			| pd N             disassemble N instructions
			| pd--[n]          当前上下文进行前后反汇编N条指令
			| pda[?]           disassemble all possible opcodes (byte per byte)
			| pdb              disassemble basic block
			| pdc              类似IDA F5功能，反编译c格式代码
			| pdC              show comments found in N instructions
			| pde[q|qq|j] [N]  disassemble N instructions following execution flow from current PC
			| pdf              反汇编到函数返回
			| pdi              like 'pi', with offset and bytes
			| pdj              disassemble to json
			| pdJ              formatted disassembly like pd as json
			| pdk              disassemble all methods of a class
			| pdl              show instruction sizes
			| pdp              disassemble by following pointers to read ropchains
			| pdr              recursive disassemble across the function graph
			| pdR              recursive disassemble block size bytes without analyzing functions
			| pdr.             recursive disassemble across the function graph (from current basic block)
			| pds[?]           disassemble summary (strings, calls, jumps, refs) (see pdsf and pdfs)
			| pdt [n] [query]  disassemble N instructions in a table (see dtd for debug traces)
			| pdx [hex]        alias for pad or pix
		
			[0x556fc52731b5]> pdf @ sym.main
				; DATA XREF from entry0 @ 0x556fc52730bd
				;-- rax:
				;-- rip:
			┌ 188: int main (int argc, char **argv, char **envp);
			│           ; var int64_t var_20h @ rbp-0x20
			│           ; var int64_t var_14h @ rbp-0x14
			│           ; var int64_t var_10h @ rbp-0x10
			│           ; var int64_t var_8h @ rbp-0x8
			│           ; arg int argc @ rdi
			│           ; arg char **argv @ rsi
			│           0x556fc52731b5 b    55             push rbp
			│           0x556fc52731b6      4889e5         mov rbp, rsp
			│           0x556fc52731b9      4883ec20       sub rsp, 0x20
			│           0x556fc52731bd      897dec         mov dword [var_14h], edi ; argc
			│           0x556fc52731c0      488975e0       mov qword [var_20h], rsi ; argv
			│           0x556fc52731c4      837dec01       cmp dword [var_14h], 1
			│       ┌─< 0x556fc52731c8      7f19           jg 0x556fc52731e3
			
			@ addr 表示从addr开始汇编
			
+ 调试指令
	- r2 -d -A heap AAAAAAAAAAAA
		+ -A 自动化分析或者再命令台使用aaa
		+ -d 启动调试
	- s:移动到不同位置
		+ s：打印当前地址
		+ s @main：打印main函数地址
		+ s @PC：打印当前eip寄存器内容
		+ s addr
		+ s/sr	[register]
	- VV:可视化的函数调用图
	- db <function-name>：在函数或内存地址下断点
		::
		
			Usage: db    # Breakpoints commands
			| db                        List breakpoints
			| db*                       List breakpoints in r commands
			| db sym.main               Add breakpoint into sym.main
			| db <addr>                 Add breakpoint
			| dbH <addr>                Add hardware breakpoint
			| db- <addr>                Remove breakpoint
			| db-*                      Remove all the breakpoints
			| db.                       Show breakpoint info in current offset
			| dbj                       List breakpoints in JSON format
			| dbc <addr> <cmd>          Run command when breakpoint is hit
			| dbC <addr> <cmd>          Run command but continue until <cmd> returns zero
			| dbd <addr>                Disable breakpoint
			| dbe <addr>                Enable breakpoint
			| dbs <addr>                Toggle breakpoint
			| dbf                       Put a breakpoint into every no-return function
			| dbm <module> <offset>     Add a breakpoint at an offset from a module's base
			| dbn [<name>]              Show or set name for current breakpoint
			| dbi                       查看断点列表
			| dbi <addr>                Show breakpoint index in givengiven  offset
			| dbi.                      Show breakpoint index in current offset
			| dbi- <idx>                Remove breakpoint by index
			| dbix <idx> [expr]         Set expression for bp at given index
			| dbic <idx> <cmd>          Run command at breakpoint index
			| dbie <idx>                Enable breakpoint by index
			| dbid <idx>                Disable breakpoint by index
			| dbis <idx>                Swap Nth breakpoint
			| dbite <idx>               Enable breakpoint Trace by index
			| dbitd <idx>               Disable breakpoint Trace by index
			| dbits <idx>               Swap Nth breakpoint trace
			| dbh x86                   Set/list breakpoint plugin handlers
			| dbh- <name>               Remove breakpoint plugin handler
			| dbt[?]                    查看调用堆栈
			| dbx [expr]                Set expression for bp in current offset
			| dbw <addr> <r/w/rw>       Add watchpoint
			| drx number addr len perm  Modify hardware breakpoint
			| drx-number                Clear hardware breakpoint
	- do：重启调试程序
		::
		
			[0x7f5a4267b050]> do?
			Usage: do   # Debug (re)open commands
			| do            Open process (reload, alias for 'oo')
			| dor [rarun2]  Comma separated list of k=v rarun2 profile options (e dbg.profile)
			| doe           Show rarun2 startup profile
			| doe!          Edit rarun2 startup profile with $EDITOR
			| doo [args]    Reopen in debug mode with args (alias for 'ood')
			| doof [args]   Reopen in debug mode from file (alias for 'oodf')
			| doc           Close debug session
	- dc:执行二进制程序
		::
		
			Usage: dc   Execution continuation commands
			| dc                           Continue execution of all children
			| dc <pid>                     Continue execution of pid
			| dc[-pid]                     Stop execution of pid
			| dca [sym] [sym].             Continue at every hit on any given symbol
			| dcb                          Continue back until breakpoint
			| dcc                          Continue until call (use step into)
			| dccu                         Continue until unknown call (call reg)
			| dcf                          Continue until fork (TODO)
			| dck <signal> <pid>           Continue sending signal to process
			| dcp                          Continue until program code (mapped io section)
			| dcr                          Continue until ret (uses step over)
			| dcs[?] <num>                 Continue until syscall
			| dct <len>                    Traptrace from curseek to len, no argument to list
			| dcu[?] [..end|addr] ([end])  Continue until address (or range)
	- dr：打印寄存器数据
		+ dr：打印寄存器数据
		+ dr=：多列显示寄存器数据
		+ drr：打印寄存器数据，并显示引用数据
	- ds:单步相关命令
		::
		
			Usage: ds   Step commands
			| ds                Step one instruction				:单步步入
			| ds <num>          Step <num> instructions
			| dsb               Step back one instruction
			| dsf               Step until end of frame
			| dsi <cond>        Continue until condition matches
			| dsl               Step one source line
			| dsl <num>         Step <num> source lines
			| dso <num>         Step over <num> instructions		:单步步过
			| dsp               Step into program (skip libs)
			| dss <num>         Skip <num> step instructions
			| dsu[?] <address>  Step until <address>. See 'dsu?' for other step until cmds.
+ 内存指令
	- pv:打印内存数据
		::
		
			[0x55c6f2211149]> pv?
			Usage: pv[j][1,2,4,8,z]   
			| pv   print bytes based on asm.bits
			| pv1  print 1 byte in memory
			| pv2  print 2 bytes in memory
			| pv4  print 4 bytes in memory
			| pv8  print 8 bytes in memory
			| pvz  print value as string (alias for ps)
	- p[b/B/xb]：打印二进制格式数据
		- pb [N]：以比特位为计数单位
		- pB [N]：以字节为计数单位
		- pxb [N]:以hexdump形式显示二进制数据
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
	- pc [N]：以代码形式显示数据
		::
		
			Usage: pc   # Print in code
			| pc   C
			| pc*  print 'wx' r2 commands
			| pcA  .bytes with instructions in comments
			| pca  GAS .byte blob
			| pcd  C dwords (8 byte)
			| pch  C half-words (2 byte)
			| pci  C array of bytes with instructions	//显示汇编注释
			| pcJ  javascript
			| pcj  json
			| pck  kotlin
			| pco  Objective-C
			| pcp  python
			| pcr  rust
			| pcS  shellscript that reconstructs the bin
			| pcs  string
			| pcv  JaVa
			| pcV  V (vlang.io)
			| pcw  C words (4 byte)
			| pcy  yara
			| pcz  Swift
	- px:十六进制视图
		::
		
			Usage: px[0afoswqWqQ][f]   # Print heXadecimal
			| px                show hexdump
			| px/               same as x/ in gdb (help x)
			| px0               8bit hexpair list of bytes until zero byte
			| pxa               show annotated hexdump
			| pxA[?]            show op analysis color map
			| pxb               dump bits in hexdump form
			| pxc               show hexdump with comments
			| pxd[?1248]        signed integer dump (1 byte, 2 and 4)
			| pxe               emoji hexdump! :)
			| pxf               show hexdump of current function
			| pxh               show hexadecimal half-words dump (16bit)
			| pxH               same as above, but one per line
			| pxi               HexII compact binary representation
			| pxl               display N lines (rows) of hexdump
			| pxo               show octal dump
			| pxq               show hexadecimal quad-words dump (64bit)
			| pxQ[q]            same as above, but one per line
			| pxr[1248][qj]     show hexword references (q=quiet, j=json)
			| pxs               show hexadecimal in sparse mode
			| pxt[*.] [origin]  show delta pointer table in r2 commands
			| pxw               show hexadecimal words dump (32bit)
			| pxW[q]            same as above, but one per line (q=quiet)
			| pxx               show N bytes of hex-less hexdump
			| pxX               show N words of hex-less hexdump
			
	- dm
		::
		
			Usage: dm   # Memory maps commands
			| dm                               List memory maps of target process
			| dm address size                  Allocate <size> bytes at <address> (anywhere if address is -1) in child process
			| dm=                              List memory maps of target process (ascii-art bars)		；进程内存布局
			| dm.                              Show map name of current address
			| dm*                              List memmaps in radare commands
			| dm- address                      Deallocate memory map of <address>
			| dmd[a] [file]                    Dump current (all) debug map region to a file (from-to.dmp) (see Sd)
			| dmh[?]                           Show map of heap			；查看Malloc chunk列表
			| dmi [addr|libname] [symname]     List symbols of target lib		；进程加载的模块
			| dmi* [addr|libname] [symname]    List symbols of target lib in radare commands
			| dmi.                             List closest symbol to the current address
			| dmiv                             Show address of given symbol for given lib
			| dmj                              List memmaps in JSON format
			| dml <file>                       Load contents of file into the current map region
			| dmm[?][j*]                       列出模块 (库文件，内存中加载的二进制文件)
			| dmp[?] <address> <size> <perms>  Change page at <address> with <size>, protection <perms> (perm)
			| dms[?] <id> <mapaddr>            Take memory snapshot
			| dms- <id> <mapaddr>              Restore memory snapshot
			| dmS [addr|libname] [sectname]    List sections of target lib
			| dmS* [addr|libname] [sectname]   List sections of target lib in radare commands
			| dmL address size                 Allocate <size> bytes at <address> and promote to huge page
			| TODO:                            map files in process memory. (dmf file @ [addr])
+ 堆指令
	::
	
		Usage:  dmh   # Memory map heap
		| dmh                                          查看堆中所有malloc_chunk列表
		| dmh @[malloc_state]                          查看指定malloc_state的malloc_chunk列表
		| dmha                                         查看所有malloc_state列表
		| dmhb @[malloc_state]                         查看指定malloc_state的所有bin数据
		| dmhb [bin_num|bin_num:malloc_state]          查看指定malloc_state的指定序号bin数据
		| dmhbg [bin_num]                              Display double linked list graph of main_arena's bin [Under developemnt]
		| dmhc @[chunk_addr]                           查看指定地址的malloc_chunk数据
		| dmhf @[malloc_state]                         查看指定malloc_state的fastbins数据
		| dmhf [fastbin_num|fastbin_num:malloc_state]  查看指定malloc_state的指定序号的fastbin数据
		| dmhg                                         查看堆malloc_chunk列表图示
		| dmhg [malloc_state]                          Display heap graph of a particular arena
		| dmhi @[malloc_state]                         查看指定malloc_state的heap_info数据
		| dmhj                                         List the chunks inside the heap segment in JSON format
		| dmhm                                         查看main thread所有的malloc_state数据
		| dmhm @[malloc_state]                         List all malloc_state instance of a particular arena
		| dmht                                         查看thread cache的malloc_state列表
		| dmh?                                         Show map heap help
+ ELF文件指令
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
	- afl：列出二进制中存在的函数
	- axt：查看交叉引用
		::
		
			[0x7f9902a44050]> axt sym.imp.malloc
			main 0x5636016ef1e8 [CALL] call sym.imp.malloc
			main 0x5636016ef1f6 [CALL] call sym.imp.malloc