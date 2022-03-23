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
	+ 附件：`heap.c <..//_static//heap.c>`_
	
调试过程
----------------------------------------
	
编写EXP
----------------------------------------
