整数溢出
========================================

简介
----------------------------------------
计算机中整数变量有上下界，如果在算术运算中出现越界，就会出现两类整数溢出。超出整数类型的最大表示范围，数字便会由一个极大值变为一个极小值或直接归零，叫做“上溢”;超出整数类型的最小表示范围的话，数字便会由一个极小值或者零变成一个极大值，叫做“下溢”。

逻辑漏洞
----------------------------------------

示例代码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

	#include<stdlib.h>
	#include <stdio.h>
	#include <string.h>

	#define MAXFLAG 255
	void exec() {
		// do logic
		printf("do a lot logic, but dangerous, we don't expect it to execute!\n");
	}

	int main(int argc, char** argv) {
		int a = 0;
		if (argc > 1) {
			a = (int)atoi(argv[1]);
		} else {
			printf("Bad input!\n");
			exit(-1);
		}

		if(a > 254) {
			printf("Bad input!\n");
					exit(-1);
		}

		printf("input flag = %d\n", a);
		
		if( (char)(MAXFLAG - a) == 0) {
			exec();
		}
		return 0;
	}

编译环境:
 | IDE：Visual Studio 2019
 | 编译选项：无。
 | 附件：`int_sample1.rar <..//_static//int_sample1.rar>`_
 
栈溢出
----------------------------------------

示例代码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

	#include<stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#define MAX_BUF_LEN 256
	int main(int argc, char** argv) {
		unsigned char buflen = 0;
		char* arg = NULL;

		char buf[MAX_BUF_LEN];
		if (argc > 1) {
			arg = argv[1];
			buflen = (unsigned char)strlen(arg);
		} else {
			printf("Bad input!\n");
			exit(-1);
		}

		if(buflen > MAX_BUF_LEN || arg == NULL) {
			printf("Bad input!\n");
					exit(-1);
		}

		printf("input buf len = %d\n", buflen);
		memset(buf, 0, MAX_BUF_LEN);	
		strncpy(buf, arg, strlen(arg));
		printf("buf = %s\n", buf);

		return 0;
	}

编译环境:
 | IDE：Visual Studio 2019
 | 编译选项：无。
 | 附件：无。
 
堆溢出
----------------------------------------

示例代码
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

	#include<stdlib.h>
	#include <stdio.h>
	#include <string.h>
	#define MAX_BUF_LEN 256
	int main(int argc, char** argv) {
		unsigned char buflen = 0;
		char* arg = NULL;

		char* buf = (char*)malloc(MAX_BUF_LEN);
		char* second = (char*) malloc(0x10);

		if (argc > 1) {
			arg = argv[1];
			buflen = (unsigned char)strlen(arg);
		} else {
			printf("Bad input!\n");
			exit(-1);
		}

		if(buflen > MAX_BUF_LEN || arg == NULL) {
			printf("Bad input!\n");
					exit(-1);
		}

		printf("input buf len = %d\n", buflen);
		memset(buf, 0, MAX_BUF_LEN);
		strcpy(second, "hello world");

		printf("second = %s\n", second);	
		strncpy(buf, arg, strlen(arg));
		printf("second = %s\n", second);

		return 0;
	}

编译环境:
 | IDE：Visual Studio 2019
 | 编译选项：无。
 | 附件：无。
 
挖掘方法
----------------------------------------
- 源代码审计，难点在于如何把审计自动化。 
- 逆向分析，收集整数作为参数出现的所有位置，收集哪些作为参数的整数是可控的，摸索测试；难点在于如何实现半自动化挖掘。 