堆喷
========================================

简介
----------------------------------------
 | Heap Spray是一种通过比较巧妙的方式控制堆上数据，继而把程序控制流导向ShellCode的古老艺术。
 | 在shellcode的前面加上大量的slidecode（滑板指令），组成一个注入代码段。然后向系统申请大量内存，并且反复用注入代码段来填充。这样就使得进程的地址空间被大量的注入代码所占据。然后结合其他的漏洞攻击技术控制程序流，使得程序执行到堆上，最终将导致shellcode的执行。
 | 传统slide code（滑板指令）一般是NOP指令，但是随着一些新的攻击技术的出现，逐渐开始使用更多的类NOP指令，譬如0x0C（0x0C0C代表的x86指令是OR AL 0x0C），0x0D等等，不管是NOP还是0C，他们的共同特点就是不会影响shellcode的执行。
 | Heap Spray只是一种辅助技术，需要结合其他的栈溢出或堆溢出等等各种溢出技术才能发挥作用。

示例代码
-----------------------------------------

::

	#include "stdafx.h"
	#include<string>

	class base
	{
		char m_buf[8];
	public:
		virtual int baseInit1()
		{
			printf("%s\n", "baseInit1");
			return 0;
		}
		virtual int baseInit2()
		{
			printf("%s\n", "baseInit2");
			return 0;
		}
	};

	int main()
	{
		getchar();
		unsigned int bufLen = 200 * 1024 * 1024;
		base *baseObj = new base;
		char buff[8] = { 0 };
		char *spray = new char[bufLen];
		memset(spray, 0x0c, sizeof(char)*bufLen);//此处存放shellcode
		memset(spray + bufLen - 0x10, 0xcc, 0x10);
		strcpy(buff, "12345678\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c");//覆盖base类的虚表指针
		baseObj->baseInit1();
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
 | 附件：`HeapSpray.zip <..//_static//HeapSpray.zip>`_