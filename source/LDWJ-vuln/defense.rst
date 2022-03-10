防护与对抗
========================================

windows
----------------------------------------
- 启用GS选项
	| 防护：启用GS选项之后，会在函数执行一开始先往栈上保存一个数据，等函数返回时候检查这个数据，若不一致则为被覆盖，这样就跳转进入相应的处理过程，不再返回，因此shellcode也就无法被执行，这个值被称为“Security cookie”。
	| 对抗：覆盖SEH链为jmp esp的地址，之后触发异常跳转到esp执行shellcode。
- SafeSEH
	| 防护：SafeSEH是在程序编译的时候，就将所有的异常处理函数进行注册。凡是执行过程中触发异常后，都要经过一个检验函数，检查SEH链指向的地址是否在注册的列表中。
	| 对抗：如果SEH链指向的地址不在SEH链指向模块（exe、dll）地址的情况下，那就可以执行了。因此在程序中非模块的数据空间找到jmp esp，比方说nls后缀的资源文件等。或者是在支持JS脚本的软件中（浏览器等），通过脚本申请堆空间写入shellcode。
- DEP
	| 防护：数据执行保护（DEP）指的是堆和栈只有读写权限没有执行权限。
	| 对抗：对抗DEP的方式是将shellcode写入堆栈中，从程序自身的代码去凑到执行VirtualProtect()将shellcode所在内存属性添加上可执行权限，将函数返回值或者SEH链覆盖成代码片段的起始地址。这种利用程序自身碎片绕过DEP的方式被称作ROP。ROP技术的前提是代码片段的地址固定，这样才能知道往函数返回值或者SEH链中填写哪个地址。
- ASLR
	| 防护：ALSR即是让exe、dll的地址全都随机。
	| 对抗：对抗ASLR的方式是暴力把程序空间占满，全铺上shellcode，只要跳转地址没落在已有模块中，落在我们的空间中即可以执行了shellcode，但是这样做无法绕过DEP，这种将程序空间全部占满铺上shellcode的技术被称为堆喷射技术，堆喷射技术只能对抗ASLR，缺无法对抗ASLR+DEP的双重防护。ASLR+DEP的双重防护使得大多数软件的漏洞只能造成崩溃，无法稳定利用。将程序空间占满的技术，称之为堆喷射（Heap Spraying），这种技术只能应用在可以执行JS等脚本的软件上，如浏览器等。堆喷射通过大面积的申请内存空间并构造适当的数据，一旦EIP指向这片空间，就可以执行shellcode。堆喷射已经是不得已而为之，有时候会造成系统卡一段时间，容易被发现；另一点，如果EIP恰好指向shellcode中间部分就会造成漏洞利用失败，因此不能保证100%成功。
- LFH
	| 防护：在Window7中，它用LFH(Low Fragmentation Heap)取代了之前Windows XP版本中的lookaside。堆分配时候的随机化出现是为了缓解系统中UAF漏洞的利用。
	| 对抗：使用目标对象喷满整个userblocks，然后修改他们的metadata，总会有办法做到代码执行。
- CFG
	| 防护：微软在最新的操作系统win10当中，对基于执行流防护的实际应用中采用了CFG技术。CFG是Control Flow Guard的缩写，就是控制流保护，它是一种编译器和操作系统相结合的防护手段，目的在于防止不可信的间接调用。
	| 对抗：无。

linux
-----------------------------------------
- 工具：checksec
	checksec用来检查可执行文件属性，例如PIE, RELRO, PaX, Canaries, ASLR, Fortify Source等等属性。
- CANNARY
	类似windows下的启用GS选项。
- FORTIFY
	通过编译选项-D_FORTIFY_SOURCE使用带判断的安全函数替换掉strcpy, memcpy, memset等函数。
- NX
	| 防护：类似windows下的DEP。
	| 对抗：linux下shellcode的功能是通过execute执行/bin/sh，那么系统函数库（Linux称为glibc）有个system函数，它就是通过/bin/sh命令去执行一个用户执行命令或者脚本，我们完全可以利用system来实现Shellcode的功能。EIP一旦改写成system函数地址后，那执行system函数时，它需要获取参数。而根据Linux X86 32位函数调用约定，参数是压到栈上的。噢，栈空间完全由我们控制了，所以控制system的函数不是一件难事情。这种攻击方法称之为ret2libc，即return-to-libc，返回到系统库函数执行 的攻击方法。
	
	|rop1|
	::
	
		工作原理如下：
		①当程序运行到 gadget_addr 时（rsp 指向 gadget_addr），接下来会跳转到小片段里执行命令，
			同时 rsp+8(rsp 指向 bin_sh_addr)
		②然后执行 pop rdi, 将 bin_sh_addr 弹入 rdi 寄存器中，同时 rsp + 8(rsp 指向 system_ad
			dr)
		③执行 return 指令，因为这时 rsp 是指向 system_addr 的，这时就会调用 system 函数，而参
			数是通过 rdi 传递的，也就是会将 /bin/sh 传入，从而实现调用 system('/bin/sh')
		gadget_addr工具ROPgadget：https://github.com/JonathanSalwan/ROPgadget.git
- PIE
	类似与windows下的ASLR。
- RELRO
	RELRO设置符号重定向表格为只读或在程序启动时就解析并绑定所有动态符号，从而减少对GOT（Global Offset Table）攻击。
- SELinux
	安全增强型 Linux（Security-Enhanced Linux）简称 SELinux，它是一个 Linux 内核模块，也是 Linux 的一个安全子系统。SELinux 主要由美国国家安全局开发。2.6 及以上版本的 Linux 内核都已经集成了 SELinux 模块。
	SELinux 主要作用就是最大限度地减小系统中服务进程可访问的资源（最小权限原则）。
	
.. |rop1| image:: ../images/rop1.png